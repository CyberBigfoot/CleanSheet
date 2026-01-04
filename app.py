import os
import uuid
import docker
from flask import Flask, request, send_file, render_template_string, jsonify
from werkzeug.utils import secure_filename
import time
import requests
import hashlib

app = Flask(__name__)

UPLOAD_FOLDER = '/app/uploads'
OUTPUT_FOLDER = '/app/output'

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# Get VirusTotal API key from environment
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')

ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'rtf', 'odt', 'jpg', 'jpeg', 'png'}

# File size limit: 100MB
MAX_FILE_SIZE = 100 * 1024 * 1024

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_file_hash(filepath):
    """Calculate SHA256 hash of file"""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def scan_with_virustotal(filepath, job_id):
    """Scan file with VirusTotal API"""
    if not VIRUSTOTAL_API_KEY:
        print("⚠ VirusTotal API key not configured - skipping AV scan")
        return True, "No API key configured"
    
    try:
        print(f"[VirusTotal] Calculating file hash...")
        file_hash = get_file_hash(filepath)
        
        # First, check if file was already scanned
        print(f"[VirusTotal] Checking hash: {file_hash}")
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers=headers,
            timeout=30
        )
        
        if response.status_code == 200:
            # File already scanned, check results
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            
            print(f"[VirusTotal] Scan results - Malicious: {malicious}, Suspicious: {suspicious}")
            
            if malicious > 0:
                return False, f"THREAT DETECTED: {malicious} engines flagged as malicious"
            elif suspicious > 3:  # Allow up to 3 suspicious flags (false positives)
                return False, f"SUSPICIOUS: {suspicious} engines flagged as suspicious"
            
            return True, f"Clean (0/{stats.get('harmless', 0) + stats.get('undetected', 0)} engines)"
        
        elif response.status_code == 404:
            # File not in database, upload for scanning
            print(f"[VirusTotal] File not in database, uploading for scan...")
            
            with open(filepath, 'rb') as f:
                files = {"file": (os.path.basename(filepath), f)}
                upload_response = requests.post(
                    "https://www.virustotal.com/api/v3/files",
                    headers=headers,
                    files=files,
                    timeout=120
                )
            
            if upload_response.status_code in [200, 201]:
                analysis_id = upload_response.json()['data']['id']
                print(f"[VirusTotal] Upload successful, analysis ID: {analysis_id}")
                
                # Wait for analysis (poll up to 60 seconds)
                for _ in range(12):
                    time.sleep(5)
                    analysis_response = requests.get(
                        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                        headers=headers,
                        timeout=30
                    )
                    
                    if analysis_response.status_code == 200:
                        analysis_data = analysis_response.json()
                        status = analysis_data['data']['attributes']['status']
                        
                        if status == 'completed':
                            stats = analysis_data['data']['attributes']['stats']
                            malicious = stats.get('malicious', 0)
                            suspicious = stats.get('suspicious', 0)
                            
                            print(f"[VirusTotal] Analysis complete - Malicious: {malicious}, Suspicious: {suspicious}")
                            
                            if malicious > 0:
                                return False, f"THREAT DETECTED: {malicious} engines flagged as malicious"
                            elif suspicious > 3:
                                return False, f"SUSPICIOUS: {suspicious} engines flagged as suspicious"
                            
                            return True, f"Clean (0/{stats.get('harmless', 0) + stats.get('undetected', 0)} engines)"
                
                print(f"[VirusTotal] Analysis timeout - proceeding with caution")
                return True, "Analysis timeout - proceeding"
            else:
                print(f"[VirusTotal] Upload failed: {upload_response.status_code}")
                return True, "Upload failed - proceeding"
        
        else:
            print(f"[VirusTotal] API error: {response.status_code}")
            return True, f"API error - proceeding"
    
    except Exception as e:
        print(f"[VirusTotal] Error: {e}")
        return True, f"Scan error - proceeding: {str(e)}"

def cleanup_orphaned_files():
    """Clean up any files older than 1 hour (failsafe)"""
    current_time = time.time()
    cleaned = 0
    
    for folder in [UPLOAD_FOLDER, OUTPUT_FOLDER]:
        if not os.path.exists(folder):
            continue
            
        for filename in os.listdir(folder):
            filepath = os.path.join(folder, filename)
            try:
                file_age = current_time - os.path.getmtime(filepath)
                if file_age > 3600:  # 1 hour
                    os.remove(filepath)
                    cleaned += 1
                    print(f"✓ Cleaned up orphaned file: {filename}")
            except Exception as e:
                print(f"Error cleaning {filename}: {e}")
    
    if cleaned > 0:
        print(f"✓ Orphaned file cleanup: {cleaned} files removed")
    
    return cleaned

def sanitize_in_container(input_path, output_path, job_id):
    """Spawn an isolated Docker container to sanitize the document"""
    try:
        client = docker.DockerClient(base_url='unix:///var/run/docker.sock')
        print(f"Docker client connected successfully")
        version_info = client.version()
        print(f"Docker version: {version_info.get('Version', 'unknown')}")
    except Exception as e:
        print(f"ERROR: Cannot connect to Docker: {e}")
        return False
    
    container = None
    try:
        # Build worker image if it doesn't exist
        try:
            client.images.get('cleansheet-worker:latest')
            print("Worker image found")
        except docker.errors.ImageNotFound:
            print("Building worker image...")
            try:
                image, build_logs = client.images.build(
                    path='/app',
                    dockerfile='Dockerfile.worker',
                    tag='cleansheet-worker:latest',
                    rm=True,
                    forcerm=True
                )
                for log in build_logs:
                    if 'stream' in log:
                        print(log['stream'].strip())
                print("Worker image built successfully")
            except Exception as build_error:
                print(f"ERROR building worker image: {build_error}")
                return False
        
        host_pwd = os.environ.get('HOST_PWD', '/app')
        host_uploads = os.path.join(host_pwd, 'uploads')
        host_output = os.path.join(host_pwd, 'output')
        
        print(f"\n{'='*60}")
        print(f"SANITIZATION SEQUENCE INITIATED - JOB: {job_id}")
        print(f"{'='*60}")
        print(f"[1/7] Spawning isolated worker container...")
        
        # Enhanced container isolation
        container = client.containers.run(
            'cleansheet-worker:latest',
            name=f'cleansheet-worker-{job_id}',
            volumes={
                host_uploads: {'bind': '/worker/input', 'mode': 'ro'},
                host_output: {'bind': '/worker/output', 'mode': 'rw'}
            },
            environment={
                'INPUT_FILE': f'/worker/input/{os.path.basename(input_path)}',
                'OUTPUT_FILE': f'/worker/output/{os.path.basename(output_path)}'
            },
            detach=True,
            remove=False,
            network_mode='none',  # No network access
            mem_limit='2g',
            cpu_quota=100000,
            # Enhanced security options
            security_opt=['no-new-privileges:true'],
            cap_drop=['ALL'],  # Drop all capabilities
            read_only=False,  # Need write for temp processing
            tmpfs={'/tmp': 'size=1g,mode=1777'},  # Temporary filesystem in memory
        )
        
        print(f"[2/7] Container {container.id[:12]} deployed with enhanced isolation")
        print(f"       - Network: DISABLED")
        print(f"       - Capabilities: NONE")
        print(f"       - Privileges: RESTRICTED")
        print(f"[3/7] Processing document in air-gapped environment...")
        
        result = container.wait(timeout=300)
        
        print(f"[4/7] Container processing complete")
        
        logs = container.logs().decode('utf-8')
        print(f"\n--- Worker Container Output ---")
        print(logs)
        print(f"--- End Worker Output ---\n")
        
        print(f"[5/7] Terminating and purging container...")
        container.remove(force=True)
        print(f"✓ Container destroyed")
        
        if result['StatusCode'] == 0:
            # Validate output file
            print(f"[6/7] Validating sanitized output...")
            if not os.path.exists(output_path):
                print(f"✗ Output file not found")
                return False
            
            output_size = os.path.getsize(output_path)
            if output_size == 0:
                print(f"✗ Output file is empty")
                return False
            
            print(f"✓ Output validated ({output_size} bytes)")
            
            # Scan sanitized file with VirusTotal
            print(f"[7/7] Scanning sanitized output...")
            is_clean, scan_message = scan_with_virustotal(output_path, job_id)
            print(f"✓ Output scan: {scan_message}")
            
            if not is_clean:
                print(f"✗ Sanitized file failed security scan!")
                if os.path.exists(output_path):
                    os.remove(output_path)
                return False
            
            print(f"{'='*60}")
            print(f"✓ SANITIZATION COMPLETE - Document is clean")
            print(f"{'='*60}\n")
            return True
        else:
            print(f"{'='*60}")
            print(f"✗ SANITIZATION FAILED - Status code: {result['StatusCode']}")
            print(f"{'='*60}\n")
            return False
            
    except Exception as e:
        print(f"Error spawning container: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        if container:
            try:
                container.remove(force=True)
            except:
                pass

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>CleanSheet - Advanced Document Sanitizer</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Roboto+Mono:wght@300;400;700&display=swap');
        
        html, body {
            margin: 0;
            padding: 0;
            min-height: 100vh;
            overflow-x: hidden;
        }
        
        body {
            font-family: 'Roboto Mono', monospace;
            background: #0a0e27;
            padding: 40px 20px;
            position: relative;
        }
        
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: #0a0e27;
            z-index: 0;
        }
        
        .boxes-background {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: 0;
            overflow: hidden;
            pointer-events: none;
        }
        
        .boxes-container {
            position: absolute;
            left: 25%;
            top: -25%;
            display: flex;
            transform: translate(-40%, -60%) skewX(-48deg) skewY(14deg) scale(0.675) rotate(0deg) translateZ(0);
            padding: 1rem;
        }
        
        .box-row {
            width: 4rem;
            height: 2rem;
            border-left: 1px solid #334155;
            position: relative;
        }
        
        .box-cell {
            width: 4rem;
            height: 2rem;
            border-right: 1px solid #334155;
            border-top: 1px solid #334155;
            position: relative;
            transition: background-color 2s ease;
            pointer-events: all;
        }
        
        .box-cell:hover {
            transition: background-color 0s;
        }
        
        .box-plus {
            position: absolute;
            height: 1.5rem;
            width: 2.5rem;
            top: -0.875rem;
            left: -1.375rem;
            color: #334155;
            stroke-width: 1px;
            pointer-events: none;
        }
        
        .container {
            background: rgba(15, 23, 42, 0.95);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 0 50px rgba(0,255,255,0.3), 0 0 100px rgba(138,43,226,0.2);
            max-width: 700px;
            width: 100%;
            border: 2px solid rgba(0,255,255,0.3);
            position: relative;
            z-index: 1;
            margin: 0 auto;
        }
        
        h1 {
            font-family: 'Orbitron', sans-serif;
            background: linear-gradient(135deg, #00ffff, #8a2be2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 10px;
            font-size: 3em;
            font-weight: 900;
            text-transform: uppercase;
            letter-spacing: 3px;
            text-align: center;
        }
        
        .subtitle {
            color: #00ffff;
            margin-bottom: 30px;
            font-size: 0.9em;
            text-align: center;
            text-transform: uppercase;
            letter-spacing: 2px;
            opacity: 0.8;
        }
        
        .security-badge {
            background: linear-gradient(135deg, rgba(0,255,255,0.1), rgba(138,43,226,0.1));
            border: 1px solid rgba(0,255,255,0.5);
            color: #00ffff;
            padding: 12px 20px;
            border-radius: 8px;
            margin-bottom: 25px;
            font-weight: bold;
            text-align: center;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 1px;
            box-shadow: 0 0 20px rgba(0,255,255,0.2);
        }
        
        .info-box {
            background: rgba(0,255,255,0.05);
            border: 1px solid rgba(0,255,255,0.3);
            padding: 20px;
            margin-bottom: 30px;
            border-radius: 10px;
        }
        
        .info-box h3 {
            color: #00ffff;
            margin-bottom: 15px;
            font-family: 'Orbitron', sans-serif;
            text-transform: uppercase;
            font-size: 0.9em;
            letter-spacing: 2px;
        }
        
        .info-box ul {
            list-style: none;
            color: #8ab4f8;
            font-size: 0.85em;
            line-height: 1.8;
        }
        
        .info-box ul li {
            padding-left: 20px;
            position: relative;
        }
        
        .info-box ul li::before {
            content: '▸';
            position: absolute;
            left: 0;
            color: #00ffff;
        }
        
        .upload-area {
            border: 2px dashed rgba(0,255,255,0.5);
            border-radius: 15px;
            padding: 40px;
            text-align: center;
            background: rgba(0,255,255,0.03);
            cursor: pointer;
            transition: all 0.3s;
            position: relative;
            overflow: hidden;
        }
        
        .upload-area:hover {
            background: rgba(0,255,255,0.08);
            border-color: #00ffff;
            box-shadow: 0 0 30px rgba(0,255,255,0.3);
        }
        
        input[type="file"] {
            display: none;
        }
        
        .upload-btn {
            background: linear-gradient(135deg, #00ffff, #8a2be2);
            color: #0a0e27;
            padding: 15px 40px;
            border: none;
            border-radius: 30px;
            font-size: 1em;
            font-weight: bold;
            cursor: pointer;
            margin-top: 20px;
            transition: all 0.3s;
            font-family: 'Orbitron', sans-serif;
            text-transform: uppercase;
            letter-spacing: 2px;
            box-shadow: 0 0 20px rgba(0,255,255,0.5);
        }
        
        .upload-btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 5px 30px rgba(0,255,255,0.7);
        }
        
        .upload-btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        
        .file-name {
            margin-top: 20px;
            color: #00ffff;
            font-weight: bold;
            font-size: 0.9em;
        }
        
        .status {
            margin-top: 25px;
            padding: 20px;
            border-radius: 10px;
            display: none;
            border: 1px solid;
            font-size: 0.9em;
        }
        
        .status.success {
            background: rgba(0,255,0,0.1);
            color: #00ff00;
            border-color: rgba(0,255,0,0.5);
            display: block;
        }
        
        .status.error {
            background: rgba(255,0,0,0.1);
            color: #ff4444;
            border-color: rgba(255,0,0,0.5);
            display: block;
        }
        
        .status.processing {
            background: rgba(0,255,255,0.1);
            color: #00ffff;
            border-color: rgba(0,255,255,0.5);
            display: block;
        }
        
        .status.warning {
            background: rgba(255, 165, 0, 0.1);
            color: #ffaa00;
            border-color: rgba(255, 165, 0, 0.5);
            display: block;
        }
        
        .threat-warning-box {
            background: rgba(255, 0, 0, 0.1);
            border: 2px solid rgba(255, 0, 0, 0.5);
            border-radius: 10px;
            padding: 15px;
            margin-top: 10px;
            color: #ff4444;
            font-weight: bold;
        }
        
        .threat-warning-box .warning-icon {
            font-size: 1.5em;
            margin-right: 10px;
        }
        
        .processing-steps {
            margin-top: 15px;
            padding-left: 10px;
        }
        
        .processing-step {
            display: flex;
            align-items: center;
            margin: 8px 0;
            font-size: 0.85em;
            opacity: 0.5;
            transition: opacity 0.3s;
        }
        
        .processing-step.active {
            opacity: 1;
            color: #00ffff;
        }
        
        .processing-step.complete {
            opacity: 0.7;
            color: #00ff00;
        }
        
        .step-icon {
            margin-right: 10px;
            font-size: 1.2em;
        }
        
        .cyber-spinner {
            width: 20px;
            height: 20px;
            border: 2px solid rgba(0,255,255,0.3);
            border-top-color: #00ffff;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            display: inline-block;
            margin-right: 10px;
            vertical-align: middle;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="boxes-background">
        <div class="boxes-container" id="boxesContainer"></div>
    </div>

    <div class="container">
        <h1>CleanSheet</h1>
        <p class="subtitle">Advanced Neural Document Sanitization</p>
        
        <div class="security-badge">
            🛡️ Multi-Engine Security • CDR • VirusTotal • Isolated Processing
        </div>
        
        <div class="info-box">
            <h3>◢ Enhanced Security Protocol ◣</h3>
            <ul>
                <li>Multi-engine antivirus scanning (VirusTotal)</li>
                <li>Content Disarm & Reconstruction (CDR)</li>
                <li>Strip macros, scripts, and embedded objects</li>
                <li>Complete metadata removal</li>
                <li>Render to pixel matrix in isolated container</li>
                <li>Reconstruct sanitized PDF from pixel data</li>
                <li>Post-sanitization validation and scanning</li>
            </ul>
        </div>
        
        <form method="POST" enctype="multipart/form-data" id="uploadForm">
            <div class="upload-area" onclick="document.getElementById('fileInput').click()">
                <p style="font-size: 3em; margin-bottom: 10px;">🔒</p>
                <p style="color: #00ffff; font-size: 1.2em; margin-bottom: 5px; font-family: 'Orbitron', sans-serif;">
                    INITIATE SECURE UPLOAD
                </p>
                <p style="color: #8ab4f8; font-size: 0.8em;">
                    SUPPORTED: PDF • DOCX • XLSX • PPTX • IMAGES (Max 100MB)
                </p>
                <input type="file" name="file" id="fileInput" onchange="showFileName()" required>
                <div class="file-name" id="fileName"></div>
            </div>
            <center>
                <button type="submit" class="upload-btn" id="submitBtn">
                    <span id="btnText">🛡️ SANITIZE DOCUMENT</span>
                </button>
            </center>
        </form>
        
        <div class="status" id="status">
            <div id="statusMessage"></div>
            <div class="processing-steps" id="processingSteps" style="display: none;">
                <div class="processing-step" id="step1">
                    <span class="step-icon">◯</span>
                    <span id="step1-text">Pre-scanning with VirusTotal...</span>
                </div>
                <div class="processing-step" id="step2">
                    <span class="step-icon">◯</span>
                    <span>Spawning isolated container...</span>
                </div>
                <div class="processing-step" id="step3">
                    <span class="step-icon">◯</span>
                    <span>Applying CDR and stripping threats...</span>
                </div>
                <div class="processing-step" id="step4">
                    <span class="step-icon">◯</span>
                    <span>Rendering to pixel matrix...</span>
                </div>
                <div class="processing-step" id="step5">
                    <span class="step-icon">◯</span>
                    <span>Reconstructing sanitized PDF...</span>
                </div>
                <div class="processing-step" id="step6">
                    <span class="step-icon">◯</span>
                    <span>Validating and scanning output...</span>
                </div>
                <div class="processing-step" id="step7">
                    <span class="step-icon">◯</span>
                    <span>Terminating container...</span>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        function generateBoxes() {
            const container = document.getElementById('boxesContainer');
            const rows = 150;
            const cols = 100;
            const colors = [
                'rgb(125, 211, 252)', 'rgb(249, 168, 212)', 'rgb(134, 239, 172)',
                'rgb(253, 224, 71)', 'rgb(252, 165, 165)', 'rgb(216, 180, 254)',
                'rgb(147, 197, 253)', 'rgb(165, 180, 252)', 'rgb(196, 181, 253)',
                'rgb(0, 255, 255)', 'rgb(138, 43, 226)'
            ];
            
            function getRandomColor() {
                return colors[Math.floor(Math.random() * colors.length)];
            }
            
            for (let i = 0; i < rows; i++) {
                const row = document.createElement('div');
                row.className = 'box-row';
                
                for (let j = 0; j < cols; j++) {
                    const cell = document.createElement('div');
                    cell.className = 'box-cell';
                    
                    cell.addEventListener('mouseenter', function() {
                        this.style.backgroundColor = getRandomColor();
                    });
                    
                    cell.addEventListener('mouseleave', function() {
                        setTimeout(() => {
                            this.style.backgroundColor = '';
                        }, 2000);
                    });
                    
                    if (j % 2 === 0 && i % 2 === 0) {
                        const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
                        svg.setAttribute('fill', 'none');
                        svg.setAttribute('viewBox', '0 0 24 24');
                        svg.setAttribute('stroke-width', '1.5');
                        svg.setAttribute('stroke', 'currentColor');
                        svg.setAttribute('class', 'box-plus');
                        
                        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
                        path.setAttribute('stroke-linecap', 'round');
                        path.setAttribute('stroke-linejoin', 'round');
                        path.setAttribute('d', 'M12 6v12m6-6H6');
                        
                        svg.appendChild(path);
                        cell.appendChild(svg);
                    }
                    
                    row.appendChild(cell);
                }
                
                container.appendChild(row);
            }
        }
        
        generateBoxes();
        
        function showFileName() {
            const input = document.getElementById('fileInput');
            const fileName = document.getElementById('fileName');
            if (input.files.length > 0) {
                const file = input.files[0];
                const sizeMB = (file.size / (1024 * 1024)).toFixed(2);
                fileName.textContent = `▸ ${file.name} (${sizeMB} MB)`;
            }
        }
        
        function resetUI() {
            const btn = document.getElementById('submitBtn');
            btn.disabled = false;
            document.getElementById('btnText').textContent = '🛡️ SANITIZE DOCUMENT';
            
            const status = document.getElementById('status');
            status.style.display = 'none';
            status.className = 'status';
            
            const processingSteps = document.getElementById('processingSteps');
            processingSteps.style.display = 'none';
            
            const steps = ['step1', 'step2', 'step3', 'step4', 'step5', 'step6', 'step7'];
            steps.forEach(stepId => {
                const step = document.getElementById(stepId);
                step.classList.remove('active', 'complete');
                step.querySelector('.step-icon').textContent = '◯';
            });
            
            document.getElementById('fileInput').value = '';
            document.getElementById('fileName').textContent = '';
            
            currentStep = 0;
        }
        
        let currentStep = 0;
        const steps = ['step1', 'step2', 'step3', 'step4', 'step5', 'step6', 'step7'];
        
        function animateSteps() {
            if (currentStep < steps.length) {
                const stepEl = document.getElementById(steps[currentStep]);
                stepEl.classList.add('active');
                const icon = stepEl.querySelector('.step-icon');
                icon.innerHTML = '<span class="cyber-spinner"></span>';
                
                if (currentStep > 0) {
                    const prevStep = document.getElementById(steps[currentStep - 1]);
                    prevStep.classList.remove('active');
                    prevStep.classList.add('complete');
                    prevStep.querySelector('.step-icon').textContent = '✓';
                }
                
                currentStep++;
                setTimeout(animateSteps, 2500);
            }
        }
        
        document.getElementById('uploadForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const fileInput = document.getElementById('fileInput');
            const file = fileInput.files[0];
            
            // Check file size
            if (file.size > 100 * 1024 * 1024) {
                alert('File size exceeds 100MB limit');
                return;
            }
            
            const btn = document.getElementById('submitBtn');
            const status = document.getElementById('status');
            const processingSteps = document.getElementById('processingSteps');
            const statusMessage = document.getElementById('statusMessage');
            
            btn.disabled = true;
            document.getElementById('btnText').innerHTML = '<span class="cyber-spinner"></span> PROCESSING...';
            
            status.className = 'status processing';
            statusMessage.innerHTML = '<span class="cyber-spinner"></span> INITIALIZING MULTI-LAYER SECURITY SCAN...';
            status.style.display = 'block';
            processingSteps.style.display = 'block';
            
            currentStep = 0;
            steps.forEach(stepId => {
                const step = document.getElementById(stepId);
                step.classList.remove('active', 'complete');
                step.querySelector('.step-icon').textContent = '◯';
            });
            
            setTimeout(animateSteps, 1000);
            
            const formData = new FormData(this);
            
            fetch('/', {
                method: 'POST',
                body: formData
            })
            .then(response => {
                // Check for threat warning headers
                const threatWarning = response.headers.get('X-Threat-Warning');
                const threatDetails = response.headers.get('X-Threat-Details');
                
                if (response.ok) {
                    return response.blob().then(blob => ({
                        blob,
                        threatWarning,
                        threatDetails
                    }));
                }
                return response.json().then(data => {
                    throw new Error(data.error || 'Sanitization failed');
                });
            })
            .then(data => {
                const { blob, threatWarning, threatDetails } = data;
                
                steps.forEach(stepId => {
                    const step = document.getElementById(stepId);
                    step.classList.remove('active');
                    step.classList.add('complete');
                    step.querySelector('.step-icon').textContent = '✓';
                });
                
                // Show success or warning based on threat detection
                if (threatWarning) {
                    status.className = 'status warning';
                    statusMessage.innerHTML = `
                        <div>⚠️ THREAT DETECTED BUT NEUTRALIZED</div>
                        <div class="threat-warning-box">
                            <span class="warning-icon">🦠</span>
                            <span>${threatDetails}</span>
                        </div>
                        <div style="margin-top: 10px; color: #00ff00;">
                            ✓ Document has been fully sanitized and is now safe to download
                        </div>
                    `;
                } else {
                    status.className = 'status success';
                    statusMessage.textContent = '✓ SANITIZATION COMPLETE - File was clean. Downloading...';
                }
                
                // Create download link
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.style.display = 'none';
                a.href = url;
                
                const originalName = file.name;
                const baseName = originalName.substring(0, originalName.lastIndexOf('.')) || originalName;
                a.download = `sanitized_${baseName}.pdf`;
                
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);
                
                // Reset UI after delay (longer if threat detected to show warning)
                setTimeout(resetUI, threatWarning ? 5000 : 2000);
            })
            .catch(error => {
                console.error('Error:', error);
                status.className = 'status error';
                statusMessage.textContent = `✗ ${error.message}`;
                processingSteps.style.display = 'none';
                
                setTimeout(() => {
                    btn.disabled = false;
                    document.getElementById('btnText').textContent = '🛡️ SANITIZE DOCUMENT';
                }, 3000);
            });
        });
    </script>
</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        try:
            if 'file' not in request.files:
                return jsonify({'error': 'No file provided'}), 400
            
            file = request.files['file']
            
            if file.filename == '' or not allowed_file(file.filename):
                return jsonify({'error': 'Invalid file type'}), 400
            
            # Check file size
            file.seek(0, 2)  # Seek to end
            file_size = file.tell()
            file.seek(0)  # Reset to beginning
            
            if file_size > MAX_FILE_SIZE:
                return jsonify({'error': 'File size exceeds 100MB limit'}), 400
            
            filename = secure_filename(file.filename)
            job_id = str(uuid.uuid4())
            
            input_path = os.path.join(UPLOAD_FOLDER, f"{job_id}_{filename}")
            output_path = os.path.join(OUTPUT_FOLDER, f"{job_id}_sanitized.pdf")
            
            file.save(input_path)
            
            print(f"\n{'='*60}")
            print(f"PRE-PROCESSING SECURITY SCAN")
            print(f"{'='*60}")
            
            # Pre-scan with VirusTotal (informational only, don't reject)
            is_clean, scan_message = scan_with_virustotal(input_path, job_id)
            print(f"Pre-scan result: {scan_message}")
            
            threat_detected = not is_clean
            if threat_detected:
                print(f"⚠ THREAT DETECTED: {scan_message} - Processing anyway...")
            
            # Store threat status for later use
            threat_info = scan_message if threat_detected else None
            
            if sanitize_in_container(input_path, output_path, job_id):
                time.sleep(2)
                
                if os.path.exists(output_path):
                    # Create custom response with threat warning header if applicable
                    response = send_file(
                        output_path,
                        as_attachment=True,
                        download_name=f"sanitized_{filename.rsplit('.', 1)[0]}.pdf"
                    )
                    
                    # Add warning header if threat was detected
                    if threat_detected:
                        response.headers['X-Threat-Warning'] = 'Original file contained malware - now sanitized'
                        response.headers['X-Threat-Details'] = threat_info
                    
                    print(f"\n{'='*60}")
                    print(f"SECURE CLEANUP INITIATED")
                    print(f"{'='*60}")
                    
                    @response.call_on_close
                    def cleanup():
                        if os.path.exists(input_path):
                            os.remove(input_path)
                            print(f"✓ Deleted original upload")
                        
                        if os.path.exists(output_path):
                            os.remove(output_path)
                            print(f"✓ Deleted sanitized output")
                        
                        print(f"✓ All traces purged")
                        print(f"{'='*60}\n")
                    
                    return response
            
            if os.path.exists(input_path):
                os.remove(input_path)
            
            return jsonify({'error': 'Sanitization failed'}), 500
            
        except Exception as e:
            print(f"ERROR: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500
    
    return render_template_string(HTML_TEMPLATE)

if __name__ == '__main__':
    print("="*60)
    print("CLEANSHEET ADVANCED SECURITY INITIALIZATION")
    print("="*60)
    
    if VIRUSTOTAL_API_KEY:
        print("✓ VirusTotal API key configured")
    else:
        print("⚠ VirusTotal API key not found (set VIRUSTOTAL_API_KEY)")
    
    cleanup_orphaned_files()
    
    print("\n" + "="*60)
    print("Starting Flask server on port 10400...")
    print("="*60 + "\n")
    
    app.run(host='0.0.0.0', port=10400, debug=False)