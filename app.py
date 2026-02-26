import os
import uuid
import docker
import re
import dns.resolver
import whois
from urllib.parse import urlparse
from flask import Flask, request, send_file, render_template_string, jsonify, Response
from werkzeug.utils import secure_filename
import time
import requests
import hashlib
import threading
from collections import defaultdict

app = Flask(__name__)

# Event emitters for SSE progress updates
_event_listeners = defaultdict(list)

def emit_progress(job_id, step, message):
    """Emit a progress event to all listeners for a job"""
    for listener in _event_listeners[job_id]:
        try:
            listener(f"data: {step}|{message}\n\n")
        except:
            pass

def sse_progress(job_id):
    """Server-Sent Events endpoint for progress updates"""
    def generate():
        queue = []
        
        def listener(data):
            queue.append(data)
        
        _event_listeners[job_id].append(listener)
        
        try:
            while True:
                if queue:
                    data = queue.pop(0)
                    yield data
                else:
                    time.sleep(0.1)
        finally:
            if job_id in _event_listeners:
                _event_listeners[job_id].remove(listener)
                if not _event_listeners[job_id]:
                    del _event_listeners[job_id]
    
    return Response(generate(), mimetype='text/event-stream')

UPLOAD_FOLDER = '/app/uploads'
OUTPUT_FOLDER = '/app/output'
MAX_FILE_SIZE = 100 * 1024 * 1024
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
ALLOWED_EXTENSIONS = {'pdf', 'docx', 'xlsx', 'pptx', 'png', 'jpg', 'jpeg'}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_file_hash(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def scan_with_virustotal(filepath, job_id):
    """Scan file with VirusTotal API (used by document sanitizer pre/post scan)
    Returns: (is_clean: bool, message: str, stats: dict or None)
    """
    if not VIRUSTOTAL_API_KEY:
        pass  # Logging disabled
        return True, "No API key configured", None
    try:
        file_hash = get_file_hash(filepath)
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        pass  # Logging disabled
        response = requests.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers=headers,
            timeout=30
        )
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            harmless = stats.get('harmless', 0)
            undetected = stats.get('undetected', 0)
            total = malicious + suspicious + harmless + undetected
            
            scan_stats = {
                'malicious': malicious,
                'suspicious': suspicious,
                'harmless': harmless,
                'undetected': undetected,
                'total': total
            }
            
            if malicious > 0:
                return False, f"{malicious}/{total} engines flagged as malicious", scan_stats
            if suspicious > 3:
                return False, f"{suspicious}/{total} engines flagged as suspicious", scan_stats
            return True, f"0/{total} threats detected", scan_stats
        if response.status_code == 404:
            with open(filepath, "rb") as f:
                files = {"file": (os.path.basename(filepath), f)}
                response = requests.post(
                    "https://www.virustotal.com/api/v3/files",
                    headers=headers,
                    files=files,
                    timeout=120
                )
            if response.status_code in (200, 201):
                return True, "Scan queued (first-time upload)", None
            return True, "Upload failed - proceeding", None
        return True, f"API error - proceeding", None
    except requests.exceptions.Timeout:
        pass  # Logging disabled
        return True, "Scan timeout - proceeding", None
    except Exception as e:
        pass  # Logging disabled
        return True, f"Scan error - proceeding", None

def check_ip_with_virustotal(ip):
    """Check IP address with VirusTotal API"""
    if not VIRUSTOTAL_API_KEY:
        return {'success': False, 'error': 'VirusTotal API key not configured'}
    
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers=headers,
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()['data']['attributes']
            stats = data['last_analysis_stats']
            
            return {
                'success': True,
                'ip': ip,
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'asn': data.get('asn', 'N/A'),
                'as_owner': data.get('as_owner', 'N/A'),
                'country': data.get('country', 'N/A'),
                'reputation': data.get('reputation', 0),
                'tags': data.get('tags', [])
            }
        elif response.status_code == 404:
            return {'success': False, 'error': 'IP address not found in VirusTotal database'}
        else:
            return {'success': False, 'error': f'VirusTotal API error: {response.status_code}'}
            
    except Exception as e:
        return {'success': False, 'error': str(e)}

def check_url_with_virustotal(url):
    """Check URL with VirusTotal API"""
    if not VIRUSTOTAL_API_KEY:
        return {
            'success': False,
            'error': 'VirusTotal API key not configured'
        }
    
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    # URL needs to be base64 encoded for VT API
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    pass  # Logging disabled
    response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        return {
            'success': True,
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'harmless': stats.get('harmless', 0),
            'undetected': stats.get('undetected', 0),
            'status': 'completed'
        }
    
    # If not found, submit for scanning
    payload = {"url": url}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=payload)
    
    if response.status_code == 200:
        return {
            'success': True,
            'status': 'pending',
            'message': 'URL submitted for scanning'
        }
    
    return {
        'success': False,
        'error': f'VirusTotal API error: {response.status_code}'
    }

def validate_email_address(email):
    """Validate email address format, domain, and MX records"""
    results = {
        'email': email,
        'format_valid': False,
        'domain_exists': False,
        'has_mx_records': False,
        'is_disposable': False,
        'mx_records': [],
        'trust_score': 0,
        'warnings': [],
        'errors': []
    }
    
    # Format check
    if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        results['format_valid'] = True
        results['trust_score'] += 20
    else:
        results['errors'].append("Invalid email format")
        return results
        
    domain = email.split('@')[1]
    
    # Domain and MX check
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        results['domain_exists'] = True
        results['has_mx_records'] = True
        results['trust_score'] += 30
        for rdata in mx_records:
            results['mx_records'].append(str(rdata.exchange).rstrip('.'))
        
        results['trust_score'] += 20 # Bonus for having MX records
    except Exception as e:
        results['errors'].append(f"Domain validation failed: {str(e)}")
        
    # Disposable check
    disposable_domains = ['tempmail.com', '10minutemail.com', 'guerrillamail.com', 'sharklasers.com']
    if domain.lower() in disposable_domains:
        results['is_disposable'] = True
        results['warnings'].append("Disposable email provider detected")
        results['trust_score'] -= 40
    else:
        results['trust_score'] += 30
        
    # Final clamping of score
    results['trust_score'] = max(0, min(100, results['trust_score']))
    return results

def analyze_email_headers(headers_text):
    """Analyze email headers for security indicators"""
    results = {
        'spf': {'status': 'unknown', 'details': ''},
        'dkim': {'status': 'unknown', 'details': ''},
        'dmarc': {'status': 'unknown', 'details': ''},
        'from_address': '',
        'return_path': '',
        'spoofing_indicators': [],
        'routing_path': [],
        'warnings': [],
        'overall_trust': 'unknown'
    }
    
    lines = headers_text.split('\n')
    
    # Basic parsing
    routing_hop = 1
    for line in lines:
        if line.lower().startswith('from:'):
            results['from_address'] = line[5:].strip()
        elif line.lower().startswith('return-path:'):
            results['return_path'] = line[12:].strip().strip('<>')
        elif 'spf=' in line.lower() and 'pass' in line.lower():
            results['spf'] = {'status': 'pass', 'details': line.strip()}
        elif 'dkim=' in line.lower() and 'pass' in line.lower():
            results['dkim'] = {'status': 'pass', 'details': line.strip()}
        elif 'dmarc=' in line.lower() and 'pass' in line.lower():
            results['dmarc'] = {'status': 'pass', 'details': line.strip()}
        elif line.lower().startswith('received:'):
            # Very basic hop parsing
            parts = line.split()
            hop_from = "unknown"
            hop_by = "unknown"
            if 'from' in parts:
                idx = parts.index('from')
                if idx + 1 < len(parts): hop_from = parts[idx+1]
            if 'by' in parts:
                idx = parts.index('by')
                if idx + 1 < len(parts): hop_by = parts[idx+1]
            results['routing_path'].append({'hop': routing_hop, 'from': hop_from, 'by': hop_by})
            routing_hop += 1

    # Spoofing check
    if results['from_address'] and results['return_path']:
        from_domain = results['from_address'].split('@')[-1].strip('>')
        rp_domain = results['return_path'].split('@')[-1]
        
        if rp_domain and from_domain and rp_domain.lower() != from_domain.lower():
            results['spoofing_indicators'].append(f"Domain mismatch: From ({from_domain}) vs Return-Path ({rp_domain})")

    # Trust level
    passes = 0
    if results['spf']['status'] == 'pass': passes += 1
    if results['dkim']['status'] == 'pass': passes += 1
    if results['dmarc']['status'] == 'pass': passes += 1
    
    if passes == 3: results['overall_trust'] = 'high'
    elif passes >= 1: results['overall_trust'] = 'medium'
    else: results['overall_trust'] = 'low'
    
    return results

def get_whois_info(url):
    """Get WHOIS information for a domain"""
    try:
        # Extract domain from URL
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        # Remove port if present
        domain = domain.split(':')[0]
        # Remove www. prefix
        if domain.startswith('www.'):
            domain = domain[4:]
        
        if not domain:
            return None
        
        pass  # Logging disabled
        w = whois.whois(domain)
        
        if not w or not w.domain_name:
            return None
        
        def first_or_val(x):
            if isinstance(x, list): return x[0] if x else "N/A"
            return x if x else "N/A"
            
        def format_date(d):
            if isinstance(d, list): d = d[0]
            if d: return d.strftime('%Y-%m-%d')
            return "N/A"
            
        def get_domain_age(creation_date):
            from datetime import datetime, timezone
            if isinstance(creation_date, list): creation_date = creation_date[0]
            if not creation_date: return "Unknown"
            
            # Ensure creation_date is a datetime-like object
            if not hasattr(creation_date, 'year'): return "Unknown"
            
            try:
                if hasattr(creation_date, 'tzinfo') and creation_date.tzinfo:
                    # Target matches awareness of source
                    now = datetime.now(creation_date.tzinfo)
                else:
                    now = datetime.now()
                
                age = now - creation_date
                return f"{age.days // 365} years, {age.days % 365} days"
            except Exception as age_err:
                pass  # Logging disabled
                return "Unknown"

        return {
            'domain': first_or_val(w.domain_name),
            'registrar': first_or_val(w.registrar),
            'creation_date': format_date(w.creation_date),
            'expiration_date': format_date(w.expiration_date),
            'updated_date': format_date(w.updated_date),
            'domain_age': get_domain_age(w.creation_date),
            'registrant': {
                'name': first_or_val(getattr(w, 'name', None)),
                'organization': first_or_val(getattr(w, 'org', None)),
                'country': first_or_val(getattr(w, 'country', None)),
                'state': first_or_val(getattr(w, 'state', None)),
                'city': first_or_val(getattr(w, 'city', None)),
            },
            'nameservers': w.name_servers[:5] if w.name_servers else [],
            'status': w.status[:3] if isinstance(w.status, list) else ([w.status] if w.status else []),
            'dnssec': getattr(w, 'dnssec', None),
        }
    except Exception as e:
        pass  # Logging disabled
        return None

def sanitize_in_container(input_path, output_path, job_id):
    """Spawn an isolated Docker container to sanitize the document"""
    try:
        client = docker.DockerClient(base_url='unix:///var/run/docker.sock')
    except Exception as e:
        emit_progress(job_id, 'error', 'Cannot connect to Docker')
        return False
    
    container = None
    try:
        emit_progress(job_id, 'step2', 'Building worker image...')
        
        # Build (or select) a worker image based on current worker sources.
        # This avoids stale Docker cache issues where old worker code keeps running.
        host_pwd = os.environ.get('HOST_PWD', '/app')
        worker_tag = None
        try:
            hasher = hashlib.sha256()
            # Use relative paths from current CWD (which is /app in the container)
            for rel in ('Dockerfile.worker', 'worker.py'):
                if os.path.exists(rel):
                    with open(rel, 'rb') as f:
                        hasher.update(f.read())
                else:
                    pass  # Logging disabled
            worker_tag = f"cleansheet-worker:{hasher.hexdigest()[:12]}"
        except Exception as e:
            # Fall back to the legacy tag if we can't hash local files for any reason
            pass  # Logging disabled
            worker_tag = "cleansheet-worker:latest"

        try:
            client.images.get(worker_tag)
        except docker.errors.ImageNotFound:
            pass  # Logging disabled
            try:
                client.images.build(
                    path='/app',
                    dockerfile='Dockerfile.worker',
                    tag=worker_tag,
                    rm=True,
                    forcerm=True
                )
                pass  # Logging disabled
            except Exception as build_error:
                pass  # Logging disabled
                return False
        host_uploads = os.path.join(host_pwd, 'uploads')
        host_output = os.path.join(host_pwd, 'output')
        
        emit_progress(job_id, 'step2', 'Spawning container...')
        
        container = client.containers.run(
            worker_tag,
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
            network_mode='none',
            mem_limit='2g',
            cpu_quota=100000,
            security_opt=['no-new-privileges:true'],
            cap_drop=['ALL'],
            read_only=False,
            tmpfs={'/tmp': 'size=1g,mode=1777'},
        )
        
        emit_progress(job_id, 'step3', 'Container running - applying CDR...')
                        
        result = container.wait(timeout=300)
        
        logs = container.logs().decode('utf-8')
        
        emit_progress(job_id, 'step7', 'Terminating container...')
        
        container.remove(force=True)
        
        if result['StatusCode'] == 0:
            if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
                emit_progress(job_id, 'error', 'Output validation failed')
                return False
            
            emit_progress(job_id, 'step6', 'Scanning sanitized output...')
            
            is_clean, scan_message, _ = scan_with_virustotal(output_path, job_id)
            
            if not is_clean:
                if os.path.exists(output_path): os.remove(output_path)
                emit_progress(job_id, 'error', f'Threat detected: {scan_message}')
                return False
            
            emit_progress(job_id, 'complete', 'Sanitization complete')
            return True
        emit_progress(job_id, 'error', 'Container processing failed')
        return False
            
    except Exception as e:
        emit_progress(job_id, 'error', str(e))
        return False
    finally:
        if container:
            try:
                container.remove(force=True)
            except Exception:
                pass

def cleanup_orphaned_files():
    """Delete files older than 1 hour"""
    now = time.time()
    for folder in [UPLOAD_FOLDER, OUTPUT_FOLDER]:
        for f in os.listdir(folder):
            filepath = os.path.join(folder, f)
            if os.stat(filepath).st_mtime < now - 3600:
                try: os.remove(filepath)
                except: pass

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>CleanSheet - Advanced Security Suite</title>
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Cdefs%3E%3ClinearGradient id='g' x1='0' y1='0' x2='1' y2='1'%3E%3Cstop offset='0%25' stop-color='%2300ffff'/%3E%3Cstop offset='100%25' stop-color='%238a2be2'/%3E%3C/linearGradient%3E%3Cfilter id='glow' x='-20%25' y='-20%25' width='140%25' height='140%25'%3E%3CfeGaussianBlur stdDeviation='3' result='blur'/%3E%3CfeComposite in='SourceGraphic' in2='blur' operator='over'/%3E%3C/filter%3E%3C/defs%3E%3Cpath d='M50 5 L10 20 L10 60 C10 80 30 90 50 95 C70 90 90 80 90 60 L90 20 Z' fill='none' stroke='url(%23g)' stroke-width='6' filter='url(%23glow)'/%3E%3Cpath d='M50 15 L18 27 L18 58 C18 75 33 84 50 88 C67 84 82 75 82 58 L82 27 Z' fill='url(%23g)'/%3E%3Cpath d='M30 40 L60 40 M30 55 L70 55 M30 70 L50 70' stroke='%230a0e27' stroke-width='6' stroke-linecap='round'/%3E%3C/svg%3E">
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
            color: #ffffff;
            padding: 40px 20px;
            position: relative;
        }
        
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: 
                radial-gradient(circle at 20% 30%, rgba(0, 255, 255, 0.05) 0%, transparent 40%),
                radial-gradient(circle at 80% 70%, rgba(138, 43, 226, 0.05) 0%, transparent 40%);
            z-index: -1;
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
            max-width: 800px;
            width: 90%;
            margin: 0 auto;
            background: rgba(10, 14, 39, 0.92);
            padding: 35px 45px;
            border-radius: 24px;
            box-shadow: 0 0 50px rgba(0, 255, 255, 0.2);
            border: 1px solid rgba(0, 255, 255, 0.25);
            backdrop-filter: blur(15px);
            position: relative;
            z-index: 1;
        }
        
        h1 {
            font-family: 'Orbitron', sans-serif;
            text-align: center;
            color: #00ffff;
            font-size: 2.8em;
            margin-bottom: 10px;
            letter-spacing: 5px;
            text-shadow: 0 0 20px rgba(0, 255, 255, 0.5);
            font-weight: 900;
        }
        
        .subtitle {
            text-align: center;
            color: #8ab4f8;
            font-size: 1em;
            margin-bottom: 30px;
            letter-spacing: 2px;
            text-transform: uppercase;
        }
        
        .security-badge {
            display: block;
            margin: 0 auto 30px;
            padding: 8px 20px;
            background: rgba(0, 255, 255, 0.1);
            border: 1px solid #00ffff;
            border-radius: 50px;
            color: #00ffff;
            font-size: 0.8em;
            width: fit-content;
            font-family: 'Orbitron', sans-serif;
        }
        
        /* Tab Styles */
        .tab-nav {
            display: flex;
            gap: 10px;
            margin-bottom: 30px;
            border-bottom: 1px solid rgba(0, 255, 255, 0.2);
            padding-bottom: 10px;
        }
        
        .tab-btn {
            background: none;
            border: none;
            color: #8ab4f8;
            padding: 10px 20px;
            font-family: 'Orbitron', sans-serif;
            font-size: 0.9em;
            cursor: pointer;
            transition: all 0.3s;
            position: relative;
        }
        
        .tab-btn:hover {
            color: #00ffff;
        }
        
        .tab-btn.active {
            color: #00ffff;
        }
        
        .tab-btn.active::after {
            content: '';
            position: absolute;
            bottom: -11px;
            left: 0;
            width: 100%;
            height: 3px;
            background: #00ffff;
            box-shadow: 0 0 10px #00ffff;
        }
        
        .tab-content {
            display: none;
            animation: fadeIn 0.5s ease;
        }
        
        .tab-content.active {
            display: block;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .info-box {
            background: rgba(0, 255, 255, 0.05);
            border-left: 4px solid #00ffff;
            padding: 25px;
            margin-bottom: 30px;
            border-radius: 0 15px 15px 0;
        }
        
        .info-box h3 {
            color: #00ffff;
            margin-bottom: 15px;
            font-family: 'Orbitron', sans-serif;
            font-size: 1.1em;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .info-box ul {
            list-style-type: none;
            color: #8ab4f8;
            font-size: 0.9em;
        }
        
        .info-box li {
            margin-bottom: 10px;
            padding-left: 20px;
            position: relative;
        }
        
        .info-box li::before {
            content: '◢';
            position: absolute;
            left: 0;
            color: #00ffff;
            font-size: 0.8em;
        }
        
        .upload-area {
            border: 2px dashed rgba(0, 255, 255, 0.3);
            border-radius: 20px;
            padding: 60px 40px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s;
            margin-bottom: 30px;
            position: relative;
            background: rgba(0, 255, 255, 0.02);
        }
        
        .upload-area:hover {
            border-color: #00ffff;
            background: rgba(0, 255, 255, 0.05);
            box-shadow: 0 0 20px rgba(0, 255, 255, 0.1);
        }
        
        .upload-area p {
            margin: 5px 0;
            font-family: 'Orbitron', sans-serif;
        }
        
        input[type="file"] {
            display: none;
        }
        
        .file-name {
            margin-top: 15px;
            color: #00ffff;
            font-size: 0.9em;
            word-break: break-all;
        }
        
        .upload-btn {
            background: linear-gradient(45deg, #00ffff, #8a2be2);
            color: white;
            border: none;
            padding: 15px 40px;
            font-size: 1.1em;
            border-radius: 50px;
            cursor: pointer;
            font-family: 'Orbitron', sans-serif;
            font-weight: bold;
            letter-spacing: 2px;
            transition: all 0.3s;
            box-shadow: 0 0 20px rgba(0, 255, 255, 0.3);
            text-transform: uppercase;
        }
        
        .upload-btn:hover:not(:disabled) {
            transform: scale(1.05);
            box-shadow: 0 0 30px rgba(0, 255, 255, 0.5);
        }
        
        .upload-btn:disabled {
            background: #2a2d3e;
            cursor: not-allowed;
            opacity: 0.7;
            box-shadow: none;
        }
        
        .status {
            margin-top: 30px;
            text-align: center;
            padding: 20px;
            border-radius: 15px;
            display: none;
        }
        
        .status.processing {
            background: rgba(0, 255, 255, 0.05);
            border: 1px solid rgba(0, 255, 255, 0.2);
            color: #00ffff;
        }
        
        .status.success {
            background: rgba(0, 255, 255, 0.1);
            border: 1px solid #00ffff;
            color: #00ffff;
        }
        
        .status.warning {
            background: rgba(255, 170, 0, 0.1);
            border: 1px solid #ffaa00;
            color: #ffaa00;
        }
        
        .status.error {
            background: rgba(255, 68, 68, 0.1);
            border: 1px solid #ff4444;
            color: #ff4444;
        }
        
        /* Action Buttons */
        .action-btn {
            background: rgba(0, 255, 255, 0.1);
            color: #00ffff;
            border: 1px solid #00ffff;
            padding: 12px 30px;
            font-family: 'Orbitron', sans-serif;
            border-radius: 30px;
            cursor: pointer;
            transition: all 0.3s;
            letter-spacing: 1px;
            margin-top: 10px;
        }
        
        .action-btn:hover {
            background: rgba(0, 255, 255, 0.2);
            box-shadow: 0 0 15px rgba(0, 255, 255, 0.3);
        }
        
        /* Result Panels */
        .results-panel {
            margin-top: 30px;
            padding: 25px;
            background: rgba(0, 255, 255, 0.03);
            border: 1px solid rgba(0, 255, 255, 0.1);
            border-radius: 15px;
            display: none;
        }
        
        .results-panel.show {
            display: block;
        }
        
        .result-header {
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 1px solid rgba(0, 255, 255, 0.1);
        }
        
        .result-icon {
            font-size: 2em;
        }
        
        .result-verdict {
            font-family: 'Orbitron', sans-serif;
            font-size: 1.5em;
            font-weight: bold;
            letter-spacing: 2px;
        }
        
        .verdict-clean { color: #00ff00; }
        .verdict-malicious { color: #ff4444; }
        .verdict-suspicious { color: #ffaa00; }
        .verdict-pending { color: #8ab4f8; }
        
        .result-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }
        
        .stat-box {
            background: rgba(255,255,255,0.05);
            padding: 15px;
            border-radius: 10px;
            text-align: center;
            border: 1px solid transparent;
            transition: all 0.3s;
        }
        
        .stat-malicious { border-color: rgba(255, 68, 68, 0.5); background: rgba(255, 68, 68, 0.15); }
        .stat-malicious .stat-value { color: #ff4444; font-size: 1.8em; }
        .stat-malicious .stat-label { color: #ff8888; }
        
        .stat-suspicious { border-color: rgba(255, 170, 0, 0.5); background: rgba(255, 170, 0, 0.15); }
        .stat-suspicious .stat-value { color: #ffaa00; font-size: 1.8em; }
        .stat-suspicious .stat-label { color: #ffcc66; }
        
        .stat-safe { border-color: rgba(0, 255, 0, 0.5); background: rgba(0, 255, 0, 0.15); }
        .stat-safe .stat-value { color: #00ff00; font-size: 1.8em; }
        .stat-safe .stat-label { color: #66ff66; }
        
        .stat-neutral { border-color: rgba(138, 180, 248, 0.4); background: rgba(138, 180, 248, 0.1); }
        .stat-neutral .stat-value { color: #8ab4f8; font-size: 1.8em; }
        .stat-neutral .stat-label { color: #a8c8ff; }
        
        .stat-value {
            font-size: 1.5em;
            font-weight: bold;
            color: #fff;
        }
        
        .stat-label {
            font-size: 0.7em;
            color: #00ffff;
            text-transform: uppercase;
            margin-top: 5px;
        }
        
        .engine-list {
            max-height: 200px;
            overflow-y: auto;
            border: 1px solid rgba(255,255,255,0.05);
            border-radius: 10px;
            padding: 10px;
        }
        
        .engine-item {
            display: flex;
            justify-content: space-between;
            padding: 8px 10px;
            border-bottom: 1px solid rgba(255,255,255,0.03);
            font-size: 0.85em;
        }
        
        .engine-name { color: #8ab4f8; }
        .engine-result { color: #ff4444; }
        
        /* WHOIS Section in Results */
        .whois-section {
            margin-top: 25px;
            padding-top: 20px;
            border-top: 1px solid rgba(255,255,255,0.1);
        }
        
        .whois-title {
            color: #00ffff;
            font-family: 'Orbitron', sans-serif;
            font-size: 0.9em;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .whois-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 10px;
        }
        
        .whois-item {
            background: rgba(255,255,255,0.02);
            padding: 10px;
            border-radius: 8px;
        }
        
        .whois-label {
            font-size: 0.7em;
            color: #00ffff;
            text-transform: uppercase;
        }
        
        .whois-value {
            font-size: 0.85em;
            color: #fff;
            margin-top: 3px;
            font-family: 'Roboto Mono', monospace;
        }
        
        /* Email Validation Styles */
        .sub-tab-nav {
            display: flex;
            gap: 10px;
            margin: 20px 0;
            justify-content: center;
        }
        
        .sub-tab-btn {
            background: rgba(138,43,226,0.1);
            border: 1px solid rgba(138,43,226,0.3);
            color: #c9a8ff;
            padding: 8px 20px;
            font-family: 'Roboto Mono', monospace;
            font-size: 0.75em;
            cursor: pointer;
            border-radius: 20px;
            transition: all 0.3s;
        }
        
        .sub-tab-btn:hover {
            background: rgba(138,43,226,0.2);
        }
        
        .sub-tab-btn.active {
            background: rgba(138,43,226,0.3);
            color: #00ffff;
            border-color: #00ffff;
        }
        
        .sub-tab-content {
            display: none;
        }
        
        .sub-tab-content.active {
            display: block;
        }
        
        /* Input fields */
        .input-group {
            margin-bottom: 20px;
        }
        
        .input-group label {
            display: block;
            color: #00ffff;
            font-size: 0.85em;
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .cyber-input {
            width: 100%;
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(0,255,255,0.2);
            padding: 12px 20px;
            color: #fff;
            font-family: 'Roboto Mono', monospace;
            border-radius: 10px;
            outline: none;
            transition: all 0.3s;
        }
        
        .cyber-input:focus {
            border-color: #00ffff;
            background: rgba(0,255,255,0.05);
            box-shadow: 0 0 10px rgba(0,255,255,0.2);
        }
        
        .cyber-textarea {
            width: 100%;
            height: 150px;
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(0,255,255,0.2);
            padding: 15px;
            color: #fff;
            font-family: 'Roboto Mono', monospace;
            border-radius: 10px;
            outline: none;
            resize: vertical;
            font-size: 0.85em;
        }
        
        .cyber-textarea:focus {
            border-color: #00ffff;
            background: rgba(0,255,255,0.05);
        }
        
        /* Email Trust Score */
        .trust-score {
            margin: 20px 0;
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .trust-meter {
            flex-grow: 1;
            height: 10px;
            background: rgba(255,255,255,0.1);
            border-radius: 5px;
            overflow: hidden;
        }
        
        .trust-fill {
            height: 100%;
            background: linear-gradient(90deg, #ff4444, #ffaa00, #00ff00);
            width: 0%;
            transition: width 1s ease;
        }
        
        .trust-value {
            font-family: 'Orbitron', sans-serif;
            font-weight: bold;
            color: #00ffff;
            width: 40px;
            text-align: right;
        }
        
        .check-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px;
            background: rgba(0,255,255,0.02);
            border-radius: 8px;
            margin-bottom: 8px;
            font-size: 0.9em;
        }
        
        .check-icon { margin-right: 10px; }
        .check-pass { color: #00ff00; }
        .check-fail { color: #ff4444; }
        .check-warn { color: #ffaa00; }
        .check-info { color: #8ab4f8; }
        
        .warning-badge {
            background: rgba(255, 170, 0, 0.1);
            color: #ffaa00;
            padding: 8px 15px;
            border-radius: 8px;
            font-size: 0.8em;
            margin-top: 10px;
            border: 1px solid rgba(255, 170, 0, 0.2);
        }
        
        .error-badge {
            background: rgba(255, 68, 68, 0.1);
            color: #ff4444;
            padding: 8px 15px;
            border-radius: 8px;
            font-size: 0.8em;
            margin-top: 10px;
            border: 1px solid rgba(255, 68, 68, 0.2);
        }
        
        /* Auth Results */
        .auth-section { margin-top: 20px; }
        .auth-title { color: #8ab4f8; font-size: 0.8em; text-transform: uppercase; margin-bottom: 10px; }
        
        .auth-item {
            background: rgba(255,255,255,0.02);
            padding: 12px;
            border-radius: 10px;
            margin-bottom: 10px;
        }
        
        .auth-status {
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75em;
            font-weight: bold;
            margin-left: 10px;
            text-transform: uppercase;
        }
        
        .auth-pass { background: rgba(0,255,0,0.2); color: #00ff00; }
        .auth-fail { background: rgba(255,0,0,0.2); color: #ff4444; }
        .auth-unknown { background: rgba(255,255,255,0.1); color: #ccc; }
        
        .auth-details {
            font-size: 0.75em;
            color: #8ab4f8;
            margin-top: 5px;
            word-break: break-all;
        }
        
        /* Routing Table */
        .routing-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.75em;
            margin-top: 10px;
        }
        
        .routing-table th, .routing-table td {
            text-align: left;
            padding: 8px;
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }
        
        .routing-table th { color: #00ffff; text-transform: uppercase; }
        .routing-table td { color: #8ab4f8; }
        
        .processing-steps {
            margin-top: 40px;
            text-align: left;
            max-width: 400px;
            margin-left: auto;
            margin-right: auto;
        }
        
        .processing-step {
            margin-bottom: 15px;
            color: rgba(255, 255, 255, 0.4);
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 0.9em;
            transition: all 0.3s;
        }
        
        .processing-step.active {
            color: #00ffff;
            text-shadow: 0 0 10px rgba(0, 255, 255, 0.4);
        }
        
        .processing-step.complete {
            color: #00ff00;
        }
        
        .step-icon {
            font-size: 1.2em;
        }
        
        .cyber-spinner {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 2px solid rgba(255,255,255,0.3);
            border-radius: 50%;
            border-top-color: #fff;
            animation: spin 1s ease-in-out infinite;
            margin-right: 10px;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        /* Mobile Responsive Styles */
        @media screen and (max-width: 768px) {
            .container {
                padding: 20px;
                width: 95%;
            }
            h1 {
                font-size: 1.8em;
                letter-spacing: 2px;
            }
            .tab-nav {
                flex-wrap: wrap;
                justify-content: center;
            }
            .tab-btn {
                padding: 8px 12px;
                font-size: 0.8em;
            }
            .upload-area {
                padding: 40px 20px;
            }
            .stat-box {
                padding: 10px;
            }
            .stat-value {
                font-size: 1.4em;
            }
            .whois-grid {
                grid-template-columns: 1fr;
            }
        }

        @media screen and (max-width: 480px) {
            body {
                padding: 20px 10px;
            }
            .container {
                padding: 15px;
            }
            h1 {
                font-size: 1.5em;
            }
            .security-badge {
                font-size: 0.7em;
                padding: 5px 12px;
            }
            .cyber-input {
                font-size: 0.9em;
            }
        }
    </style>
</head>
<body>

    <div class="boxes-background">
        <div class="boxes-container" id="boxesContainer"></div>
    </div>

    <div class="container">
        <h1>CleanSheet</h1>
        <p class="subtitle">Advanced Security Suite</p>
        
        <div class="security-badge">
            🛡️ Document Sanitization &bull; 🔗 URL Scanning &bull; 📧 Email Verification
        </div>
        
        <!-- Tab Navigation -->
        <div class="tab-nav">
            <button class="tab-btn active" onclick="switchTab('sanitize')">📄 Sanitize</button>
            <button class="tab-btn" onclick="switchTab('url')">🔗 Check URL</button>
            <button class="tab-btn" onclick="switchTab('ip')">🌐 Check IP</button>
            <button class="tab-btn" onclick="switchTab('email')">📧 Check Email</button>
        </div>
        
        <!-- Tab 1: Document Sanitization -->
        <div id="tab-sanitize" class="tab-content active">
            <div class="info-box">
                <h3>◢ Enhanced Security Protocol ◣</h3>
                <ul>
                    <li>Multi-engine antivirus scanning (VirusTotal)</li>
                    <li>Content Disarm & Reconstruction (CDR)</li>
                    <li>Strip macros, scripts, and embedded objects</li>
                    <li>Render to pixel matrix in isolated container</li>
                </ul>
            </div>
            
            <form method="POST" enctype="multipart/form-data" id="uploadForm">
                <div class="upload-area" onclick="document.getElementById('fileInput').click()">
                    <p style="font-size: 3em; margin-bottom: 10px;">🔒</p>
                    <p style="color: #00ffff; font-size: 1.2em; margin-bottom: 5px; font-family: 'Orbitron', sans-serif;">
                        INITIATE SECURE UPLOAD
                    </p>
                    <p style="color: #8ab4f8; font-size: 0.8em;">
                        SUPPORTED: PDF &bull; DOCX &bull; XLSX &bull; PPTX &bull; IMAGES (Max 100MB)
                    </p>
                    <input type="file" name="file" id="fileInput" onchange="showFileName()" required>
                    <div class="file-name" id="fileName"></div>
                </div>
                <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 10px; margin: 15px 0;">
                    <label style="display: flex; align-items: center; gap: 8px; cursor: pointer; padding: 8px 16px; border: 1px solid rgba(0, 255, 255, 0.2); border-radius: 8px; background: rgba(0, 255, 255, 0.05); transition: all 0.3s;" onmouseover="this.style.borderColor='rgba(0, 255, 255, 0.5)'; this.style.background='rgba(0, 255, 255, 0.1)'" onmouseout="this.style.borderColor='rgba(0, 255, 255, 0.2)'; this.style.background='rgba(0, 255, 255, 0.05)'">
                        <input type="checkbox" name="vt_scan" id="vtScanCheckbox" style="width: 18px; height: 18px; accent-color: #00ffff; cursor: pointer;" onchange="toggleVTDisclaimer()">
                        <span style="color: #8ab4f8; font-size: 0.85em; font-family: 'Orbitron', sans-serif;">🔍 Include VirusTotal Scan</span>
                    </label>
                    <div id="vtDisclaimer" style="display: none; max-width: 400px; padding: 10px; border: 1px solid rgba(255, 170, 0, 0.3); border-radius: 8px; background: rgba(255, 170, 0, 0.1); color: #ffaa00; font-size: 0.75em; text-align: center; margin-top: 5px;">
                        ⚠️ <strong>DISCLAIMER:</strong> Files will be uploaded to VirusTotal (a third-party service). Do not upload sensitive data like passwords, credit card info, or proprietary documents.
                    </div>
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
                    <div class="processing-step" id="step1" style="display: none;">
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
                        <span class="step-icon">( )</span>
                        <span>Terminating container...</span>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Tab 2: URL Check -->
        <div id="tab-url" class="tab-content">
            <div class="info-box">
                <h3>◢ URL Security Scanner ◣</h3>
                <ul>
                    <li>Scan URLs with 70+ antivirus engines via VirusTotal</li>
                    <li>Detect phishing, malware, and suspicious sites</li>
                    <li>WHOIS domain registration information</li>
                    <li>Domain age and registrar details</li>
                </ul>
            </div>
            
            <div class="input-group">
                <label for="urlInput">Enter URL to Check</label>
                <input type="text" id="urlInput" class="cyber-input" placeholder="https://example.com">
            </div>
            
            <center>
                    <button class="action-btn" id="checkUrlBtn" onclick="checkUrl()">
                        🔍 SCAN URL
                    </button>
                </center>
                
                <div class="results-panel" id="urlResults">
                    <div class="result-header">
                        <span class="result-icon" id="urlResultIcon">🔍</span>
                        <span class="result-verdict" id="urlVerdict">Scanning...</span>
                    </div>
                <div class="result-stats" id="urlStats"></div>
                <div class="engine-list" id="urlEngines"></div>
                
                <!-- WHOIS Section -->
                <div class="whois-section" id="whoisSection">
                    <div class="whois-title">🔍 Domain Information (WHOIS)</div>
                    <div class="whois-grid" id="whoisInfo"></div>
                </div>
            </div>
        </div>
        
        <!-- Tab 3: IP Check -->
        <div id="tab-ip" class="tab-content">
            <div class="info-box">
                <h3>◢ IP Reputation Analyzer ◣</h3>
                <ul>
                    <li>Check IP reputation across 70+ security engines</li>
                    <li>Identify malicious, suspicious, and known botnet IPs</li>
                    <li>View ASN, domain owner, and geographic information</li>
                    <li>Identify VPN, proxy, and Tor exit nodes</li>
                </ul>
            </div>
            
            <div class="input-group">
                <label for="ipInput">Enter IP Address to Check</label>
                <input type="text" id="ipInput" class="cyber-input" placeholder="8.8.8.8">
            </div>
            
            <center>
                <button class="action-btn" id="checkIpBtn" onclick="checkIp()">
                    🔍 SCAN IP
                </button>
            </center>
                
            <div class="results-panel" id="ipResults">
                <div class="result-header">
                    <span class="result-icon" id="ipResultIcon">🌐</span>
                    <span class="result-verdict" id="ipVerdict">Scanning...</span>
                </div>
                <div class="result-stats" id="ipStats"></div>
                
                <!-- IP Details Section -->
                <div class="whois-section" id="ipInfoSection" style="display: none;">
                    <div class="whois-title">🌐 IP Information</div>
                    <div class="whois-grid" id="ipDetails"></div>
                </div>
            </div>
        </div>
        
        <!-- Tab 4: Email Check -->
        <div id="tab-email" class="tab-content">
            <div class="info-box">
                <h3>◢ Email Security Analyzer ◣</h3>
                <ul>
                    <li>Validate email addresses for format and domain</li>
                    <li>Check MX records and detect disposable emails</li>
                    <li>Analyze email headers for SPF/DKIM/DMARC</li>
                    <li>Detect spoofing and phishing attempts</li>
                </ul>
            </div>
            
            <!-- Sub-tabs -->
            <div class="sub-tab-nav">
                <button class="sub-tab-btn active" onclick="switchEmailTab('address')">📧 Check Address</button>
                <button class="sub-tab-btn" onclick="switchEmailTab('headers')">📋 Analyze Headers</button>
            </div>
            
            <!-- Email Address Sub-tab -->
            <div id="email-address" class="sub-tab-content active">
                <div class="input-group">
                    <label for="emailInput">Enter Email Address</label>
                    <input type="email" id="emailInput" class="cyber-input" placeholder="user@example.com">
                </div>
                
                <center>
                    <button class="action-btn" id="checkEmailBtn" onclick="checkEmail()">
                        &#10003; VALIDATE EMAIL
                    </button>
                </center>
                
                <div class="results-panel" id="emailResults">
                    <div class="result-header">
                        <span class="result-icon" id="emailResultIcon">&#128231;</span>
                        <span class="result-verdict" id="emailVerdict">Checking...</span>
                    </div>
                    
                    <div class="trust-score" id="emailTrustScore">
                        <span style="color: #8ab4f8;">Trust Score:</span>
                        <div class="trust-meter">
                            <div class="trust-fill" id="trustFill" style="width: 0%"></div>
                        </div>
                        <span class="trust-value" id="trustValue">0</span>
                    </div>
                    
                    <div id="emailChecks"></div>
                    <div id="emailWarnings"></div>
                </div>
            </div>
            
            <!-- Email Headers Sub-tab -->
            <div id="email-headers" class="sub-tab-content">
                <div class="input-group">
                    <label for="headersInput">Paste Email Headers</label>
                    <textarea id="headersInput" class="cyber-textarea" placeholder="Paste raw email headers here...&#10;&#10;Example:&#10;From: sender@example.com&#10;Return-Path: <bounce@example.com>&#10;Authentication-Results: spf=pass dkim=pass dmarc=pass&#10;Received: from mail.example.com by mx.receiver.com"></textarea>
                </div>
                
                <center>
                    <button class="action-btn" id="analyzeHeadersBtn" onclick="analyzeHeaders()">
                        🔍 ANALYZE HEADERS
                    </button>
                </center>
                
                <div class="results-panel" id="headersResults">
                    <div class="result-header">
                        <span class="result-icon" id="headersResultIcon">&#128203;</span>
                        <span class="result-verdict" id="headersVerdict">Analyzing...</span>
                    </div>
                    
                    <div class="auth-section">
                        <div class="auth-title">Authentication Results</div>
                        <div id="authItems"></div>
                    </div>
                    
                    <div id="spoofingAlerts"></div>
                    
                    <div class="auth-section">
                        <div class="auth-title">Routing Path</div>
                        <table class="routing-table" id="routingTable">
                            <thead>
                                <tr><th>Hop</th><th>From</th><th>By</th></tr>
                            </thead>
                            <tbody id="routingBody"></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Tab switching logic
        function switchTab(tabId) {
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            
            document.getElementById('tab-' + tabId).classList.add('active');
            event.currentTarget.classList.add('active');
        }

        function switchEmailTab(subTabId) {
            document.querySelectorAll('#tab-email .sub-tab-content').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('#tab-email .sub-tab-btn').forEach(b => b.classList.remove('active'));
            
            document.getElementById('email-' + subTabId).classList.add('active');
            event.currentTarget.classList.add('active');
        }

        // Background animation
        function createBoxes() {
            const container = document.getElementById('boxesContainer');
            if (!container) return;
            container.innerHTML = '';
            
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
        createBoxes();
        window.addEventListener('resize', createBoxes);

        // VT Disclaimer toggle
        function toggleVTDisclaimer() {
            const checkbox = document.getElementById('vtScanCheckbox');
            const disclaimer = document.getElementById('vtDisclaimer');
            disclaimer.style.display = checkbox.checked ? 'block' : 'none';
        }

        // IP Check Logic
        async function checkIp() {
            const ip = document.getElementById('ipInput').value;
            const btn = document.getElementById('checkIpBtn');
            const results = document.getElementById('ipResults');
            const verdict = document.getElementById('ipVerdict');
            const icon = document.getElementById('ipResultIcon');
            const stats = document.getElementById('ipStats');
            const detailsSection = document.getElementById('ipInfoSection');
            const detailsGrid = document.getElementById('ipDetails');
            
            if (!ip) return;
            
            btn.disabled = true;
            results.classList.add('show');
            results.style.display = 'block';
            verdict.textContent = 'Scanning IP...';
            icon.textContent = '🌐';
            stats.innerHTML = '<div class="cyber-spinner"></div> Analyzing reputation...';
            detailsSection.style.display = 'none';
            
            try {
                const response = await fetch('/api/check-ip', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    const isMalicious = data.malicious > 0;
                    verdict.textContent = isMalicious ? 'THREAT DETECTED' : 'CLEAN / SAFE';
                    verdict.className = 'result-verdict ' + (isMalicious ? 'verdict-malicious' : 'verdict-clean');
                    icon.textContent = isMalicious ? '☣️' : '🛡️';
                    
                    stats.innerHTML = `
                        <div class="stat-box stat-malicious"><div class="stat-value">${data.malicious}</div><div class="stat-label">Malicious</div></div>
                        <div class="stat-box stat-suspicious"><div class="stat-value">${data.suspicious}</div><div class="stat-label">Suspicious</div></div>
                        <div class="stat-box stat-safe"><div class="stat-value">${data.harmless}</div><div class="stat-label">Harmless</div></div>
                        <div class="stat-box stat-neutral"><div class="stat-value">${data.undetected}</div><div class="stat-label">Undetected</div></div>
                    `;
                    
                    detailsSection.style.display = 'block';
                    detailsGrid.innerHTML = `
                        <div class="whois-item"><div class="whois-label">IP Address</div><div class="whois-value">${data.ip}</div></div>
                        <div class="whois-item"><div class="whois-label">Country</div><div class="whois-value">${data.country}</div></div>
                        <div class="whois-item"><div class="whois-label">ASN</div><div class="whois-value">${data.asn}</div></div>
                        <div class="whois-item"><div class="whois-label">ASN Owner</div><div class="whois-value">${data.as_owner}</div></div>
                        <div class="whois-item"><div class="whois-label">Reputation</div><div class="whois-value">${data.reputation}</div></div>
                        <div class="whois-item" style="grid-column: span 2;"><div class="whois-label">Tags</div><div class="whois-value">${data.tags.length ? data.tags.join(', ') : 'None'}</div></div>
                    `;
                } else {
                    verdict.textContent = 'ERROR';
                    verdict.className = 'result-verdict verdict-malicious';
                    stats.innerHTML = `<div style="color: #ff4444; padding: 20px;">${data.error}</div>`;
                }
            } catch (err) {
                verdict.textContent = 'SYSTEM FAILURE';
                stats.innerHTML = `<div style="color: #ff4444; padding: 20px;">${err.message}</div>`;
            } finally {
                btn.disabled = false;
            }
        }

        // Anti-Inspect Logic (Hinder developer tools)
        (function() {
            // Disable right click
            document.addEventListener('contextmenu', e => e.preventDefault());

            // Disable key shortcuts
            document.addEventListener('keydown', e => {
                if (
                    e.keyCode === 123 || // F12
                    (e.ctrlKey && e.shiftKey && (e.keyCode === 73 || e.keyCode === 74)) || // Ctrl+Shift+I/J
                    (e.ctrlKey && e.keyCode === 85) // Ctrl+U
                ) {
                    e.preventDefault();
                    return false;
                }
            });

            // Detect DevTools opening
            setInterval(() => {
                const threshold = 160;
                if (window.outerWidth - window.innerWidth > threshold || window.outerHeight - window.innerHeight > threshold) {
                    document.body.innerHTML = '<div style="background:#0a0e27; color:#ff4444; height:100vh; display:flex; align-items:center; justify-content:center; font-family:sans-serif; text-align:center; padding:20px;"><div><h1>⚠️ SECURITY VIOLATION</h1><p>Developer tools are disabled for security reasons.</p><button onclick="location.reload()" style="background:#00ffff; border:none; padding:10px 20px; border-radius:5px; cursor:pointer;">Reload Page</button></div></div>';
                }
            }, 1000);
        })();

        // Drag and Drop Logic
        const uploadArea = document.querySelector('.upload-area');
        const fileInput = document.getElementById('fileInput');

        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.style.borderColor = '#00ffff';
            uploadArea.style.background = 'rgba(0, 255, 255, 0.1)';
        });

        uploadArea.addEventListener('dragleave', () => {
            uploadArea.style.borderColor = '';
            uploadArea.style.background = '';
        });

        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.style.borderColor = '';
            uploadArea.style.background = '';
            
            if (e.dataTransfer.files.length) {
                fileInput.files = e.dataTransfer.files;
                showFileName();
            }
        });

        // Existing document sanitizer logic
        function showFileName() {
            const input = document.getElementById('fileInput');
            const fileName = document.getElementById('fileName');
            fileName.textContent = input.files[0] ? 'SELECTED: ' + input.files[0].name : '';
        }

        document.getElementById('uploadForm').onsubmit = async (e) => {
            e.preventDefault();
            const btn = document.getElementById('submitBtn');
            const status = document.getElementById('status');
            const statusMessage = document.getElementById('statusMessage');
            const stepsContainer = document.getElementById('processingSteps');
            const allSteps = ['step1', 'step2', 'step3', 'step4', 'step5', 'step6', 'step7'];
            
            const vtScanEnabled = document.getElementById('vtScanCheckbox').checked;
            
            btn.disabled = true;
            status.style.display = 'block';
            status.className = 'status processing';
            statusMessage.innerHTML = '<div class="cyber-spinner"></div> INITIATING SANITIZATION...';
            stepsContainer.style.display = 'block';
            
            // Show/hide VT scan step based on checkbox
            const step1El = document.getElementById('step1');
            if (step1El) step1El.style.display = vtScanEnabled ? 'flex' : 'none';
            
            // Reset all steps
            allSteps.forEach(stepId => {
                const el = document.getElementById(stepId);
                if (el) {
                    el.classList.remove('active', 'complete');
                    el.querySelector('.step-icon').textContent = '◯';
                }
            });
            
            const formData = new FormData(e.target);
            if (vtScanEnabled) {
                formData.append('vt_scan', 'on');
            }
            
            // Generate a job ID for progress tracking
            const jobId = crypto.randomUUID();
            formData.append('job_id', jobId);
            
            // Connect to SSE for real-time progress updates
            const eventSource = new EventSource('/api/progress/' + jobId);
            
            eventSource.onmessage = (event) => {
                const [step, message] = event.data.split('|');
                
                if (step === 'error') {
                    statusMessage.innerHTML = 'ERROR: ' + message;
                    eventSource.close();
                    return;
                }
                
                if (step === 'complete') {
                    statusMessage.innerHTML = '✓ Sanitization complete';
                    eventSource.close();
                    return;
                }
                
                // Map step to UI element
                const stepMap = {
                    'step2': 'step2',
                    'step3': 'step3',
                    'step4': 'step4',
                    'step5': 'step5',
                    'step6': 'step6',
                    'step7': 'step7'
                };
                
                if (stepMap[step]) {
                    // Complete all previous steps
                    const stepOrder = ['step1', 'step2', 'step3', 'step4', 'step5', 'step6', 'step7'];
                    const currentIndex = stepOrder.indexOf(stepMap[step]);
                    
                    for (let i = 0; i <= currentIndex; i++) {
                        setStepComplete(stepOrder[i]);
                    }
                    
                    // Set current step as active
                    if (currentIndex < stepOrder.length - 1) {
                        setStepActive(stepOrder[currentIndex + 1]);
                    }
                    
                    statusMessage.innerHTML = '<div class="cyber-spinner"></div> ' + message + '...';
                }
            };
            
            eventSource.onerror = () => {
                eventSource.close();
            };
            
            // Helper to update step status
            const setStepActive = (stepId) => {
                const el = document.getElementById(stepId);
                if (el) {
                    el.classList.add('active');
                    el.querySelector('.step-icon').innerHTML = '<div class="cyber-spinner" style="width:16px;height:16px;margin:0;"></div>';
                }
            };
            
            const setStepComplete = (stepId) => {
                const el = document.getElementById(stepId);
                if (el) {
                    el.classList.remove('active');
                    el.classList.add('complete');
                    el.querySelector('.step-icon').textContent = '✓';
                }
            };
            
            try {
                // Start step 1 (VT scan) only if enabled
                if (vtScanEnabled) {
                    setStepActive('step1');
                    statusMessage.innerHTML = '<div class="cyber-spinner"></div> Pre-scanning with VirusTotal...';
                } else {
                    setStepActive('step2');
                    statusMessage.innerHTML = '<div class="cyber-spinner"></div> Spawning isolated container...';
                }
                
                // Make the actual request
                const response = await fetch('/', {
                    method: 'POST',
                    body: formData
                });
                
                // Once we get a response, all backend steps are complete
                // Mark all steps complete in sequence with small delays for visual effect
                const completeStepsSequentially = async () => {
                    const stepMessages = [
                        'Pre-scanning complete',
                        'Container spawned',
                        'CDR applied',
                        'Pixel rendering done',
                        'PDF reconstructed',
                        'Output validated',
                        'Container terminated'
                    ];
                    
                    for (let i = 0; i < allSteps.length; i++) {
                        setStepComplete(allSteps[i]);
                        if (i < allSteps.length - 1) {
                            setStepActive(allSteps[i + 1]);
                            statusMessage.innerHTML = '<div class="cyber-spinner"></div> ' + stepMessages[i + 1] + '...';
                        }
                        await new Promise(r => setTimeout(r, 150)); // Quick visual feedback
                    }
                };
                
                await completeStepsSequentially();

                if (response.ok) {
                    const threatWarning = response.headers.get('X-Threat-Warning');
                    const blob = await response.blob();
                    
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.style.display = 'none';
                    a.href = url;
                    
                    const fileInput = document.getElementById('fileInput');
                    const fileName = fileInput.files[0] ? fileInput.files[0].name : 'document';
                    const baseName = fileName.substring(0, fileName.lastIndexOf('.')) || fileName;
                    a.download = `sanitized_${baseName}.pdf`;
                    
                    document.body.appendChild(a);
                    a.click();
                    window.URL.revokeObjectURL(url);
                    document.body.removeChild(a);
                    
                    status.className = 'status success';
                    
                    // Get pre-scan result from headers
                    const prescanResult = response.headers.get('X-Prescan-Result') || '';
                    const prescanStatsRaw = response.headers.get('X-Prescan-Stats');
                    const isThreatNeutralized = prescanResult.startsWith('THREAT:');
                    const prescanMessage = prescanResult.replace('CLEAN: ', '').replace('THREAT: ', '');
                    
                    // Parse stats if available
                    let statsHtml = '';
                    if (prescanStatsRaw) {
                        try {
                            const stats = JSON.parse(prescanStatsRaw);
                            statsHtml = `
                                <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin: 15px 0;">
                                    <div style="background: rgba(255, 68, 68, 0.15); border: 1px solid rgba(255, 68, 68, 0.4); padding: 10px; border-radius: 8px; text-align: center;">
                                        <div style="color: #ff4444; font-size: 1.5em; font-weight: bold;">${stats.malicious}</div>
                                        <div style="color: #ff8888; font-size: 0.7em; text-transform: uppercase;">Malicious</div>
                                    </div>
                                    <div style="background: rgba(255, 170, 0, 0.15); border: 1px solid rgba(255, 170, 0, 0.4); padding: 10px; border-radius: 8px; text-align: center;">
                                        <div style="color: #ffaa00; font-size: 1.5em; font-weight: bold;">${stats.suspicious}</div>
                                        <div style="color: #ffcc66; font-size: 0.7em; text-transform: uppercase;">Suspicious</div>
                                    </div>
                                    <div style="background: rgba(0, 255, 0, 0.15); border: 1px solid rgba(0, 255, 0, 0.4); padding: 10px; border-radius: 8px; text-align: center;">
                                        <div style="color: #00ff00; font-size: 1.5em; font-weight: bold;">${stats.harmless}</div>
                                        <div style="color: #66ff66; font-size: 0.7em; text-transform: uppercase;">Harmless</div>
                                    </div>
                                    <div style="background: rgba(138, 180, 248, 0.15); border: 1px solid rgba(138, 180, 248, 0.4); padding: 10px; border-radius: 8px; text-align: center;">
                                        <div style="color: #8ab4f8; font-size: 1.5em; font-weight: bold;">${stats.undetected}</div>
                                        <div style="color: #a8c8ff; font-size: 0.7em; text-transform: uppercase;">Undetected</div>
                                    </div>
                                </div>
                                <div style="font-size: 0.8em; color: #666; text-align: center;">${stats.total} security engines scanned</div>
                            `;
                        } catch (e) {}
                    }
                    
                    if (prescanResult === 'SKIPPED') {
                        // No VT scan was done
                        statusMessage.innerHTML = `
                            <div style="font-size: 1.4em; margin-bottom: 15px;">🛡️ DOCUMENT SECURED AND DOWNLOADED</div>
                            <div style="background: rgba(0, 255, 0, 0.15); border: 2px solid rgba(0, 255, 0, 0.4); padding: 12px 15px; border-radius: 10px;">
                                <div style="color: #00ff00; font-size: 1.1em; font-weight: bold;">✅ Sanitization Complete</div>
                                <div style="color: #88ff88; font-size: 0.9em; margin-top: 5px;">Document cleaned and rebuilt from pixels</div>
                            </div>
                        `;
                    } else if (threatWarning || isThreatNeutralized) {
                        status.className = 'status warning';
                        statusMessage.innerHTML = `
                            <div style="font-size: 1.4em; margin-bottom: 15px;">🛡️ SANITIZATION SUCCESSFUL</div>
                            <div style="background: rgba(255, 68, 68, 0.2); border: 2px solid rgba(255, 68, 68, 0.6); padding: 12px 15px; border-radius: 10px; margin-bottom: 15px;">
                                <div style="color: #ff4444; font-size: 1.1em; font-weight: bold;">⚠️ THREAT NEUTRALIZED</div>
                                <div style="color: #ffaaaa; font-size: 0.9em; margin-top: 5px;">${prescanMessage}</div>
                            </div>
                            ${statsHtml}
                        `;
                    } else {
                        statusMessage.innerHTML = `
                            <div style="font-size: 1.4em; margin-bottom: 15px;">🛡️ DOCUMENT SECURED AND DOWNLOADED</div>
                            <div style="background: rgba(0, 255, 0, 0.15); border: 2px solid rgba(0, 255, 0, 0.4); padding: 12px 15px; border-radius: 10px; margin-bottom: 15px;">
                                <div style="color: #00ff00; font-size: 1.1em; font-weight: bold;">✅ SAFE - No threats detected</div>
                                <div style="color: #88ff88; font-size: 0.9em; margin-top: 5px;">${prescanMessage || 'File verified clean'}</div>
                            </div>
                            ${statsHtml}
                        `;
                    }
                } else {
                    let errorMessage = 'Sanitization failed';
                    try {
                        const errorData = await response.json();
                        errorMessage = errorData.error || errorMessage;
                    } catch (e) {
                        errorMessage = `Server Error (${response.status})`;
                    }
                    status.className = 'status error';
                    statusMessage.textContent = 'ERROR: ' + errorMessage;
                    stepsContainer.style.display = 'none';
                }
            } catch (err) {
                status.className = 'status error';
                statusMessage.textContent = 'SYSTEM FAILURE: ' + err.message;
            } finally {
                btn.disabled = false;
            }
        };

        // URL Check Logic
        async function checkUrl() {
            const url = document.getElementById('urlInput').value;
            const btn = document.getElementById('checkUrlBtn');
            const results = document.getElementById('urlResults');
            const verdict = document.getElementById('urlVerdict');
            const icon = document.getElementById('urlResultIcon');
            const stats = document.getElementById('urlStats');
            const engines = document.getElementById('urlEngines');
            const whoisDetails = document.getElementById('whoisInfo');
            const whoisSection = document.getElementById('whoisSection');
            
            if (!url) return;
            
            btn.disabled = true;
            results.classList.add('show');
            verdict.textContent = 'SCANNING...';
            verdict.className = 'result-verdict verdict-pending';
            icon.textContent = '⏳';
            stats.innerHTML = '';
            engines.innerHTML = '';
            whoisSection.style.display = 'none';
            
            try {
                const response = await fetch('/api/check-url', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    if (data.status === 'pending') {
                        verdict.textContent = 'SCAN QUEUED (Refresh in 30s)';
                        icon.textContent = '⏳';
                        return;
                    }
                    
                    const isMalicious = data.malicious > 0;
                    const isSuspicious = data.suspicious > 2;
                    
                    // Set verdict based on severity
                    if (isMalicious) {
                        verdict.textContent = 'THREAT DETECTED';
                        verdict.className = 'result-verdict verdict-malicious';
                        icon.textContent = '☣️';
                    } else if (isSuspicious) {
                        verdict.textContent = 'SUSPICIOUS';
                        verdict.className = 'result-verdict verdict-suspicious';
                        icon.textContent = '⚠️';
                    } else {
                        verdict.textContent = 'CLEAN / SAFE';
                        verdict.className = 'result-verdict verdict-clean';
                        icon.textContent = '🛡️';
                    }
                    
                    stats.innerHTML = `
                        <div class="stat-box stat-malicious"><div class="stat-value">${data.malicious}</div><div class="stat-label">Malicious</div></div>
                        <div class="stat-box stat-suspicious"><div class="stat-value">${data.suspicious}</div><div class="stat-label">Suspicious</div></div>
                        <div class="stat-box stat-safe"><div class="stat-value">${data.harmless}</div><div class="stat-label">Harmless</div></div>
                        <div class="stat-box stat-neutral"><div class="stat-value">${data.undetected}</div><div class="stat-label">Undetected</div></div>
                    `;
                    
                    // Display WHOIS if available
                    if (data.whois) {
                        whoisSection.style.display = 'block';
                        const w = data.whois;
                        whoisDetails.innerHTML = `
                            <div class="whois-item"><div class="whois-label">Domain</div><div class="whois-value">${w.domain}</div></div>
                            <div class="whois-item"><div class="whois-label">Age</div><div class="whois-value">${w.domain_age}</div></div>
                            <div class="whois-item"><div class="whois-label">Created</div><div class="whois-value">${w.creation_date}</div></div>
                            <div class="whois-item"><div class="whois-label">Registrar</div><div class="whois-value">${w.registrar}</div></div>
                            <div class="whois-item"><div class="whois-label">Registrant</div><div class="whois-value">${w.registrant.organization || 'Private'}</div></div>
                            <div class="whois-item"><div class="whois-label">Country</div><div class="whois-value">${w.registrant.country || 'N/A'}</div></div>
                        `;
                    }
                } else {
                    verdict.textContent = 'SCAN FAILED: ' + data.error;
                    verdict.className = 'result-verdict verdict-malicious';
                    icon.textContent = '❌';
                }
            } catch (err) {
                verdict.textContent = 'CONNECTION ERROR';
                icon.textContent = '📡';
            } finally {
                btn.disabled = false;
            }
        }

        // Email Check Logic
        async function checkEmail() {
            const email = document.getElementById('emailInput').value;
            const btn = document.getElementById('checkEmailBtn');
            const results = document.getElementById('emailResults');
            const verdict = document.getElementById('emailVerdict');
            const icon = document.getElementById('emailResultIcon');
            const checks = document.getElementById('emailChecks');
            const fill = document.getElementById('trustFill');
            const val = document.getElementById('trustValue');
            
            if (!email) return;
            
            btn.disabled = true;
            results.classList.add('show');
            verdict.textContent = 'VALIDATING...';
            icon.textContent = '⏳';
            checks.innerHTML = '';
            
            try {
                const response = await fetch('/api/check-email', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    fill.style.width = data.trust_score + '%';
                    val.textContent = data.trust_score;
                    
                    const isHigh = data.trust_score >= 70;
                    const isMedium = data.trust_score >= 40 && data.trust_score < 70;
                    
                    if (isHigh) {
                        verdict.textContent = 'TRUSTED ADDRESS';
                        verdict.className = 'result-verdict verdict-clean';
                        icon.textContent = '✅';
                    } else if (isMedium) {
                        verdict.textContent = 'NEEDS VERIFICATION';
                        verdict.className = 'result-verdict verdict-suspicious';
                        icon.textContent = '⚠️';
                    } else {
                        verdict.textContent = 'SUSPICIOUS ADDRESS';
                        verdict.className = 'result-verdict verdict-malicious';
                        icon.textContent = '🚨';
                    }
                    
                    checks.innerHTML = `
                        <div class="check-item"><span>Format Valid</span><span class="${data.format_valid ? 'check-pass' : 'check-fail'}">${data.format_valid ? 'PASS' : 'FAIL'}</span></div>
                        <div class="check-item"><span>Domain Exists</span><span class="${data.domain_exists ? 'check-pass' : 'check-fail'}">${data.domain_exists ? 'PASS' : 'FAIL'}</span></div>
                        <div class="check-item"><span>MX Records</span><span class="${data.has_mx_records ? 'check-pass' : 'check-fail'}">${data.has_mx_records ? 'PASS' : 'FAIL'}</span></div>
                        <div class="check-item"><span>Safe (Non-Disposable)</span><span class="${!data.is_disposable ? 'check-pass' : 'check-fail'}">${!data.is_disposable ? 'PASS' : 'FAIL'}</span></div>
                    `;
                    
                    data.warnings.forEach(w => {
                        checks.innerHTML += `<div class="warning-badge">⚠️ ${w}</div>`;
                    });
                }
            } finally {
                btn.disabled = false;
            }
        }

        async function analyzeHeaders() {
            const headers = document.getElementById('headersInput').value;
            const btn = document.getElementById('analyzeHeadersBtn');
            const results = document.getElementById('headersResults');
            const verdict = document.getElementById('headersVerdict');
            const icon = document.getElementById('headersResultIcon');
            const authItems = document.getElementById('authItems');
            const alerts = document.getElementById('spoofingAlerts');
            const routing = document.getElementById('routingBody');
            
            if (!headers) return;
            
            btn.disabled = true;
            results.classList.add('show');
            verdict.textContent = 'ANALYZING...';
            icon.textContent = '⏳';
            authItems.innerHTML = '';
            alerts.innerHTML = '';
            routing.innerHTML = '';
            
            try {
                const response = await fetch('/api/analyze-headers', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ headers })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    const isHigh = data.overall_trust === 'high';
                    verdict.textContent = isHigh ? 'AUTHENTICATED' : 'TRUST ISSUES';
                    verdict.className = 'result-verdict ' + (isHigh ? 'verdict-clean' : 'verdict-malicious');
                    icon.textContent = isHigh ? '🛡️' : '⚠️';
                    
                    const createAuth = (label, check) => `
                        <div class="auth-item">
                            <div>${label} <span class="auth-status auth-${check.status}">${check.status}</span></div>
                            <div class="auth-details">${check.details || 'No records found'}</div>
                        </div>
                    `;
                    
                    authItems.innerHTML = createAuth('SPF', data.spf) + createAuth('DKIM', data.dkim) + createAuth('DMARC', data.dmarc);
                    
                    data.spoofing_indicators.forEach(s => {
                        alerts.innerHTML += `<div class="error-badge">🚨 SPOOFING DETECTED: ${s}</div>`;
                    });
                    
                    data.routing_path.forEach(hop => {
                        routing.innerHTML += `<tr><td>${hop.hop}</td><td>${hop.from}</td><td>${hop.by}</td></tr>`;
                    });
                }
            } finally {
                btn.disabled = false;
            }
        }
    </script>
</body>
</html>
'''

@app.route('/api/progress/<job_id>')
def api_progress(job_id):
    """Server-Sent Events endpoint for progress updates"""
    return sse_progress(job_id)

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
            # Use job_id from frontend if provided, otherwise generate new one
            job_id = request.form.get('job_id') or str(uuid.uuid4())
            
            input_path = os.path.join(UPLOAD_FOLDER, f"{job_id}_{filename}")
            output_path = os.path.join(OUTPUT_FOLDER, f"{job_id}_sanitized.pdf")
            
            file.save(input_path)
            
            # Check if VirusTotal scan was requested
            vt_scan_requested = request.form.get('vt_scan') == 'on'
            
            threat_detected = False
            threat_info = None
            scan_message = None
            scan_stats = None
            
            if vt_scan_requested:
                # Pre-scan with VirusTotal (informational only, don't reject)
                emit_progress(job_id, 'step1', 'Pre-scanning with VirusTotal...')
                is_clean, scan_message, scan_stats = scan_with_virustotal(input_path, job_id)
                
                threat_detected = not is_clean
                if threat_detected:
                    pass  # threat detected but processing continues
                threat_info = scan_message if threat_detected else None
            else:
                pass  # VT scan skipped
            
            if sanitize_in_container(input_path, output_path, job_id):
                time.sleep(2)
                
                if os.path.exists(output_path):
                    # Create custom response with threat warning header if applicable
                    response = send_file(
                        output_path,
                        as_attachment=True,
                        download_name=f"sanitized_{filename.rsplit('.', 1)[0]}.pdf"
                    )
                    
                    # Add pre-scan result headers (only if VT scan was done)
                    import json
                    if vt_scan_requested:
                        if threat_detected:
                            response.headers['X-Threat-Warning'] = 'Original file contained malware - now sanitized'
                            response.headers['X-Threat-Details'] = threat_info
                            response.headers['X-Prescan-Result'] = f'THREAT: {scan_message}'
                        else:
                            response.headers['X-Prescan-Result'] = f'CLEAN: {scan_message}'
                        
                        # Add detailed stats if available
                        if scan_stats:
                            response.headers['X-Prescan-Stats'] = json.dumps(scan_stats)
                    else:
                        response.headers['X-Prescan-Result'] = 'SKIPPED'
                    
                    @response.call_on_close
                    def cleanup():
                        if os.path.exists(input_path):
                            os.remove(input_path)
                        
                        if os.path.exists(output_path):
                            os.remove(output_path)
                    
                    return response
            
            if os.path.exists(input_path):
                os.remove(input_path)
            
            return jsonify({'error': 'Sanitization failed'}), 500
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/check-url', methods=['POST'])
def api_check_url():
    """API endpoint to check URL with VirusTotal and get WHOIS info"""
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'success': False, 'error': 'URL is required'}), 400
        
        url = data['url'].strip()
        
        # Basic URL validation
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Get VirusTotal scan results
        result = check_url_with_virustotal(url)
        
        # Get WHOIS information
        whois_data = get_whois_info(url)
        if whois_data:
            result['whois'] = whois_data
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/check-email', methods=['POST'])
def api_check_email():
    """API endpoint to validate email address"""
    try:
        data = request.get_json()
        if not data or 'email' not in data:
            return jsonify({'success': False, 'error': 'Email is required'}), 400
        
        email = data['email'].strip().lower()
        result = validate_email_address(email)
        result['success'] = True
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/analyze-headers', methods=['POST'])
def api_analyze_headers():
    """API endpoint to analyze email headers"""
    try:
        data = request.get_json()
        if not data or 'headers' not in data:
            return jsonify({'success': False, 'error': 'Headers are required'}), 400
        
        headers_text = data['headers']
        if not headers_text or len(headers_text.strip()) < 10:
            return jsonify({'success': False, 'error': 'Invalid or empty headers'}), 400
        
        result = analyze_email_headers(headers_text)
        result['success'] = True
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/check-ip', methods=['POST'])
def api_check_ip():
    """API endpoint to check IP reputation"""
    try:
        data = request.get_json()
        if not data or 'ip' not in data:
            return jsonify({'success': False, 'error': 'IP address is required'}), 400
        
        ip = data['ip'].strip()
        if not ip:
            return jsonify({'success': False, 'error': 'Empty IP address'}), 400
        
        result = check_ip_with_virustotal(ip)
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    # Cleanup orphaned files on startup
    cleanup_orphaned_files()
    
    # Start Flask server
    app.run(host='0.0.0.0', port=10400, debug=False)
