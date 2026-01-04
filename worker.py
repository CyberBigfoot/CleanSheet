import os
import sys
import subprocess
import shutil
from pdf2image import convert_from_path
from PIL import Image
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import ImageReader
import PyPDF2
from datetime import datetime

def strip_metadata_from_image(img):
    """Remove all EXIF and metadata from images"""
    try:
        # Convert to RGB if necessary and create new image without metadata
        if img.mode in ('RGBA', 'LA', 'P'):
            background = Image.new('RGB', img.size, (255, 255, 255))
            if img.mode == 'P':
                img = img.convert('RGBA')
            if 'A' in img.mode:
                background.paste(img, mask=img.split()[-1])
            else:
                background.paste(img)
            img = background
        elif img.mode != 'RGB':
            img = img.convert('RGB')
        
        # Create new image without any metadata
        clean_img = Image.new(img.mode, img.size)
        clean_img.putdata(list(img.getdata()))
        
        return clean_img
    except Exception as e:
        print(f"Warning: Could not strip image metadata: {e}", file=sys.stderr)
        return img

def disarm_pdf(pdf_path, output_path):
    """
    Content Disarm & Reconstruction for PDF
    - Remove JavaScript
    - Remove embedded files
    - Remove forms and actions
    - Strip metadata
    """
    try:
        print("Applying Content Disarm & Reconstruction (CDR)...")
        
        reader = PyPDF2.PdfReader(pdf_path)
        writer = PyPDF2.PdfWriter()
        
        # Copy pages without preserving any interactive content
        for page_num in range(len(reader.pages)):
            page = reader.pages[page_num]
            
            # Remove annotations (links, forms, etc)
            if '/Annots' in page:
                del page['/Annots']
            
            # Remove actions
            if '/AA' in page:
                del page['/AA']
            if '/A' in page:
                del page['/A']
            
            writer.add_page(page)
        
        # Remove document-level JavaScript
        if '/Names' in writer._root_object:
            if '/JavaScript' in writer._root_object['/Names']:
                del writer._root_object['/Names']['/JavaScript']
        
        # Remove embedded files
        if '/Names' in writer._root_object:
            if '/EmbeddedFiles' in writer._root_object['/Names']:
                del writer._root_object['/Names']['/EmbeddedFiles']
        
        # Remove OpenAction (auto-execute on open)
        if '/OpenAction' in writer._root_object:
            del writer._root_object['/OpenAction']
        
        # Strip all metadata
        writer.add_metadata({
            '/Title': 'Sanitized Document',
            '/Author': 'CleanSheet',
            '/Subject': 'Document Sanitized',
            '/Creator': 'CleanSheet Sanitization System',
            '/Producer': 'CleanSheet',
            '/CreationDate': datetime.now().strftime('D:%Y%m%d%H%M%S'),
        })
        
        # Write cleaned PDF
        with open(output_path, 'wb') as output_file:
            writer.write(output_file)
        
        print(f"✓ CDR complete - Removed scripts, forms, embedded files, and metadata")
        return True
        
    except Exception as e:
        print(f"CDR error: {e}", file=sys.stderr)
        # If CDR fails, copy original for further processing
        shutil.copy(pdf_path, output_path)
        return False

def strip_macros_from_office(input_path, output_pdf):
    """
    Convert Office documents to PDF, automatically stripping macros
    LibreOffice conversion naturally removes all VBA macros and active content
    """
    try:
        print("Converting Office document (macros will be stripped)...")
        
        result = subprocess.run([
            'libreoffice',
            '--headless',
            '--convert-to', 'pdf',
            '--outdir', os.path.dirname(output_pdf),
            input_path
        ], check=True, timeout=60, capture_output=True, text=True)
        
        # Find the converted file
        converted_name = os.path.splitext(os.path.basename(input_path))[0] + '.pdf'
        converted_path = os.path.join(os.path.dirname(output_pdf), converted_name)
        
        if os.path.exists(converted_path):
            os.rename(converted_path, output_pdf)
            print("✓ Office document converted - All macros and scripts removed")
            return True
        
        return False
        
    except subprocess.TimeoutExpired:
        print("ERROR: Office conversion timeout", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Office conversion error: {e}", file=sys.stderr)
        return False

def convert_to_pdf(input_path, output_path):
    """Convert various document formats to PDF with threat removal"""
    ext = input_path.rsplit('.', 1)[1].lower()
    
    if ext == 'pdf':
        # Apply CDR to existing PDF
        temp_cdr = output_path + '.cdr.pdf'
        disarm_pdf(input_path, temp_cdr)
        
        # Use CDR'd version for further processing
        shutil.copy(temp_cdr, output_path)
        
        if os.path.exists(temp_cdr):
            os.remove(temp_cdr)
        
        return True
    
    if ext in ['jpg', 'jpeg', 'png']:
        print("Processing image file...")
        img = Image.open(input_path)
        
        # Strip all metadata
        img = strip_metadata_from_image(img)
        
        # Convert to RGB if necessary
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        # Save as PDF
        img.save(output_path, 'PDF', resolution=100.0)
        print("✓ Image converted - All metadata stripped")
        return True
    
    if ext in ['doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'rtf']:
        # Office documents - macros automatically stripped during conversion
        return strip_macros_from_office(input_path, output_path)
    
    # Generic conversion for other formats
    try:
        subprocess.run([
            'libreoffice',
            '--headless',
            '--convert-to', 'pdf',
            '--outdir', os.path.dirname(output_path),
            input_path
        ], check=True, timeout=60)
        
        converted_name = os.path.splitext(os.path.basename(input_path))[0] + '.pdf'
        converted_path = os.path.join(os.path.dirname(output_path), converted_name)
        
        if os.path.exists(converted_path):
            os.rename(converted_path, output_path)
            return True
        return False
    except Exception as e:
        print(f"Conversion error: {e}", file=sys.stderr)
        return False

def pdf_to_pixels(pdf_path):
    """Convert PDF pages to pixel data (PIL Images)"""
    try:
        print("Rendering PDF to pixel matrix...")
        # Higher DPI for better quality
        images = convert_from_path(pdf_path, dpi=200)
        print(f"✓ Rendered {len(images)} pages to pixel format")
        return images
    except Exception as e:
        print(f"PDF to pixels error: {e}", file=sys.stderr)
        return None

def pixels_to_pdf(images, output_path):
    """Convert pixel data back to clean PDF"""
    try:
        print("Reconstructing sanitized PDF from pixels...")
        c = canvas.Canvas(output_path, pagesize=letter)
        
        for i, img in enumerate(images):
            # Strip any remaining metadata
            img = strip_metadata_from_image(img)
            
            img_width, img_height = img.size
            aspect = img_height / float(img_width)
            
            page_width, page_height = letter
            display_width = page_width - 40
            display_height = display_width * aspect
            
            if display_height > page_height - 40:
                display_height = page_height - 40
                display_width = display_height / aspect
            
            x = (page_width - display_width) / 2
            y = (page_height - display_height) / 2
            
            c.drawImage(ImageReader(img), x, y, width=display_width, height=display_height)
            c.showPage()
        
        c.save()
        print(f"✓ Reconstructed clean PDF with {len(images)} pages")
        return True
    except Exception as e:
        print(f"Pixels to PDF error: {e}", file=sys.stderr)
        return False

def validate_output(output_path):
    """Validate the sanitized output"""
    try:
        if not os.path.exists(output_path):
            print("ERROR: Output file does not exist", file=sys.stderr)
            return False
        
        file_size = os.path.getsize(output_path)
        if file_size == 0:
            print("ERROR: Output file is empty", file=sys.stderr)
            return False
        
        # Try to open as PDF to verify it's valid
        try:
            reader = PyPDF2.PdfReader(output_path)
            num_pages = len(reader.pages)
            print(f"✓ Output validation passed: {num_pages} pages, {file_size} bytes")
            
            # Verify no JavaScript
            if '/Names' in reader.trailer.get('/Root', {}):
                if '/JavaScript' in reader.trailer['/Root']['/Names']:
                    print("WARNING: JavaScript detected in output!", file=sys.stderr)
                    return False
            
            # Verify no embedded files
            if '/Names' in reader.trailer.get('/Root', {}):
                if '/EmbeddedFiles' in reader.trailer['/Root']['/Names']:
                    print("WARNING: Embedded files detected in output!", file=sys.stderr)
                    return False
            
            return True
            
        except Exception as e:
            print(f"ERROR: Invalid PDF structure: {e}", file=sys.stderr)
            return False
            
    except Exception as e:
        print(f"Validation error: {e}", file=sys.stderr)
        return False

def main():
    """Main worker process with enhanced security"""
    input_file = os.environ.get('INPUT_FILE')
    output_file = os.environ.get('OUTPUT_FILE')
    
    if not input_file or not output_file:
        print("ERROR: INPUT_FILE and OUTPUT_FILE environment variables required", file=sys.stderr)
        sys.exit(1)
    
    if not os.path.exists(input_file):
        print(f"ERROR: Input file not found: {input_file}", file=sys.stderr)
        sys.exit(1)
    
    print(f"{'='*60}")
    print(f"SANITIZATION WORKER STARTED")
    print(f"{'='*60}")
    print(f"Input: {input_file}")
    print(f"Output: {output_file}")
    
    temp_dir = '/tmp/cleansheet_work'
    os.makedirs(temp_dir, exist_ok=True)
    
    try:
        # Step 1: Convert to PDF with CDR and macro stripping
        print(f"\n[STEP 1] Converting to PDF with threat removal...")
        intermediate_pdf = os.path.join(temp_dir, 'intermediate.pdf')
        
        if not convert_to_pdf(input_file, intermediate_pdf):
            print("ERROR: Failed to convert document to PDF", file=sys.stderr)
            sys.exit(1)
        
        # Step 2: Apply additional PDF-level CDR if needed
        print(f"\n[STEP 2] Applying additional PDF sanitization...")
        cdr_pdf = os.path.join(temp_dir, 'cdr.pdf')
        disarm_pdf(intermediate_pdf, cdr_pdf)
        
        # Step 3: Render to pixels (ultimate sanitization)
        print(f"\n[STEP 3] Rendering to pixel matrix...")
        pixel_images = pdf_to_pixels(cdr_pdf)
        
        if not pixel_images:
            print("ERROR: Failed to render PDF to pixels", file=sys.stderr)
            sys.exit(1)
        
        # Step 4: Reconstruct PDF from pixels
        print(f"\n[STEP 4] Reconstructing clean PDF from pixels...")
        if not pixels_to_pdf(pixel_images, output_file):
            print("ERROR: Failed to reconstruct PDF from pixels", file=sys.stderr)
            sys.exit(1)
        
        # Step 5: Validate output
        print(f"\n[STEP 5] Validating sanitized output...")
        if not validate_output(output_file):
            print("ERROR: Output validation failed", file=sys.stderr)
            sys.exit(1)
        
        print(f"\n{'='*60}")
        print(f"✓ SANITIZATION COMPLETE")
        print(f"{'='*60}")
        print(f"All threats removed:")
        print(f"  ✓ Macros and scripts stripped")
        print(f"  ✓ Embedded objects removed")
        print(f"  ✓ Metadata sanitized")
        print(f"  ✓ JavaScript eliminated")
        print(f"  ✓ Forms and actions disabled")
        print(f"  ✓ File reconstructed from pixels")
        print(f"{'='*60}\n")
        
        sys.exit(0)
        
    except Exception as e:
        print(f"ERROR: Unexpected error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        # Secure cleanup of temporary files
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == '__main__':
    main()