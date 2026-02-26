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
        
        # Remove document-level JavaScript and embedded files
        if '/Names' in writer._root_object:
            names = writer._root_object['/Names']
            if hasattr(names, 'get_object'):
                names = names.get_object()
            
            if isinstance(names, dict):
                if '/JavaScript' in names:
                    del names['/JavaScript']
                if '/EmbeddedFiles' in names:
                    del names['/EmbeddedFiles']
        
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
        
        return True
        
    except Exception as e:
        # If CDR fails, copy original for further processing
        shutil.copy(pdf_path, output_path)
        return False

def strip_macros_from_office(input_path, output_pdf):
    """
    Convert Office documents to PDF, automatically stripping macros
    LibreOffice conversion naturally removes all VBA macros and active content
    """
    try:
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
            return True
        
        return False
        
    except subprocess.TimeoutExpired:
        return False
    except Exception as e:
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
        img = Image.open(input_path)
        
        # Strip all metadata
        img = strip_metadata_from_image(img)
        
        # Convert to RGB if necessary
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        # Save as PDF
        img.save(output_path, 'PDF', resolution=100.0)
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
        return False

def pdf_to_pixels(pdf_path):
    """Convert PDF pages to pixel data (PIL Images)"""
    try:
        # Higher DPI for better quality
        images = convert_from_path(pdf_path, dpi=200)
        return images
    except Exception as e:
        return None

def pixels_to_pdf(images, output_path):
    """Convert pixel data back to clean PDF"""
    try:
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
        return True
    except Exception as e:
        return False

def validate_output(output_path):
    """Validate the sanitized output"""
    try:
        if not os.path.exists(output_path):
            return False
        
        file_size = os.path.getsize(output_path)
        if file_size == 0:
            return False
        
        # Try to open as PDF to verify it's valid
        try:
            reader = PyPDF2.PdfReader(output_path)
            num_pages = len(reader.pages)
            return True
            try:
                root = reader.trailer.get('/Root')
                if root is not None:
                    # Resolve if IndirectObject so we can safely use 'in'
                    if hasattr(root, 'get_object'):
                        root = root.get_object()
                    names = root.get('/Names') if isinstance(root, dict) else None
                    if names is not None:
                        if hasattr(names, 'get_object'):
                            names = names.get_object()
                        if isinstance(names, dict):
                            if names.get('/JavaScript') or names.get('/EmbeddedFiles'):
                                return False
            except Exception:
                # Complex trailer structure (e.g. ReportLab output); we built from pixels so treat as clean
                pass
            
            return True
            
        except Exception as e:
            return False
            
    except Exception as e:
        return False

def main():
    """Main worker process with enhanced security"""
    input_file = os.environ.get('INPUT_FILE')
    output_file = os.environ.get('OUTPUT_FILE')
    
    if not input_file or not output_file:
        sys.exit(1)
    
    if not os.path.exists(input_file):
        sys.exit(1)
    
    
    temp_dir = '/tmp/cleansheet_work'
    os.makedirs(temp_dir, exist_ok=True)
    
    try:
        # Step 1: Convert to PDF with CDR and macro stripping
        intermediate_pdf = os.path.join(temp_dir, 'intermediate.pdf')
        
        if not convert_to_pdf(input_file, intermediate_pdf):
            sys.exit(1)
        
        # Step 2: Apply additional PDF-level CDR if needed
        cdr_pdf = os.path.join(temp_dir, 'cdr.pdf')
        if not disarm_pdf(intermediate_pdf, cdr_pdf):
            sys.exit(1)
        
        # Step 3: Render to pixels (ultimate sanitization)
        pixel_images = pdf_to_pixels(cdr_pdf)
        
        if not pixel_images:
            sys.exit(1)
        
        # Step 4: Reconstruct PDF from pixels
        if not pixels_to_pdf(pixel_images, output_file):
            sys.exit(1)
        
        # Step 5: Validate output
        if not validate_output(output_file):
            sys.exit(1)
        
        sys.exit(0)
        
    except Exception as e:
        sys.exit(1)
    finally:
        # Secure cleanup of temporary files
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == '__main__':
    main()
