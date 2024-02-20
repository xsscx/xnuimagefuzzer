#
#  @file read-magic-numbers.py
#  @brief Code Analysis for XNU Image Fuzzer
#  @author @h02332 | David Hoyt | @xsscx
#  @date 24 MAY 2024
#  @version 1.2.5
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program. If not, see <http://www.gnu.org/licenses/>.
#
#  @section CHANGES
#  - 24/05/2024 - Add to Public Repo
#
#  @section TODO
#  - Better Images
#


import os
import logging
import base64
from PIL import Image, UnidentifiedImageError
import io
from packaging import version
import magic
import urllib.parse

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(levelname)s: %(message)s')

def get_file_type(magic_bytes, file_content=None):
    """
    Match the magic bytes or content of a file to known file types or specific patterns.
    
    :param magic_bytes: The magic bytes read from a file, as a bytes object.
    :param file_content: Text content read from a file, for formats that require content inspection.
    :return: A string describing the file type, if recognized.
    """
    # Dictionary of file signatures with corresponding file types
    file_signatures = {
        # Common image formats
        b'\x89PNG\r\n\x1a\n': 'PNG Image',
        b'\xff\xd8\xff\xe0': 'JPEG Image (JFIF format)',
        b'\xff\xd8\xff\xe1': 'JPEG Image (EXIF format)',
        b'\xff\xd8\xff\xe2': 'JPEG Image with ICC Profile',
        b'GIF87a': 'GIF Image (87a format)',
        b'GIF89a': 'GIF Image (89a format)',
        b'BM': 'BMP Image',
        b'II*\x00': 'TIFF Image (little endian)',
        b'MM\x00*': 'TIFF Image (big endian)',
        b'\x00\x00\x01\x00': 'Windows Icon',
        b'\x00\x00\x02\x00': 'Windows Cursor',
        b'8BPS': 'Adobe Photoshop Image',
        b'acsp': 'Standard ICC Profile',
        # APPL specific formats (hypothetical examples)
        b'\x00\x00\x01\xf8': 'APPL Scene Format',
        b'\x00\x00\x02\xec': 'APPL Scene Format',
        b'\x00\x00\x00\x14': 'APPL QT Format',
        # Hoyt exploit and fuzzed formats
        b'\x00\x00\x1d\x24': 'HOYT ICC Buffer Overflow Profile',
        b'\x38\x63\x59\x1b': 'HOYT Exploit Format',
        b'\x52\x00\x01\x46': 'HOYT Exploit Format',
        b'\x1a\x0a\x00\x00': 'HOYT Exploit Format',
        b'\xff\xe0\x46\xae': 'HOYT Exploit Format',
        b'\x52\x5e\x8d\x5c': 'HOYT Exploit Format',
        b'\x01\x49\x46\x46': 'HOYT xIFF Fuzzed Format',
        b'\x52\x49\x46\xb9': 'HOYT xIFF Fuzzed Format',
        b'\x10\x74\xbc\x25': 'HOYT xIFF Fuzzed Format',
        b'\x52\x49\x46\x25': 'HOYT xIFF Fuzzed Format',
        b'\x52\xab\x2a\x46': 'HOYT xIFF Fuzzed Format',
        # Additional common image formats (duplicates and similar entries merged)
        b'\x52\x49\x46\x46': 'RIFF Container (Potential WebP/AVI/WAV)',
        # HEIF and HEIC, based on the 'ftyp' box
        b'\x00\x00\x00\x18\x66\x74\x79\x70\x68\x65\x69\x63': 'HEIC Image Format',
        b'\x00\x00\x00\x18\x66\x74\x79\x70\x6D\x69\x66\x31': 'HEIF Image Format',
        b'\x54\x52\x55\x45\x56\x49\x53\x49\x4F\x4E\x2D\x58\x46\x49\x4C\x45\x2E\x00': 'TGA Image Footer',
        b'FORM': 'IFF File',
        # Custom signatures for non-standard ICC-related formats
        b'\x23\xc9\xae\x19': 'Custom ICC-Related Format',
        b'\x49\xc9\xae\x19': 'Custom ICC-Related Format (duplicate entries removed)',
        b'\x41\xc9\xae\x19': 'Custom ICC-Related Format',
        b'\x4d\xc9\xae\x19': 'Custom ICC-Related Format',
        b'\x44\xc9\xae\x19': 'Custom ICC-Related Format',
        b'\x50\xc9\xae\x19': 'Custom ICC-Related Format',
        b'\x69\xc9\xae\x19': 'Custom ICC-Related Format',
        b'\xab\xc9\xae\x19': 'Custom ICC-Related Format',
        b'\xab\x4b\xae\x19': 'Custom ICC-Related Format',
        b'\x49\x49\xae\x19': 'Custom ICC-Related Format',
        # New formats
        b'\x25\x50\x44\x46': 'PDF Document',
        b'\x76\x2f\x31\x01': 'DDS Image',
        b'\x69\x63\x6e\x73': 'ICNS Icon',
        b'\x00\x00\x00\x00': 'TGA Image',
        b'\x52\x49\x46\x46': 'WEBP Image',
        b'\x47\x49\x46\x38': 'GIF-89a',
        b'\x49\x49\x2a\x00': 'TIFF-LE',
    }
    
    # Check binary signatures
    for signature, filetype in file_signatures.items():
        if magic_bytes.startswith(signature):
            return filetype
    
    # Check for specific text-based identifiers if applicable
    if file_content:
        # Add checks for specific text patterns here
        if '<document type="com.apple.InterfaceBuilder3.CocoaTouch.Storyboard.XIB"' in file_content:
            return 'Xcode Interface Builder Cocoa Touch Storyboard'
    
    return 'Unknown file type'

def read_file(file_path, num_bytes=16):
    """
    Read the specified number of bytes from the start of a file for binary signatures,
    and a portion of text for formats requiring content inspection.
    
    :param file_path: Path to the file.
    :param num_bytes: Number of bytes to read for identifying the file type.
    :return: Tuple of (magic_bytes, file_content) where file_content may be None.
    """
    try:
        with open(file_path, 'rb') as file:
            magic_bytes = file.read(num_bytes)
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            file_content = file.read(1024)  # Adjust size as needed for your checks
            
        return magic_bytes, file_content
    except Exception as e:
        logging.error(f'Error reading file {file_path}: {e}')
        return None, None

def is_image_file(file_path):
    """
    Check if a file is an image based on its MIME type.
    
    :param file_path: Path to the file.
    :return: True if the file is an image, False otherwise.
    """
    try:
        mime = magic.Magic(mime=True)
        file_type = mime.from_file(file_path)
        return file_type.startswith('image')
    except Exception as e:
        logging.error(f'Error checking MIME type for {file_path}: {e}')
        return False

def create_thumbnail(image_path):
    """
    Create a 76x76 thumbnail of an image and return a base64-encoded string.
    Skips over files that cannot be processed due to being truncated or otherwise unreadable.
    """
    if not is_image_file(image_path):
        logging.warning(f'Skipping non-image file: {image_path}')
        return None
    try:
        with Image.open(image_path) as img:
            img.load()
            img.thumbnail((76, 76), Image.LANCZOS)
            if img.mode == 'RGBA':
                img = img.convert('RGB')  # Convert to RGB mode to remove alpha channel
            buffer = io.BytesIO()
            img.save(buffer, format="JPEG")
            return base64.b64encode(buffer.getvalue()).decode('utf-8')
    except (UnidentifiedImageError, IOError) as e:
        logging.error(f'Error creating thumbnail for {image_path}: {e}')
    except Exception as e:
        logging.error(f'Unexpected error creating thumbnail for {image_path}: {e}')
    return None

def sanitize_filename_for_uri(filename):
    """
    Sanitize a filename to be used in a URI.
    
    :param filename: The filename to sanitize.
    :return: The sanitized filename.
    """
    return urllib.parse.quote(filename)

def generate_html_report(directory, identified_files, unknown_files):
    """
    Generate an HTML report of identified and unknown files.
    
    :param directory: Directory path where the report will be saved.
    :param identified_files: List of identified files with details.
    :param unknown_files: List of unknown files with details.
    """
    html_content = "<!DOCTYPE html>\n<html><head><title>File Report for {}</title></head><body>".format(directory)
    html_content += "<h1>Identified Image Files</h1><ul>"
    
    for filename, size, file_type, thumbnail, hex_magic in identified_files:
        sanitized_filename = sanitize_filename_for_uri(filename)
        alt_description = f"{filename} - {file_type}"
        if thumbnail:
            html_content += (f'<li>{filename} (Size: {size} bytes, Magic Bytes: {hex_magic}): {file_type} '
                             f'<a href="{sanitized_filename}" target="_blank">'
                             f'<img src="data:image/jpeg;base64,{thumbnail}" alt="{alt_description}" /></a></li>')
        else:
            html_content += f'<li>{filename} (Size: {size} bytes, Magic Bytes: {hex_magic}): {file_type}</li>'
            
    html_content += "</ul>"
    
    if unknown_files:
        html_content += "<h1>Unknown Files</h1><ul>"
        for filename, size, hex_magic in unknown_files:
            html_content += f'<li>{filename} (Size: {size} bytes, Magic Bytes: {hex_magic})</li>'
        html_content += "</ul>"
            
    html_content += "</body></html>"
    
    report_file_path = os.path.join(directory, "file_report.html")
    with open(report_file_path, "w") as report_file:
        report_file.write(html_content)
    logging.info(f'Report generated at {report_file_path}')
    
def list_file_types(directory, num_bytes=16):
    """
    List file types in a directory and generate thumbnails for identified image files.
    
    :param directory: Directory path to scan.
    :param num_bytes: Number of bytes to read for identifying the file type.
    """
    filenames = sorted(f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f)))
    identified_files = []
    unknown_files = []
    
    for filename in filenames:
        file_path = os.path.join(directory, filename)
        file_size = os.path.getsize(file_path)
        magic_bytes, file_content = read_file(file_path, num_bytes)
        
        if magic_bytes is None:
            logging.error(f'Skipping file {filename} due to read error.')
            continue
        
        file_type = get_file_type(magic_bytes, file_content)
        hex_magic = ' '.join(f'{byte:02x}' for byte in magic_bytes) if magic_bytes else 'N/A'
        
        if file_type != 'Unknown file type':
            thumbnail = None
            if 'Image' in file_type:
                thumbnail = create_thumbnail(file_path)
            identified_files.append((filename, file_size, file_type, thumbnail, hex_magic))
            logging.info(f'{filename} (Size: {file_size} bytes, Magic Bytes: {hex_magic}): {file_type}')
        else:
            unknown_files.append((filename, file_size, hex_magic))
            logging.info(f'{filename} (Size: {file_size} bytes, Magic Bytes: {hex_magic}): Unable to determine file type.')
            
    generate_html_report(directory, identified_files, unknown_files)
    
# Example usage
directory_path = '/mnt/Documents/'  # Update this to the directory you want to scan
list_file_types(directory_path)
