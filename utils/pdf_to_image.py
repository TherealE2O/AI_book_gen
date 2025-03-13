#from pdf2image import convert_from_path
from PIL import Image
import os

# ------------------------------
# Step 1: Convert PDF pages to PNG
# ------------------------------

# Replace 'input.pdf' with your PDF file's path
#pdf_path = 'OCD.pdf'
# If needed, specify the poppler path: poppler_path=r'/path/to/poppler/bin'
#pages = convert_from_path(pdf_path)

#png_files = []
#for i, page in enumerate(pages):
#    png_filename = f'output_page_{i+1}.png'
#    page.save(png_filename, 'PNG')
#    png_files.append(png_filename)
#    print(f"Saved {png_filename}")

# ------------------------------
# Step 2: Compile PNG images back to PDF
# ------------------------------

# Open each PNG file, convert to RGB (required for PDF conversion)
#images = [Image.open(png).convert('RGB') for png in png_files]

#if images:
#    output_pdf_path = 'recompiled_output.pdf'
#    # Save the first image and append the rest
#    images[0].save(output_pdf_path, save_all=True, append_images=images[1:])
#    print(f"Recompiled PDF saved as {output_pdf_path}")

# Optionally, clean up the PNG files after creating the PDF
# for png in png_files:
#     os.remove(png)