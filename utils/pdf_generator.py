from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, ListFlowable, ListItem, Table, TableStyle
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
import re
import json

def generate_pdf(final_book_data, output_pdf="final_workbook1.pdf"):
    doc = SimpleDocTemplate(output_pdf, pagesize=letter)
    styles = getSampleStyleSheet()

    # Custom style for bullet points
    styles.add(ParagraphStyle(
        name="BodyTextBullet",
        parent=styles["BodyText"],
        firstLineIndent=0,
        spaceBefore=6,
        leftIndent=20,
        bulletIndent=0
    ))

    Story = []

    # Process book title (if your JSON already has a title, this can be plain text)
    Story.append(Paragraph(final_book_data["title"], styles["Title"]))
    Story.append(Spacer(1, 24))

    # Process chapters
    for chapter in final_book_data["chapters"]:
        # Chapter header
        chapter_header = f"Chapter {chapter['chapterNumber']}: {chapter['chapterTitle']}"
        Story.append(Paragraph(chapter_header, styles["Heading1"]))
        Story.append(Spacer(1, 16))

        # Process sections
        for section in chapter.get("sections", []):
            # Section header
            Story.append(Paragraph(section["sectionTitle"], styles["Heading2"]))
            Story.append(Spacer(1, 8))

            # Process content with custom markdown parsing
            content_flowables = process_markdown_content(
                section.get("content", ""),
                styles
            )
            Story.extend(content_flowables)
            Story.append(Spacer(1, 12))

    doc.build(Story)

def process_markdown_content(content, styles):
    """
    Processes content that may have explicit markers like "Title:", "Heading 1:" or "> Paragraph:".
    These markers are stripped out so that the final rendered text does not include them.
    """
    flowables = []
    lines = content.split('\n')
    current_list = []
    in_table = False
    table_data = []
    header_separator = False
    previous_line_type = None  # To track block types

    for line in lines:
        line = line.rstrip()  # Remove trailing whitespace

        # Check for explicit markers and process them first:
        if line.startswith("Title:"):
            text = line[len("Title:"):].strip()
            flowables.append(Paragraph(text, styles["Title"]))
            continue
        elif line.startswith("Heading 1:"):
            text = line[len("Heading 1:"):].strip()
            flowables.append(Paragraph(text, styles["Heading1"]))
            continue
        elif line.startswith("Heading 2:"):
            text = line[len("Heading 2:"):].strip()
            flowables.append(Paragraph(text, styles["Heading2"]))
            continue
        elif line.startswith("Heading 3:"):
            text = line[len("Heading 3:"):].strip()
            flowables.append(Paragraph(text, styles["Heading3"]))
            continue
        elif line.startswith("> Paragraph:"):
            text = line[len("> Paragraph:"):].strip()
            flowables.append(Paragraph(text, styles["BodyText"]))
            continue

        # Check for table caption marker (e.g., "# Table: My Table Title")
        if line.startswith("# Table:"):
            if current_list:
                flowables.append(ListFlowable(current_list, bulletType='bullet'))
                current_list = []
            if in_table and table_data:
                flowables.append(create_table(table_data))
                in_table = False
                table_data = []
                header_separator = False

            table_caption = line[len("# Table:"):].strip()
            flowables.append(Paragraph(table_caption, styles.get("Heading4", styles["BodyText"])))
            flowables.append(Spacer(1, 4))
            previous_line_type = 'table_caption'
            continue

        # Next, handle markdown headings using '#' if present.
        heading_match = re.match(r'^(#+)\s+(.*)', line)
        if heading_match:
            heading_level = len(heading_match.group(1))
            heading_text = heading_match.group(2).strip()
            # Strip out explicit markers if present
            heading_text = re.sub(r'^(Title:|Heading\s*\d+:)\s*', '', heading_text)
            # Map heading levels: '#' → Heading1, '##' → Heading2, etc.
            if heading_level == 1:
                style = styles["Heading1"]
            elif heading_level == 2:
                style = styles["Heading2"]
            elif heading_level == 3:
                style = styles["Heading3"]
            else:
                style = styles.get("Heading4", styles["BodyText"])
            flowables.append(Paragraph(heading_text, style))
            flowables.append(Spacer(1, 4))
            previous_line_type = 'heading'
            continue

        # Handle table rows (detecting a vertical bar)
        if '|' in line:
            if not in_table:
                if current_list:
                    flowables.append(ListFlowable(current_list, bulletType='bullet'))
                    current_list = []
                in_table = True
                table_data = []
                header_separator = False

            # Process table row by splitting on '|'
            row = [cell.strip() for cell in line.split('|') if cell.strip()]
            # Check for a header separator (commonly a row with dashes)
            if re.match(r'^\s*-+\s*$', line.replace('|', '').strip()):
                header_separator = True
                continue
            table_data.append(row)
            previous_line_type = 'table_row'
            continue
        elif in_table:
            # Finalize and add table when non-table line is encountered
            if table_data:
                flowables.append(create_table(table_data))
            in_table = False
            table_data = []
            header_separator = False
            previous_line_type = 'table'

        # Handle bullet list items (lines starting with "*")
        if re.match(r'^\s*\*', line):
            if in_table:
                if table_data:
                    flowables.append(create_table(table_data))
                in_table = False
                table_data = []
                header_separator = False
            # Remove the bullet marker and trim
            bullet_text = re.sub(r'^\s*\*\s*', '', line).strip()
            bullet_text = format_markdown(bullet_text)
            current_list.append(
                ListItem(
                    Paragraph(bullet_text, styles["BodyTextBullet"]),
                    bulletColor='black'
                )
            )
            previous_line_type = 'list_item'
            continue
        else:
            if current_list:
                flowables.append(ListFlowable(current_list, bulletType='bullet'))
                current_list = []

            # Process any remaining non-empty lines as regular paragraphs
            if line.strip():
                formatted_text = format_markdown(line.strip())
                # If the line is short, you might choose to treat it as a heading
                if (previous_line_type not in ['list_item', 'table_row', 'heading', 'paragraph'] or not previous_line_type) and len(line.split()) <= 10:
                    flowables.append(Paragraph(formatted_text, styles.get("Heading3", styles["BodyText"])))
                    flowables.append(Spacer(1, 4))
                    previous_line_type = 'heading'
                else:
                    flowables.append(Paragraph(formatted_text, styles["BodyText"]))
                    flowables.append(Spacer(1, 4))
                    previous_line_type = 'paragraph'
            else:
                previous_line_type = 'space'

    # Flush any remaining list items or table data.
    if current_list:
        flowables.append(ListFlowable(current_list, bulletType='bullet'))
    if in_table and table_data:
        flowables.append(create_table(table_data))

    return flowables

def format_markdown(text):
    # Remove any residual markers if needed (this can be expanded)
    text = re.sub(r'^(Title:|Heading\s*\d+:|> Paragraph:)\s*', '', text)
    # Convert **bold** to <strong>
    text = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', text)
    # Convert *italic* to <em>
    text = re.sub(r'\*(.*?)\*', r'<em>\1</em>', text)
    return text

def create_table(data):
    if not data:
        return None

    table = Table(data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('WORDWRAP', (0, 0), (-1, -1), True)
    ]))
    return table

def load_json_data(filepath):
    with open(filepath, 'r') as f:
        data = json.load(f)
    return data

if __name__ == '__main__':
    # Example usage:
    json_file_path = "final_workbook.json"  # Replace with your actual file path
    try:
        book_data = load_json_data(json_file_path)
        generate_pdf(book_data, "output.pdf")
        print("PDF generated successfully!")
    except FileNotFoundError:
        print(f"Error: File not found: {json_file_path}")
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON format in {json_file_path}")
    except Exception as e:
        print(f"An error occurred: {e}")