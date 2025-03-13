import os
import json
import time
import google.generativeai as genai
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from google.api_core import exceptions
from tqdm import tqdm  # Import tqdm for progress bar

# Configure the GenAI API key
genai.configure(api_key="AIzaSyCcEnZthnlqNuy81NDJkBPAciAR-UZW2Us")  # Replace with your actual API key

# Rate limiting delay (adjust as needed)
DELAY_SECONDS = 2  # Wait 2 seconds between API calls

# Retry limit
RETRY_LIMIT = 3


# --- STEP 1: Generate Chapters ---
def generate_chapters(book_title):
    model = genai.GenerativeModel('gemini-2.0-flash')

    prompt = f"""Generate chapters for the book titled "{book_title}".
Your output must be valid JSON following this format:

{{
  "title": "{book_title}",
  "chapters": [
    {{
      "chapterNumber": 1,
      "chapterTitle": "Introduction to OCD"
    }},
    {{
      "chapterNumber": 2,
      "chapterTitle": "Managing OCD in Daily Life"
    }}
    // Additional chapters...
  ]
}}

Generate at least 10 chapters and at most 20 chapters.
"""

    for attempt in range(RETRY_LIMIT):
        try:
            response = model.generate_content(
                prompt,
                generation_config={
                    "temperature": 1,
                    "top_p": 0.95,
                    "top_k": 40,
                    "max_output_tokens": 8192,
                }
            )

            response_text = response.text

            # Clean JSON wrapping if present
            if response_text.startswith('```json'):
                response_text = response_text[7:-3].strip()
            elif response_text.startswith('```'):
                response_text = response_text[3:-3].strip()

            time.sleep(DELAY_SECONDS)  # Rate limiting
            return json.loads(response_text)
        except exceptions.TooManyRequests as e:
            print(f"Rate limit exceeded (attempt {attempt + 1}/{RETRY_LIMIT}).  Waiting and retrying...")
            time.sleep(DELAY_SECONDS * (attempt + 1))  # Exponential backoff
        except Exception as e:
            print(f"An error occurred: {e}")
            return None  # Or handle the error as appropriate

    print("Failed to generate chapters after multiple retries.")
    return None

# --- STEP 2: Generate Sections for Each Chapter ---
def generate_sections(chapter_title, book_title):
    model = genai.GenerativeModel('gemini-2.0-flash')

    prompt = f"""Generate sections for the chapter titled "{chapter_title}" in the book "{book_title}".
Your output must be valid JSON following this format:

{{
  "sections": [
    {{
      "sectionTitle": "What is OCD?"
    }},
    {{
      "sectionTitle": "OCD as an Anxiety Disorder"
    }}
    // Additional sections...
  ]
}}

Generate between 3 to 7 sections.
"""

    for attempt in range(RETRY_LIMIT):
        try:
            response = model.generate_content(
                prompt,
                generation_config={
                    "temperature": 1,
                    "top_p": 0.95,
                    "top_k": 40,
                    "max_output_tokens": 4096,
                }
            )

            response_text = response.text

            if response_text.startswith('```json'):
                response_text = response_text[7:-3].strip()
            elif response_text.startswith('```'):
                response_text = response_text[3:-3].strip()

            time.sleep(DELAY_SECONDS)  # Rate limiting
            return json.loads(response_text)
        except exceptions.TooManyRequests as e:
            print(f"Rate limit exceeded (attempt {attempt + 1}/{RETRY_LIMIT}).  Waiting and retrying...")
            time.sleep(DELAY_SECONDS * (attempt + 1))  # Exponential backoff
        except Exception as e:
            print(f"An error occurred: {e}")
            return None  # Or handle the error as appropriate

    print("Failed to generate sections after multiple retries.")
    return None


# --- STEP 3: Generate Content for Each Section ---
def generate_section_content(section_title, chapter_title, book_title):
    model = genai.GenerativeModel('gemini-2.0-flash')
    prompt = f"""Generate detailed content for the section titled "{section_title}" in the chapter titled "{chapter_title}" of the book "{book_title}".
Please output the content using the following standardized format:

- Titles: Begin with "# Title: " followed by the title.
- Heading 1: Begin with "## Heading 1: " for main headings.
- Heading 2: Begin with "### Heading 2: " for subheadings.

- Tables:
    1. Start the table with a line: "# Table: <table title>".
    2. On the next line, output the header row in the format:
         | Column 1 | Column 2 | Column 3 |
       Ensure you start and end with a vertical bar "|" and separate columns with " | ".
    3. On the following line, output a delimiter row to indicate the header separation, for example:
         | --- | --- | --- |
       (The number of dashes should match the number of columns.)
    4. Then, for each subsequent row, output the data row in the same format:
         | data1 | data2 | data3 |
    5. End the table with a blank line.

- New Lines: Use the token "\n" to represent new lines.
- Paragraphs: Begin paragraphs with "> Paragraph: " and use "\t" for an indented paragraph.
- Lists: Use "- " for bullet lists.
- Numbering: Use "1. " for numbered lists.

Ensure that the output strictly follows this format so it can be easily parsed later.
"""
    for attempt in range(RETRY_LIMIT):
        try:
            response = model.generate_content(
                prompt,
                generation_config={
                    "temperature": 1,
                    "top_p": 0.95,
                    "top_k": 40,
                    "max_output_tokens": 4096,
                }
            )
            time.sleep(DELAY_SECONDS)
            return response.text
        except exceptions.TooManyRequests as e:
            print(f"Rate limit exceeded (attempt {attempt + 1}/{RETRY_LIMIT}).  Waiting and retrying...")
            time.sleep(DELAY_SECONDS * (attempt + 1))
        except Exception as e:
            print(f"An error occurred: {e}")
            return None
    print("Failed to generate section content after multiple retries.")
    return None

# --- STEP 4: Generate PDF from Final JSON ---
def generate_pdf(final_book_data, output_pdf="final_workbook.pdf"):
    doc = SimpleDocTemplate(output_pdf, pagesize=letter)
    styles = getSampleStyleSheet()
    Story = []

    # Book title
    Story.append(Paragraph(final_book_data["title"], styles["Title"]))
    Story.append(Spacer(1, 12))

    # Process each chapter
    for chapter in final_book_data["chapters"]:
        chapter_header = f"Chapter {chapter['chapterNumber']}: {chapter['chapterTitle']}"
        Story.append(Paragraph(chapter_header, styles["Heading1"]))
        Story.append(Spacer(1, 12))

        # Process each section within the chapter
        for section in chapter.get("sections", []):
            section_header = section["sectionTitle"]
            Story.append(Paragraph(section_header, styles["Heading2"]))
            Story.append(Spacer(1, 6))
            Story.append(Paragraph(section.get("content", ""), styles["BodyText"]))
            Story.append(Spacer(1, 12))

    doc.build(Story)

# --- MAIN WORKFLOW ---
def main():
    book_title = input("Enter the book title: ")

    # Step 1: Generate chapters
    chapters_data = generate_chapters(book_title)
    if chapters_data is None:
        print("Failed to generate chapters. Exiting.")
        return

    with open("chapters.json", "w") as f:
        json.dump(chapters_data, f, indent=4)

    # Step 2: Generate sections for each chapter
    for chapter in chapters_data["chapters"]:
        sections_data = generate_sections(chapter["chapterTitle"], book_title)
        if sections_data is None:
            print(f"Failed to generate sections for chapter {chapter['chapterNumber']}. Skipping.")
            continue
        chapter["sections"] = sections_data["sections"]
        with open(f"sections_chapter_{chapter['chapterNumber']}.json", "w") as f:
            json.dump(sections_data, f, indent=4)

    # Step 3: Generate content for each section
    total_sections = sum(len(chapter["sections"]) for chapter in chapters_data["chapters"])
    with tqdm(total=total_sections, desc="Generating Section Content") as pbar: # Initialize tqdm
        for chapter in chapters_data["chapters"]:
            for section in chapter["sections"]:
                content = generate_section_content(
                    section["sectionTitle"],
                    chapter["chapterTitle"],
                    book_title
                )
                if content is None:
                    print(f"Failed to generate content for section '{section['sectionTitle']}' in chapter '{chapter['chapterTitle']}'. Skipping.")
                    section["content"] = "Content generation failed." # Add a placeholder
                else:
                    section["content"] = content
                pbar.update(1) # Increment progress bar

    # Save final JSON
    with open("final_workbook.json", "w") as f:
        json.dump(chapters_data, f, indent=4)

    # Step 4: Generate PDF
    generate_pdf(chapters_data)
    print("PDF generated as final_workbook.pdf")

if __name__ == "__main__":
    main()