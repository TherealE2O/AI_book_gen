from flask import Flask, request, jsonify, send_file, Response, stream_with_context, render_template, redirect, url_for
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from utils.models import db, User, Credit
from utils.ai_handler import generate_chapters, generate_sections, generate_section_content
from utils.pdf_generator import generate_pdf
import json
import os
import time
import threading
from pypaystack import Transaction 
import uuid 


app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['PAYSTACK_SECRET_KEY'] = 'sk_test_8796b1633b5cce9209c63d5159cb2a0321d10d0d'  # Replace with your actual secret key

transaction_handler = Transaction(authorization_key=app.config['PAYSTACK_SECRET_KEY'])

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Global variable to store progress
progress = {
    "status": "idle",
    "percentage": 0,
    "message": ""
}

def update_progress(status, percentage, message):
    """Update the progress dictionary."""
    progress["status"] = status
    progress["percentage"] = percentage
    progress["message"] = message




@app.route('/initiate_payment', methods=['POST'])
@login_required
def initiate_payment():
    user = current_user
    amount = 200000  # ₦2000 in kobo
    
    reference = f"payment-{uuid.uuid4().hex[:10]}"
    
    user_id = str(user.id)
    if user_id not in payment_references:
        payment_references[user_id] = []
    payment_references[user_id].append(reference)
    
    # Initialize transaction without callback_url
    response = transaction_handler.initialize(
        email=user.email,
        amount=amount,
        reference=reference
    )
    
    if response[0] == 200:
        authorization_url = response[3]['authorization_url']
        return jsonify({"status": "success", "authorization_url": authorization_url})
    else:
        return jsonify({"status": "error", "message": "Failed to initialize payment"}), 400
        
        
payment_references = {}



@app.route('/verify_payment')
@login_required
def verify_payment():
    """Verify a payment transaction with Paystack"""
    reference = request.args.get('reference')
    user_id = str(current_user.id)
    
    # Verify the reference exists in the user's payment references
    if user_id not in payment_references or reference not in payment_references[user_id]:
        return jsonify({"status": "error", "message": "Invalid reference"}), 400
    
    # Verify the payment with Paystack
    response = transaction_handler.verify(reference)
    
    if response[0] == 200 and response[3]['status'] == 'success':
        # Payment verified successfully
        user = current_user
        credit = Credit.query.filter_by(user_id=user.id).first()
        if not credit:
            credit = Credit(user_id=user.id, amount=10)
        else:
            credit.amount += 10
        db.session.add(credit)
        db.session.commit()
        
        # Remove the reference from the user's payment references
        payment_references[user_id].remove(reference)
        
        return redirect(url_for('index'))
    else:
        return jsonify({"status": "error", "message": "Payment verification failed"}), 400






def generate_book_async(book_title):
    """Background function to generate the book and update progress."""
    try:
        update_progress("started", 0, "Starting book generation...")

        # Step 1: Generate chapters
        update_progress("in_progress", 10, "Generating chapters...")
        chapters_data = generate_chapters(book_title)
        if chapters_data is None:
            update_progress("error", 0, "Failed to generate chapters.")
            return

        # Step 2: Generate sections for each chapter
        update_progress("in_progress", 30, "Generating sections...")
        total_chapters = len(chapters_data["chapters"])
        for i, chapter in enumerate(chapters_data["chapters"]):
            sections_data = generate_sections(chapter["chapterTitle"], book_title)
            if sections_data is None:
                print(f"Failed to generate sections for chapter {chapter['chapterNumber']}. Skipping.")
                continue
            chapter["sections"] = sections_data["sections"]
            update_progress("in_progress", 30 + (i / total_chapters) * 30, f"Generated sections for chapter {i + 1}/{total_chapters}")

        # Step 3: Generate content for each section
        update_progress("in_progress", 60, "Generating section content...")
        total_sections = sum(len(chapter["sections"]) for chapter in chapters_data["chapters"])
        sections_completed = 0
        for chapter in chapters_data["chapters"]:
            for section in chapter["sections"]:
                content = generate_section_content(
                    section["sectionTitle"],
                    chapter["chapterTitle"],
                    book_title
                )
                if content is None:
                    print(f"Failed to generate content for section '{section['sectionTitle']}' in chapter '{chapter['chapterTitle']}'. Skipping.")
                    section["content"] = "Content generation failed."
                else:
                    section["content"] = content
                sections_completed += 1
                update_progress("in_progress", 60 + (sections_completed / total_sections) * 30, f"Generated content for section {sections_completed}/{total_sections}")

        # Save final JSON
        final_json_path = "final_workbook.json"
        with open(final_json_path, "w") as f:
            json.dump(chapters_data, f, indent=4)

        # Step 4: Generate PDF
        update_progress("in_progress", 95, "Generating PDF...")
        pdf_path = "final_workbook.pdf"
        generate_pdf(chapters_data, pdf_path)

        update_progress("completed", 100, "Book generation complete!")
    except Exception as e:
        update_progress("error", 0, f"An error occurred: {str(e)}")

@app.route('/')
def index():
    """Serve the main HTML page with credit balance."""
    credit_balance = 0
    if current_user.is_authenticated:
        credit = Credit.query.filter_by(user_id=current_user.id).first()
        if credit:
            credit_balance = credit.amount
    return render_template('index.html', credit_balance=credit_balance)
    
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        return 'Invalid email or password'
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)  # Use default method
        new_user = User(name=name, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')



@app.route('/generate_book', methods=['POST'])
@login_required
def generate_book():
    """Endpoint to start book generation."""
    user = current_user
    credit = Credit.query.filter_by(user_id=user.id).first()
    if not credit or credit.amount < 5:
        return jsonify({"error": "Insufficient credits. You need at least 5 credits to generate a book."}), 400

    data = request.json
    book_title = data.get('title')

    if not book_title:
        return jsonify({"error": "Book title is required"}), 400

    # Deduct credits
    credit.amount -= 5
    db.session.commit()

    # Reset progress
    update_progress("started", 0, "Starting book generation...")

    # Start the book generation process in a background thread
    thread = threading.Thread(target=generate_book_async, args=(book_title,))
    thread.start()

    return jsonify({"message": "Book generation started."}), 202

@app.route('/progress')
def get_progress():
    """Endpoint to stream progress updates."""
    def generate():
        while True:
            yield f"data: {json.dumps(progress)}\n\n"
            if progress["status"] in ["completed", "error"]:
                break
            time.sleep(1)  # Update every second
    return Response(stream_with_context(generate()), content_type='text/event-stream')

@app.route('/download_book')
@login_required
def download_book():
    """Endpoint to download the generated book."""
    if progress["status"] != "completed":
        return jsonify({"error": "Book generation is not complete."}), 400
    pdf_path = "final_workbook.pdf"
    return send_file(pdf_path, as_attachment=True)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)