import os
import re
from dotenv import load_dotenv
from flask import Flask, request, redirect, url_for, render_template, session, flash
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from mysql.connector import Error
import secrets

# --- Flask Config ---
app = Flask(__name__)
# Generate a secure secret key - in production, use environment variable
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

UPLOAD_FOLDER = "static/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Allowed file extensions for uploads
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def allowed_file(filename):
    """Check if uploaded file has allowed extension"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Za-z]', password):
        return False, "Password must contain at least one letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    return True, "Password is valid"

# --- DB connection ---
def get_connection():
    """Get database connection with error handling"""
    try:
        return mysql.connector.connect(
            host=os.getenv("DB_HOST"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASS"),
            database=os.getenv("DB_NAME")
        )
    except Error as e:
        print(f"Database connection error: {e}")
        return None

def check_post_ownership(post_id, user_id):
    """Check if user owns the post"""
    conn = get_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT user_id FROM posts WHERE id = %s", (post_id,))
        result = cursor.fetchone()
        return result and result[0] == user_id
    except Error as e:
        print(f"Database error: {e}")
        return False
    finally:
        conn.close()

# -------------------------
# Routes
# -------------------------

# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        # Validation
        errors = []
        
        if not first_name:
            errors.append("First name is required")
        if not last_name:
            errors.append("Last name is required")
        if not email:
            errors.append("Email is required")
        elif not validate_email(email):
            errors.append("Invalid email format")
        if not password:
            errors.append("Password is required")
        else:
            is_valid, msg = validate_password(password)
            if not is_valid:
                errors.append(msg)

        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template("register.html")

        conn = get_connection()
        if not conn:
            flash("Database connection error. Please try again.", 'error')
            return render_template("register.html")

        try:
            cursor = conn.cursor()
            
            # Check if email already exists
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                flash("Email already registered. Please use a different email.", 'error')
                return render_template("register.html")
            
            # Hash password and insert user
            hashed_password = generate_password_hash(password)
            cursor.execute(
                "INSERT INTO users (first_name, last_name, email, password) VALUES (%s, %s, %s, %s)",
                (first_name, last_name, email, hashed_password)
            )
            conn.commit()
            flash("Registration successful! Please log in.", 'success')
            return redirect(url_for('login'))
            
        except Error as e:
            print(f"Database error: {e}")
            flash("Registration failed. Please try again.", 'error')
            return render_template("register.html")
        finally:
            conn.close()

    return render_template("register.html")


# Login
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        if not email or not password:
            flash("Please enter both email and password", 'error')
            return render_template("login.html")

        conn = get_connection()
        if not conn:
            flash("Database connection error. Please try again.", 'error')
            return render_template("login.html")

        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT id, first_name, last_name, password FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
            
            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['first_name'] = user['first_name']
                session['last_name'] = user['last_name']
                flash(f"Welcome back, {user['first_name']}!", 'success')
                return redirect(url_for('dashboard'))
            else:
                flash("Invalid email or password", 'error')
                
        except Error as e:
            print(f"Database error: {e}")
            flash("Login failed. Please try again.", 'error')
        finally:
            conn.close()

    return render_template("login.html")


# Dashboard
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please log in to access the dashboard", 'error')
        return redirect('/')

    conn = get_connection()
    if not conn:
        flash("Database connection error", 'error')
        return redirect('/')

    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT posts.id, posts.title, posts.content, posts.user_id,
                   users.first_name, users.last_name
            FROM posts 
            JOIN users ON posts.user_id = users.id
            ORDER BY posts.id DESC
        """)
        posts = cursor.fetchall()

        # Attach images to each post
        for post in posts:
            cursor.execute("SELECT id, filename FROM post_images WHERE post_id = %s", (post['id'],))
            post['images'] = cursor.fetchall()
            # Add ownership flag
            post['is_owner'] = post['user_id'] == session['user_id']

        return render_template(
            'dashboard.html',
            posts=posts,
            first_name=session['first_name'],
            last_name=session['last_name']
        )
        
    except Error as e:
        print(f"Database error: {e}")
        flash("Error loading posts", 'error')
        return render_template('dashboard.html', posts=[])
    finally:
        conn.close()


# Add Post
@app.route('/add', methods=['GET', 'POST'])
def add_post():
    if 'user_id' not in session:
        flash("Please log in to add a post", 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form.get('title', '').strip().upper()
        content = request.form.get('content', '').strip()

        # Validation
        if not title:
            flash("Title is required", 'error')
            return render_template("add.html")
        if not content:
            flash("Content is required", 'error')
            return render_template("add.html")

        conn = get_connection()
        if not conn:
            flash("Database connection error", 'error')
            return render_template("add.html")

        try:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO posts (title, content, user_id) VALUES (%s, %s, %s)",
                          (title, content, session['user_id']))
            conn.commit()
            post_id = cursor.lastrowid

            # Handle file uploads
            if 'images' in request.files:
                files = request.files.getlist('images')
                uploaded_count = 0
                
                for file in files:
                    if file and file.filename != '' and allowed_file(file.filename):
                        filename = secure_filename(file.filename)
                        # Add timestamp to prevent filename conflicts
                        name, ext = os.path.splitext(filename)
                        filename = f"{name}_{secrets.token_hex(8)}{ext}"
                        
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        file.save(file_path)
                        
                        cursor.execute("INSERT INTO post_images (post_id, filename) VALUES (%s, %s)",
                                     (post_id, filename))
                        uploaded_count += 1
                    elif file and file.filename != '':
                        flash(f"File '{file.filename}' is not allowed. Only images are permitted.", 'warning')

                if uploaded_count > 0:
                    flash(f"Post created successfully with {uploaded_count} images!", 'success')
                else:
                    flash("Post created successfully!", 'success')
            else:
                flash("Post created successfully!", 'success')

            conn.commit()
            return redirect(url_for('dashboard'))
            
        except Error as e:
            print(f"Database error: {e}")
            flash("Error creating post. Please try again.", 'error')
        finally:
            conn.close()

    return render_template("add.html")


# Update Post
@app.route('/update/<int:post_id>', methods=['GET', 'POST'])
def update_post(post_id):
    if 'user_id' not in session:
        flash("Please log in to update posts", 'error')
        return redirect(url_for('login'))

    # Check ownership
    if not check_post_ownership(post_id, session['user_id']):
        flash("You can only edit your own posts", 'error')
        return redirect(url_for('dashboard'))

    conn = get_connection()
    if not conn:
        flash("Database connection error", 'error')
        return redirect(url_for('dashboard'))

    try:
        cursor = conn.cursor(dictionary=True)

        if request.method == 'POST':
            title = request.form.get('title', '').strip()
            content = request.form.get('content', '').strip()

            if not title or not content:
                flash("Title and content are required", 'error')
                return redirect(url_for('update_post', post_id=post_id))

            cursor.execute("UPDATE posts SET title = %s, content = %s WHERE id = %s", 
                          (title, content, post_id))

            # Handle new image uploads
            if 'images' in request.files:
                files = request.files.getlist('images')
                uploaded_count = 0
                
                for file in files:
                    if file and file.filename != '' and allowed_file(file.filename):
                        filename = secure_filename(file.filename)
                        name, ext = os.path.splitext(filename)
                        filename = f"{name}_{secrets.token_hex(8)}{ext}"
                        
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        file.save(file_path)
                        
                        cursor.execute("INSERT INTO post_images (post_id, filename) VALUES (%s, %s)", 
                                     (post_id, filename))
                        uploaded_count += 1

                if uploaded_count > 0:
                    flash(f"Post updated with {uploaded_count} new images!", 'success')

            conn.commit()
            flash("Post updated successfully!", 'success')
            return redirect(url_for('dashboard'))

        # GET request - show update form
        cursor.execute("SELECT * FROM posts WHERE id = %s", (post_id,))
        post = cursor.fetchone()
        cursor.execute("SELECT id, filename FROM post_images WHERE post_id = %s", (post_id,))
        images = cursor.fetchall()

        return render_template("update.html", post=post, images=images)
        
    except Error as e:
        print(f"Database error: {e}")
        flash("Error updating post", 'error')
        return redirect(url_for('dashboard'))
    finally:
        conn.close()


# Delete Post
@app.route('/delete/<int:post_id>')
def delete_post(post_id):
    if 'user_id' not in session:
        flash("Please log in to delete posts", 'error')
        return redirect(url_for('login'))

    # Check ownership
    if not check_post_ownership(post_id, session['user_id']):
        flash("You can only delete your own posts", 'error')
        return redirect(url_for('dashboard'))

    conn = get_connection()
    if not conn:
        flash("Database connection error", 'error')
        return redirect(url_for('dashboard'))

    try:
        cursor = conn.cursor()

        # Get and delete image files
        cursor.execute("SELECT filename FROM post_images WHERE post_id = %s", (post_id,))
        images = cursor.fetchall()
        
        for (filename,) in images:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except OSError as e:
                    print(f"Error deleting file {filename}: {e}")

        # Delete from database
        cursor.execute("DELETE FROM post_images WHERE post_id = %s", (post_id,))
        cursor.execute("DELETE FROM posts WHERE id = %s", (post_id,))
        conn.commit()
        
        flash("Post deleted successfully!", 'success')
        
    except Error as e:
        print(f"Database error: {e}")
        flash("Error deleting post", 'error')
    finally:
        conn.close()

    return redirect(url_for('dashboard'))


# Delete single image
@app.route('/delete_image/<int:post_id>/<int:image_id>', methods=['POST'])
def delete_image(post_id, image_id):
    if 'user_id' not in session:
        flash("Please log in to delete images", 'error')
        return redirect(url_for('login'))

    # Check ownership
    if not check_post_ownership(post_id, session['user_id']):
        flash("You can only edit your own posts", 'error')
        return redirect(url_for('dashboard'))

    conn = get_connection()
    if not conn:
        flash("Database connection error", 'error')
        return redirect(url_for('update_post', post_id=post_id))

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT filename FROM post_images WHERE id = %s AND post_id = %s", 
                      (image_id, post_id))
        img = cursor.fetchone()
        
        if img:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], img[0])
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except OSError as e:
                    print(f"Error deleting file: {e}")

            cursor.execute("DELETE FROM post_images WHERE id = %s", (image_id,))
            conn.commit()
            flash("Image deleted successfully!", 'success')
        else:
            flash("Image not found", 'error')
            
    except Error as e:
        print(f"Database error: {e}")
        flash("Error deleting image", 'error')
    finally:
        conn.close()

    return redirect(url_for('update_post', post_id=post_id))


# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out successfully", 'info')
    return redirect(url_for('login'))


# Error handlers
@app.errorhandler(413)
def too_large(e):
    flash("File is too large. Maximum size is 16MB.", 'error')
    return redirect(request.url)

@app.errorhandler(404)
def not_found(e):
    flash("Page not found", 'error')
    return redirect(url_for('dashboard'))

@app.errorhandler(500)
def server_error(e):
    flash("Internal server error. Please try again.", 'error')
    return redirect(url_for('dashboard'))


# -------------------------
# Run App
# -------------------------
if __name__ == '__main__':
    app.run(debug=False)  # Set to False in production