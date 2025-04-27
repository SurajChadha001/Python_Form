from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, Response, send_file
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import os
from datetime import datetime
from flask import send_from_directory, abort
from werkzeug.utils import secure_filename
import pymysql
import pymysql.cursors 
from werkzeug.security import check_password_hash
pymysql.install_as_MySQLdb()

app = Flask(__name__)
app.secret_key = "your_secret_key"


app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'workabroad'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = pymysql.connect(
    host=app.config['MYSQL_HOST'],
    user=app.config['MYSQL_USER'],
    password=app.config['MYSQL_PASSWORD'],
    database=app.config['MYSQL_DB'],
    cursorclass=pymysql.cursors.DictCursor
)

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
bcrypt = Bcrypt(app)
cur = mysql.cursor()
cur.execute("SELECT email, password FROM admins")
admins = cur.fetchall()

for admin in admins:
    email = admin['email']
    plain_password = admin['password']
    if not plain_password.startswith('$2b$'):
        hashed_password = bcrypt.generate_password_hash(plain_password).decode('utf-8')
        cur.execute("UPDATE admins SET password = %s WHERE email = %s", (hashed_password, email))

mysql.commit()
cur.close()
login_manager = LoginManager(app)
login_manager.login_view = 'login'
jobs = []
class User(UserMixin):
    def __init__(self, id, email, first_name, last_name, phone):
        self.id = id
        self.email = email
        self.first_name = first_name
        self.last_name = last_name
        self.phone = phone

@login_manager.user_loader
def load_user(user_id):
    cur = mysql.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user_data = cur.fetchone()
    cur.close()
    if user_data:
        return User(user_data['id'], user_data['email'], user_data['first_name'], user_data['last_name'],user_data['phone'])
    return None

@app.route('/validate_email', methods=['POST'])
def validate_email():
    try:
        data = request.get_json(force=True)
        email = data.get('email')

        if not email:
            return jsonify({'error': 'Email is required'}), 400

        cur = mysql.cursor()
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        existing_user = cur.fetchone()
        cur.close()

        if existing_user:
            return jsonify({'error': 'Email already exists'}), 400

        return jsonify({'message': 'Email is available'}), 200

    except Exception as e:
        print(f"Error during email validation: {e}")
        return jsonify({'error': 'Internal server error'}), 500
@app.route('/')
def home():
    return redirect(url_for('find_jobs'))
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        phone = request.form['phone']
        address = request.form['address']
        if not password: return redirect(request.url)
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        cur = mysql.cursor()
        try:
            cur.execute("SELECT * FROM users WHERE email = %s", (email,))
            existing_user = cur.fetchone()
            if existing_user:
                flash('Email already exists!', 'danger')
                return redirect(url_for('signup'))

            cur.execute(""" 
                INSERT INTO users (first_name, last_name, email, password_hash, phone, address) 
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (first_name, last_name, email, hashed_password, phone, address))
            mysql.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except:
            flash('Email already exists!', 'danger')
        finally:
            cur.close()

    return render_template('signup.html')
# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         email = request.form['email']
#         password = request.form['password']

#         if not email or not password:
#             flash("Email and password don't match", 'danger')
#             return redirect(url_for('login'))

#         cur = mysql.cursor(pymysql.cursors.DictCursor)  # Use correct DictCursor for pymysql

#         # Check if admin email
#         if email == 'admin@example.com':
#             print("Attempting admin login...")
#             cur.execute("SELECT password FROM admins WHERE email = %s LIMIT 1", (email,))
#             admin_data = cur.fetchone()

#             if admin_data:
#                 if bcrypt.check_password_hash(admin_data['password'], password):
#                     print("Admin login successful!")
#                     session['admin'] = True
#                     cur.close()
#                     flash('Admin login successful!', 'success')
#                     return redirect(url_for('admin_dashboard'))
#                 else:
#                     flash('Invalid admin credentials', 'danger')
#             else:
#                 flash('No admin found with that email', 'danger')

#             cur.close()
#             return render_template('login.html', error="Email and password don't match")

#         # Regular user login
#         print("Attempting user login...")
#         cur.execute("SELECT * FROM users WHERE email = %s", (email,))
#         user_data = cur.fetchone()
#         cur.close()

#         if user_data:
#             if bcrypt.check_password_hash(user_data['password_hash'], password):
#                 print("User login successful!")
#                 session['admin'] = False  # Ensure correct session role
#                 user = User(user_data['id'], user_data['email'], user_data['first_name'], user_data['last_name'])
#                 login_user(user)
#                 flash('Login successful!', 'success')
#                 return redirect(url_for('profile'))
#             else:
#                 flash('Invalid credentials', 'danger')
#         else:
#             flash('No user found with that email', 'danger')

#         return render_template('login.html', error="Email and password don't match")

#     return render_template('login.html')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        
        if not email or not password:
            flash("Email and password don't match", 'danger')
            return redirect(url_for('login'))

        cur = mysql.cursor(pymysql.cursors.DictCursor)  

        
        cur.execute("SELECT password FROM admins WHERE email = %s LIMIT 1", (email,))
        admin_data = cur.fetchone()

        if admin_data and bcrypt.check_password_hash(admin_data['password'], password):
            session['admin'] = True
            cur.close()
            
            admin_user = User(id=1, email=email, first_name="Admin", last_name="User", phone="")  
            login_user(admin_user)  
            flash('Admin login successful!', 'success')
            return redirect(url_for('admin_dashboard'))

        
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user_data = cur.fetchone()
        cur.close()

        if user_data and bcrypt.check_password_hash(user_data['password_hash'], password):
            session['admin'] = False
            user = User(user_data['id'], user_data['email'], user_data['first_name'], user_data['last_name'],  user_data['phone'])
            login_user(user)  
            flash('Login successful!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Invalid credentials', 'danger')
            return render_template('login.html', error="Email and password don't match")

    return render_template('login.html')

# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         email = request.form['email']
#         password = request.form['password']

#         if not email or not password:
#             flash("Email and password don't match", 'danger')
#             return redirect(url_for('login'))

#         cur = mysql.cursor(pymysql.cursors.DictCursor) # Ensure data is returned as a dict

#         if email == 'admin@example.com':
#             cur.execute("SELECT password FROM admins WHERE email = %s LIMIT 1", (email,))
#             admin_data = cur.fetchone()

#             if admin_data and bcrypt.check_password_hash(admin_data['password'], password):
#                 session['admin'] = True
#                 cur.close()
#                 flash('Admin login successful!', 'success')
#                 return redirect(url_for('admin_dashboard'))
#             else:
#                 cur.close()
#                 flash('Invalid admin credentials', 'danger')
#                 return render_template('login.html', error="Email and password don't match")

#         # Regular user login
#         cur.execute("SELECT * FROM users WHERE email = %s", (email,))
#         user_data = cur.fetchone()
#         cur.close()

#         if user_data and bcrypt.check_password_hash(user_data['password_hash'], password):
#             session['admin'] = False
#             user = User(user_data['id'], user_data['email'], user_data['first_name'], user_data['last_name'])
#             login_user(user)  # Required for Flask-Login session handling
#             flash('Login successful!', 'success')
#             return redirect(url_for('profile'))
#         else:
#             flash('Invalid credentials', 'danger')
#             return render_template('login.html', error="Email and password don't match")

#     return render_template('login.html')

# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         logout_user()
#         session.clear()

#         email = request.form['email']
#         password = request.form['password']
#         next_page = request.args.get('next')

#         if not email or not password:
#             flash("Email and password are required.", 'danger')
#             return redirect(url_for('login'))

#         # Admin login
#         if email == 'admin@example.com':
#             cur = mysql.cursor()
#             cur.execute("SELECT password FROM admins WHERE email = %s LIMIT 1", (email,))
#             admin_data = cur.fetchone()
#             cur.close()

#             if admin_data and bcrypt.check_password_hash(admin_data['password'], password):
#                 user = User(id=0, email=email)
#                 login_user(user)
#                 flash('Admin login successful!', 'success')
#                 return redirect(next_page or url_for('admin_dashboard'))
#             else:
#                 flash('Invalid admin credentials', 'danger')
#                 return render_template('login.html', error="Email and password don't match")

#         # Regular user login
#         cur = mysql.cursor()
#         cur.execute("SELECT * FROM users WHERE email = %s", (email,))
#         user_data = cur.fetchone()
#         cur.close()

#         if user_data and bcrypt.check_password_hash(user_data['password_hash'], password):
#             user = User(id=0, email=email, first_name='Admin', last_name='User', is_admin=True)
#             login_user(user)
#             flash('Login successful!', 'success')
#             return redirect(next_page or url_for('profile'))
#         else:
#             flash('Invalid user credentials', 'danger')
#             return render_template('login.html', error="Email and password don't match")

#     return render_template('login.html')




@app.route('/profile')
@login_required
def profile():
    with mysql.cursor() as cur:
        tab = request.args.get('tab', 'profile') 
        cur.execute("SELECT * FROM users WHERE id = %s", (current_user.id,))
        user_data = cur.fetchone()
        # cur.execute("SELECT * FROM user_cv WHERE user_id = %s", (current_user.id,))
        # user_cv = cur.fetchone()
        cur.execute("SELECT * FROM user_cv WHERE user_id = %s ORDER BY id DESC LIMIT 1", (current_user.id,))
        user_cv = cur.fetchone()
        education = user_cv['education'] if user_cv else ''
        work_experience = user_cv['work_experience'] if user_cv else ''
        skills_languages = user_cv['skills_languages'] if user_cv else ''
        additional_info = user_cv['additional_info'] if user_cv else ''

        cur.execute("SELECT * FROM user_education WHERE user_id = %s", (current_user.id,))
        all_educations = cur.fetchall()

        cur.execute("SELECT * FROM documents WHERE user_id = %s ORDER BY upload_date DESC", (current_user.id,))
        documents = cur.fetchall()
        cur.execute("SELECT * FROM user_experience WHERE user_id = %s", (current_user.id,))
        all_experiences = cur.fetchall()
        cur.execute("SELECT * FROM jobs WHERE status IN ('Saved', 'Applied')")
        # cur.execute("SELECT * FROM jobs ORDER BY id DESC")
        jobs = cur.fetchall()
        cur.execute("SELECT * FROM user_certificates WHERE user_id = %s", (current_user.id,))
        all_certificates = cur.fetchall()
        cur.execute("SELECT skill_name, skill_level FROM skills WHERE user_id = %s", (current_user.id,))
        skills = cur.fetchall()

        cur.execute("SELECT language_name, language_level FROM languages WHERE user_id = %s", (current_user.id,))
        languages = cur.fetchall()

        cur.execute("SELECT industry_name FROM industries WHERE user_id = %s", (current_user.id,))
        industries = cur.fetchall()

        cur.execute("SELECT interest_text FROM interests WHERE user_id = %s", (current_user.id,))
        interests = cur.fetchone()

        cur.execute("SELECT reference_text FROM user_references WHERE user_id = %s", (current_user.id,))
        references = cur.fetchone()
    return render_template('profile.html', user=user_data, user_cv=user_cv, education=education, 
                           work_experience=work_experience, skills_languages=skills_languages,
                           additional_info=additional_info, documents=documents, tab=tab,
                           jobs=jobs, all_educations=all_educations,all_certificates=all_certificates, all_experiences=all_experiences, skills=skills,languages=languages,industries=industries,
                           interests=interests['interest_text'] if interests else '',
                           references=references['reference_text'] if references else '')
# @app.route('/save_cv', methods=['POST'])
# @login_required
# def save_cv():
#     user_id = current_user.id  
#     education = request.form.get('education', '')
#     work_experience = request.form.get('work_experience', '')
#     skills_languages = request.form.get('skills_languages', '')
#     additional_info = request.form.get('additional_info', '')
#     cv_file = request.files.get('cv_file')

#     cv_text = f"Education:\n{education}\n\nWork Experience:\n{work_experience}\n\nSkills & Languages:\n{skills_languages}\n\nAdditional Info:\n{additional_info}"

#     # Save CV file if it was uploaded
#     cv_file_path = None
#     if cv_file and cv_file.filename:
#         filename = secure_filename(cv_file.filename)
#         upload_folder = os.path.join('static', 'uploads', 'cv_files')
#         os.makedirs(upload_folder, exist_ok=True)
#         cv_file_path = os.path.join(upload_folder, f'user_{user_id}_{filename}')
#         cv_file.save(cv_file_path)

#     cur = mysql.cursor()

#     # Update user's cv_text
#     cur.execute("""
#         UPDATE users
#         SET cv_text = %s
#         WHERE id = %s
#     """, (cv_text, user_id))

#     # Insert into user_cv table including file path
#     cur.execute("""
#         INSERT INTO user_cv (education, work_experience, skills_languages, additional_info, user_id, cv_text, cv_file)
#         VALUES (%s, %s, %s, %s, %s, %s, %s)
#     """, (education, work_experience, skills_languages, additional_info, user_id, cv_text, cv_file_path))

#     mysql.commit()
#     cur.close()

#     flash('CV text and file saved successfully!', 'success')
#     return redirect(url_for('profile', tab='cv'))

# @app.route('/save_cv', methods=['POST'])
# @login_required
# def save_cv():
#     user_id = current_user.id  
#     education = request.form.get('education', '')
#     work_experience = request.form.get('work_experience', '')
#     skills_languages = request.form.get('skills_languages', '')
#     additional_info = request.form.get('additional_info', '')
#     cv_file = request.files.get('cv_file')

#     # Compose CV text
#     cv_text = f"Education:\n{education}\n\nWork Experience:\n{work_experience}\n\nSkills & Languages:\n{skills_languages}\n\nAdditional Info:\n{additional_info}"

#     # Save CV file if uploaded
#     cv_file_path = None
#     if cv_file and cv_file.filename:
#         filename = secure_filename(cv_file.filename)
#         upload_folder = app.config['UPLOAD_FOLDER']
#         os.makedirs(upload_folder, exist_ok=True)
#         cv_file_path = os.path.join(upload_folder, f'user_{user_id}_{filename}')
#         cv_file.save(cv_file_path)

#     cur = mysql.cursor()

#     # Update main user table (overwrite existing)
#     cur.execute("""
#         UPDATE users
#         SET cv_text = %s, cv_file = %s
#         WHERE id = %s
#     """, (cv_text, cv_file_path, user_id))

#     # Insert new entry in user_cv table (like history)
#     cur.execute("""
#         INSERT INTO user_cv (
#             education, work_experience, skills_languages, additional_info,
#             user_id, cv_text, cv_file
#         ) VALUES (%s, %s, %s, %s, %s, %s, %s)
#     """, (
#         education, work_experience, skills_languages, additional_info,
#         user_id, cv_text, cv_file_path
#     ))
#     cur.execute("""
#         INSERT INTO job_user_actions (
#             user_id, cv_text, cv_file
#         ) VALUES (%s, %s, %s)
#     """, (user_id, cv_text, cv_file_path))

#     mysql.commit()
#     cur.close()

#     flash('CV text and file saved successfully!', 'success')
#     return redirect(url_for('profile', tab='cv'))
# @app.route('/save_cv', methods=['POST'])
# @login_required
# def save_cv():
#     user_id = current_user.id  
#     education = request.form.get('education', '')
#     work_experience = request.form.get('work_experience', '')
#     skills_languages = request.form.get('skills_languages', '')
#     additional_info = request.form.get('additional_info', '')
#     cv_file = request.files.get('cv_file')

    
#     cv_text = f"Education:\n{education}\n\nWork Experience:\n{work_experience}\n\nSkills & Languages:\n{skills_languages}\n\nAdditional Info:\n{additional_info}"

#     saved_filename = None
#     if cv_file and cv_file.filename:
#         filename = secure_filename(cv_file.filename)
#         saved_filename = f"user_{user_id}_{filename}"
#         upload_folder = app.config['UPLOAD_FOLDER']
#         os.makedirs(upload_folder, exist_ok=True)
#         file_path = os.path.join(upload_folder, saved_filename)
#         cv_file.save(file_path)

#     cur = mysql.cursor()

    
#     cur.execute("""
#         UPDATE users
#         SET cv_text = %s, cv_file = %s
#         WHERE id = %s
#     """, (cv_text, saved_filename, user_id))

    
#     cur.execute("""
#         INSERT INTO user_cv (
#             education, work_experience, skills_languages, additional_info,
#             user_id, cv_text, cv_file
#         ) VALUES (%s, %s, %s, %s, %s, %s, %s)
#     """, (
#         education, work_experience, skills_languages, additional_info,
#         user_id, cv_text, saved_filename
#     ))

    
#     cur.execute("""
#         INSERT INTO job_user_actions (
#             user_id, cv_text, cv_file
#         ) VALUES (%s, %s, %s)
#     """, (user_id, cv_text, saved_filename))

#     mysql.commit()
#     cur.close()

#     flash('CV text and file saved successfully!', 'success')
#     return redirect(url_for('profile', tab='cv'))
# @app.route('/save_cv', methods=['POST'])
# @login_required
# def save_cv():
#     user_id = current_user.id  
#     education = request.form.get('education', '')
#     work_experience = request.form.get('work_experience', '')
#     skills_languages = request.form.get('skills_languages', '')
#     additional_info = request.form.get('additional_info', '')
#     cv_file = request.files.get('cv_file')

#     # Construct cv_text
#     cv_text = f"Education:\n{education}\n\nWork Experience:\n{work_experience}\n\nSkills & Languages:\n{skills_languages}\n\nAdditional Info:\n{additional_info}"

#     # Check if cv_text is empty
#     if not cv_text.strip():  # only save if cv_text is not empty
#         cv_text = None

#     saved_filename = None
#     if cv_file and cv_file.filename:
#         filename = secure_filename(cv_file.filename)
#         saved_filename = f"user_{user_id}_{filename}"
#         upload_folder = app.config['UPLOAD_FOLDER']
#         os.makedirs(upload_folder, exist_ok=True)
#         file_path = os.path.join(upload_folder, saved_filename)
#         cv_file.save(file_path)

#     cur = mysql.cursor()

#     # Update query - Only update cv_text or cv_file if they have valid values
#     if cv_text:
#         cur.execute(""" 
#             UPDATE users
#             SET cv_text = %s
#             WHERE id = %s
#         """, (cv_text, user_id))

#     if saved_filename:
#         cur.execute(""" 
#             UPDATE users
#             SET cv_file = %s
#             WHERE id = %s
#         """, (saved_filename, user_id))

#     # Insert into user_cv
#     if cv_text or saved_filename:  # Only insert if there is something to insert
#         cur.execute("""
#             INSERT INTO user_cv (
#                 education, work_experience, skills_languages, additional_info,
#                 user_id, cv_text, cv_file
#             ) VALUES (%s, %s, %s, %s, %s, %s, %s)
#         """, (
#             education, work_experience, skills_languages, additional_info,
#             user_id, cv_text, saved_filename
#         ))

#     # Insert into job_user_actions
#     if cv_text or saved_filename:  # Only insert if there is something to insert
#         cur.execute("""
#             INSERT INTO job_user_actions (
#                 user_id, cv_text, cv_file
#             ) VALUES (%s, %s, %s)
#         """, (user_id, cv_text, saved_filename))

#     mysql.commit()
#     cur.close()

#     flash('CV text and file saved successfully!', 'success')
#     return redirect(url_for('profile', tab='cv'))
# @app.route('/save_cv', methods=['POST'])
# @login_required
# def save_cv():
#     user_id = current_user.id  
#     education = request.form.get('education', '').strip()
#     work_experience = request.form.get('work_experience', '').strip()
#     skills_languages = request.form.get('skills_languages', '').strip()
#     additional_info = request.form.get('additional_info', '').strip()
#     cv_file = request.files.get('cv_file')

#     # Only construct cv_text if at least one field is filled
#     has_cv_text = any([education, work_experience, skills_languages, additional_info])
#     cv_text = None
#     if has_cv_text:
#         cv_text = f"Education:\n{education}\n\nWork Experience:\n{work_experience}\n\nSkills & Languages:\n{skills_languages}\n\nAdditional Info:\n{additional_info}"

#     saved_filename = None
#     if cv_file and cv_file.filename:
#         filename = secure_filename(cv_file.filename)
#         saved_filename = f"user_{user_id}_{filename}"
#         upload_folder = app.config['UPLOAD_FOLDER']
#         os.makedirs(upload_folder, exist_ok=True)
#         file_path = os.path.join(upload_folder, saved_filename)
#         cv_file.save(file_path)

#     cur = mysql.cursor()

#     # Update user table only if there's something to update
#     if cv_text:
#         cur.execute(""" 
#             UPDATE users
#             SET cv_text = %s
#             WHERE id = %s
#         """, (cv_text, user_id))

#     if saved_filename:
#         cur.execute(""" 
#             UPDATE users
#             SET cv_file = %s
#             WHERE id = %s
#         """, (saved_filename, user_id))

#     # Insert into user_cv if at least one CV content is available
#     if cv_text or saved_filename:
#         cur.execute("""
#             INSERT INTO user_cv (
#                 education, work_experience, skills_languages, additional_info,
#                 user_id, cv_text, cv_file
#             ) VALUES (%s, %s, %s, %s, %s, %s, %s)
#         """, (
#             education, work_experience, skills_languages, additional_info,
#             user_id, cv_text, saved_filename
#         ))

#     # Insert into job_user_actions with the latest CV data
#     cur.execute("""
#         INSERT INTO job_user_actions (
#             user_id, cv_text, cv_file
#         ) VALUES (%s, %s, %s)
#     """, (user_id, cv_text, saved_filename))

#     mysql.commit()
#     cur.close()

#     flash('CV text and file saved successfully!', 'success')
#     return redirect(url_for('profile', tab='cv'))
 
@app.route('/save_cv', methods=['POST'])
@login_required
def save_cv():
    user_id = current_user.id  
    education = request.form.get('education', '').strip()
    work_experience = request.form.get('work_experience', '').strip()
    skills_languages = request.form.get('skills_languages', '').strip()
    additional_info = request.form.get('additional_info', '').strip()
    cv_file = request.files.get('cv_file')
    save_both = request.form.get('save_both') == '1'
 
    # Only construct cv_text if at least one field is filled or we're saving both
    has_cv_text = any([education, work_experience, skills_languages, additional_info]) or save_both
    cv_text = None
    if has_cv_text:
        cv_text = f"Education:\n{education}\n\nWork Experience:\n{work_experience}\n\nSkills & Languages:\n{skills_languages}\n\nAdditional Info:\n{additional_info}"
 
    saved_filename = None
    if cv_file and cv_file.filename:
        filename = secure_filename(cv_file.filename)
        saved_filename = f"user_{user_id}_{filename}"
        upload_folder = app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        file_path = os.path.join(upload_folder, saved_filename)
        cv_file.save(file_path)
 
    cur = mysql.cursor()
 
    # Update user table only if there's something to update
    if cv_text:
        cur.execute("""
            UPDATE users
            SET cv_text = %s
            WHERE id = %s
        """, (cv_text, user_id))
 
    if saved_filename:
        cur.execute("""
            UPDATE users
            SET cv_file = %s
            WHERE id = %s
        """, (saved_filename, user_id))
 
    # Insert into user_cv if at least one CV content is available
    if cv_text or saved_filename or save_both:
        cur.execute("""
            INSERT INTO user_cv (
                education, work_experience, skills_languages, additional_info,
                user_id, cv_text, cv_file
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            education, work_experience, skills_languages, additional_info,
            user_id, cv_text, saved_filename
        ))
 
    # Check if user already has an entry in job_user_actions
    cur.execute("SELECT id FROM job_user_actions WHERE user_id = %s", (user_id,))
    existing_action = cur.fetchone()
 
    if existing_action:
        # Update existing row
        cur.execute("""
            UPDATE job_user_actions
            SET cv_text = %s, cv_file = %s
            WHERE user_id = %s
        """, (cv_text, saved_filename, user_id))
    else:
        # Insert new row
        cur.execute("""
            INSERT INTO job_user_actions (
                user_id, cv_text, cv_file
            ) VALUES (%s, %s, %s)
        """, (user_id, cv_text, saved_filename))
 
    mysql.commit()
    cur.close()
 
    flash('CV saved successfully!', 'success')
    return redirect(url_for('profile', tab='cv'))
@app.route('/upload_cv_file', methods=['POST'])
@login_required
def upload_cv_file():
    user_id = current_user.id  
    if 'cv_file' not in request.files:
        flash('No file part', 'danger')
        return redirect(request.referrer)

    file = request.files['cv_file']
    if file.filename == '':
        flash('No file selected', 'warning')
        return redirect(request.referrer)

    if file and allowed_file(file.filename):
        filename = secure_filename(f"{user_id}_{file.filename}")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        cur = mysql.cursor()
        cur.execute("""
            UPDATE users
            SET cv_file = %s
            WHERE id = %s
        """, (filepath, user_id))
        mysql.commit()
        cur.close()

        flash('CV file uploaded successfully!', 'success')
        return redirect(url_for('profile', tab='cv'))

    flash('Invalid file format. Only PDF, DOC, DOCX allowed.', 'danger')
    return redirect(request.referrer)
@app.route('/view_cv/<int:user_id>')
@login_required
def view_cv(user_id):
    cur = mysql.cursor()
    cur.execute("SELECT cv_file FROM users WHERE id = %s", (user_id,))
    row = cur.fetchone()
    cur.close()
    
    if row and row.get('cv_file'):
        filepath = row.get('cv_file')

        
        try:
            with open(filepath, 'rb') as file:
                return Response(
                    file.read(),
                    mimetype='application/pdf',  
                    headers={
                        'Content-Disposition': 'inline; filename=cv.pdf'  
                    }
                )
        except FileNotFoundError:
            flash("CV file not found.", 'danger')
            return redirect(request.referrer or url_for('view_users'))
    else:
        flash("No CV file found for this user.", 'warning')
        return redirect(request.referrer or url_for('view_users'))
@app.route('/download_cv_1/<filename>')
@login_required
def download_cv_1(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
# @app.route('/admin/view_cv_1/<filename>')
# @login_required
# def view_cv_1(filename):
#     cur = mysql.cursor()
#     cur.execute("SELECT cv_text FROM users WHERE cv_file = %s", (filename,))
#     user = cur.fetchone()
#     cur.close()
#     return render_template('admin_view_cv.html', cv_text=user['cv_text'])
@app.route('/admin/view_cv_1/<filename>')
@login_required
def view_cv_1(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
@app.route('/admin/delete_cv_1/<filename>', methods=['POST'])  
@login_required
def delete_cv_1(filename):
    cur = mysql.cursor()  
    cur.execute("SELECT cv_file FROM users WHERE cv_file = %s", (filename,))
    result = cur.fetchone()
    
    if result and result.get('cv_file'):
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], result['cv_file'])
        if os.path.exists(file_path):
            os.remove(file_path)

    cur.execute("UPDATE users SET cv_file = NULL WHERE cv_file = %s", (filename,))
    mysql.commit()
    cur.close()
    flash('CV file deleted.', 'success')
    return redirect(request.referrer or url_for('view_users'))


# @app.route('/admin/delete_cv_1/<filename>')
# @login_required
# def delete_cv_1(filename):
#     cur = mysql.cursor()
#     cur.execute("SELECT cv_file FROM users WHERE cv_file = %s", (filename,))
#     result = cur.fetchone()
#     if result and result[0]:
#         file_path = os.path.join(app.config['UPLOAD_FOLDER'], result[0])
#         if os.path.exists(file_path):
#             os.remove(file_path)

#     cur.execute("UPDATE users SET cv_file = NULL WHERE cv_file = %s", (filename,))
#     mysql.commit()
#     cur.close()
#     flash('CV file deleted.', 'success')
#     return redirect(url_for('admin_panel'))

# @app.route('/admin/download_cv_1/<filename>')
# @login_required
# def admin_download_cv_1(filename):
#     return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/download_cv/<int:user_id>', methods=['GET'])
@login_required
def download_cv(user_id):
    cur = mysql.cursor()
    cur.execute("SELECT cv_file FROM users WHERE id = %s", (user_id,))
    row = cur.fetchone()
    cur.close()

    if row and row.get('cv_file'):
        filepath = row.get('cv_file')
        try:
            return send_file(filepath, as_attachment=True)
        except FileNotFoundError:
            flash("CV file not found.", 'danger')
            return redirect(request.referrer or url_for('view_users'))
    else:
        flash("No CV file found for this user.", 'warning')
        return redirect(request.referrer or url_for('view_users'))
@app.route('/delete_cv/<int:user_id>', methods=['POST'])
@login_required
def delete_cv(user_id):
    cur = mysql.cursor()
    cur.execute("SELECT cv_file FROM users WHERE id = %s", (user_id,))
    row = cur.fetchone()
    cur.close()

    if row and row.get('cv_file'):
        filepath = row.get('cv_file')
        os.remove(filepath)  

        
        cur = mysql.cursor()
        cur.execute("""
            UPDATE users
            SET cv_file = NULL
            WHERE id = %s
        """, (user_id,))
        mysql.commit()
        cur.close()

        flash('CV file deleted successfully.', 'success')
    else:
        flash('No CV file found for this user.', 'warning')

    return redirect(request.referrer or url_for('view_users'))

@app.route('/save_certificate', methods=['POST'])
@login_required
def save_certificate():
    cert_id = request.form.get('cert_id')
    certificate_name = request.form['certificate_name']
    issuing_organization = request.form['issuing_organization']
    issue_date = request.form['issue_date']
    expiration_date = request.form['expiration_date']
    credential_id = request.form['credential_id']
    credential_url = request.form['credential_url']
    user_id = current_user.id

    cursor = mysql.cursor()

    if cert_id:
        query = """
            UPDATE user_certificates
            SET certificate_name=%s, issuing_organization=%s,
                issue_date=%s, expiration_date=%s,
                credential_id=%s, credential_url=%s
            WHERE id=%s AND user_id=%s
        """
        cursor.execute(query, (certificate_name, issuing_organization, issue_date,
                               expiration_date, credential_id, credential_url, cert_id, user_id))
    else:
        query = """
            INSERT INTO user_certificates (user_id, certificate_name, issuing_organization,
                                           issue_date, expiration_date, credential_id, credential_url)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query, (user_id, certificate_name, issuing_organization,
                               issue_date, expiration_date, credential_id, credential_url))

    mysql.commit()
    return redirect(url_for('profile', tab='certificate'))
@app.route('/delete_certificate/<int:cert_id>', methods=['POST'])
@login_required
def delete_certificate(cert_id):
    cursor = mysql.cursor()
    cursor.execute("DELETE FROM user_certificates WHERE id = %s AND user_id = %s", (cert_id, current_user.id))
    mysql.commit()
    return '', 204

@app.route('/save_skill', methods=['POST'])
def save_skill():
    user_id = current_user.id
    if not user_id:
        return redirect('/login')  

    data = request.get_json()
    skills = data.get('skills', [])
    languages = data.get('languages', [])
    industries = data.get('industries', [])
    interest = data.get('interest', '')
    reference = data.get('reference', '')

    with mysql.cursor() as cursor:
        
        cursor.execute("DELETE FROM skills WHERE user_id=%s", (user_id,))
        cursor.execute("DELETE FROM languages WHERE user_id=%s", (user_id,))
        cursor.execute("DELETE FROM industries WHERE user_id=%s", (user_id,))
        cursor.execute("DELETE FROM interests WHERE user_id=%s", (user_id,))
        cursor.execute("DELETE FROM user_references WHERE user_id=%s", (user_id,))

        
        for skill in skills:
            cursor.execute("INSERT INTO skills (user_id, skill_name, skill_level) VALUES (%s, %s, %s)",
                           (user_id, skill['name'], skill['level']))

        
        for lang in languages:
            cursor.execute("INSERT INTO languages (user_id, language_name, language_level) VALUES (%s, %s, %s)",
                           (user_id, lang['name'], lang['level']))

        
        for ind in industries:
            cursor.execute("INSERT INTO industries (user_id, industry_name) VALUES (%s, %s)",
                           (user_id, ind))

        
        if interest:
            cursor.execute("INSERT INTO interests (user_id, interest_text) VALUES (%s, %s)", (user_id, interest))

        
        if reference:
            cursor.execute("INSERT INTO user_references (user_id, reference_text) VALUES (%s, %s)", (user_id, reference))

    mysql.commit()
    return jsonify({'status': 'success'})

@app.route('/save_education', methods=['POST'])
@login_required
def save_education():
    edu_id = request.form.get('edu_id')
    institution = request.form['institution']
    location = request.form['location']
    degree = request.form['degree']
    field_of_study = request.form['field_of_study']
    start_date = request.form['start_date']
    end_date = request.form['end_date']
    description = request.form['description']
    user_id = current_user.id

    cursor = mysql.cursor()

    if edu_id:
        
        query = """
            UPDATE user_education
            SET institution=%s, location=%s, degree=%s, field_of_study=%s,
                start_date=%s, end_date=%s, description=%s
            WHERE id=%s AND user_id=%s
        """
        cursor.execute(query, (institution, location, degree, field_of_study,
                               start_date, end_date, description, edu_id, user_id))
    else:
        
        query = """
            INSERT INTO user_education (user_id, institution, location, degree, field_of_study,
                                        start_date, end_date, description)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query, (user_id, institution, location, degree, field_of_study,
                               start_date, end_date, description))

    mysql.commit()
    return redirect(url_for('profile', tab='education_new'))
@app.route('/delete_education/<int:edu_id>', methods=['POST'])
@login_required
def delete_education(edu_id):
    cursor = mysql.cursor()
    cursor.execute("DELETE FROM user_education WHERE id = %s AND user_id = %s", (edu_id, current_user.id))
    mysql.commit()
    return '', 204  
@app.route('/save_experience', methods=['POST'])
@login_required
def save_experience():
    exp_id = request.form.get('exp_id')
    company = request.form['company']
    position = request.form['position']
    location = request.form['location']
    start_date = request.form['start_date']
    end_date = request.form['end_date']
    description = request.form['description']
    user_id = current_user.id

    cursor = mysql.cursor()

    if exp_id:
        query = """
            UPDATE user_experience
            SET company=%s, position=%s, location=%s,
                start_date=%s, end_date=%s, description=%s
            WHERE id=%s AND user_id=%s
        """
        cursor.execute(query, (company, position, location, start_date, end_date, description, exp_id, user_id))
    else:
        query = """
            INSERT INTO user_experience (user_id, company, position, location,
                                         start_date, end_date, description)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query, (user_id, company, position, location, start_date, end_date, description))

    mysql.commit()
    return redirect(url_for('profile', tab='experience'))

@app.route('/delete_experience/<int:exp_id>', methods=['POST'])
@login_required
def delete_experience(exp_id):
    cursor = mysql.cursor()
    cursor.execute("DELETE FROM user_experience WHERE id = %s AND user_id = %s", (exp_id, current_user.id))
    mysql.commit()
    return '', 204
# admin dashboard
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if not session.get('admin'):
        abort(403)

    cur = mysql.cursor(pymysql.cursors.DictCursor)

    
    cur.execute("SELECT * FROM jobs")
    jobs = cur.fetchall()

    
    cur.execute("""
    SELECT j.id AS job_id, j.job_name, j.job_type, j.company_name,
           a.first_name, a.last_name, a.email, a.phone, a.action_type,
           a.cv_text, a.cv_file
    FROM job_user_actions a
    JOIN jobs j ON a.job_id = j.id
    WHERE a.action_type = 'apply'
""")
    applied_jobs = cur.fetchall()


    cur.execute("""
    SELECT j.id AS job_id, j.job_name, j.job_type, j.company_name,
           a.first_name, a.last_name, a.email, a.phone, a.action_type,
           a.cv_text, a.cv_file
    FROM job_user_actions a
    JOIN jobs j ON a.job_id = j.id
    WHERE a.action_type = 'save'
""")
    saved_jobs = cur.fetchall()
    
    for job in jobs:
        job['status'] = []
        if any(job['id'] == aj['job_id'] for aj in applied_jobs):
            job['status'].append('Applied')
        if any(job['id'] == sj['job_id'] for sj in saved_jobs):
            job['status'].append('Saved')
    
    cur.execute("SELECT * FROM users")
    users = cur.fetchall()
    cur.close()
    
    return render_template(
        'admin.html',
        jobs=jobs,
        applied_jobs=applied_jobs,
        saved_jobs=saved_jobs,
        users=users
    )


@app.route('/add_jobs', methods=['POST'])
@login_required
def add_jobs():
    if not session.get('admin'):
        abort(403)  

    job_name = request.form['job_name']
    job_type = request.form['job_type']
    company_name = request.form['company_name']
    job_description = request.form['job_description']
    skills = request.form['skills']
    cur = mysql.cursor()
    cur.execute("""
        INSERT INTO jobs (job_name, job_type, company_name, job_description, skills)
        VALUES (%s, %s, %s, %s, %s)
    """, (job_name, job_type, company_name, job_description, skills))
    mysql.commit()
    cur.close()
    
    flash('Job added successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/edit_jobs/<int:job_id>', methods=['GET', 'POST'])
@login_required
def edit_jobs(job_id):
    if not session.get('admin'):
        abort(403)

    cur = mysql.cursor()

    if request.method == 'POST':
        job_name = request.form['job_name']
        company_name = request.form['company_name']
        job_type = request.form['job_type']
        job_description = request.form['job_description']
        skills = request.form.get('skills', '')
        cur.execute("""
            UPDATE jobs SET 
                job_name = %s, 
                company_name = %s, 
                job_type = %s, 
                job_description = %s,
                skills = %s
            WHERE id = %s
        """, (job_name, company_name, job_type, job_description,skills, job_id))
        mysql.commit()
        cur.close()

        flash("Job updated successfully!", "success")
        return redirect(url_for('admin_dashboard'))

    cur.execute("SELECT * FROM jobs WHERE id = %s", (job_id,))
    job = cur.fetchone()
    cur.close()

    return render_template('edit_job.html', job=job)
@app.route('/admin/view_job/<int:job_id>')
@login_required
def admin_view_job(job_id):
    if not session.get('admin'):  
        abort(403)

    cur = mysql.cursor(pymysql.cursors.DictCursor)
    cur.execute("SELECT * FROM jobs WHERE id = %s", (job_id,))
    job = cur.fetchone()
    cur.close()

    if not job:
        flash("Job not found", "danger")
        return redirect(url_for('admin_dashboard'))

    return render_template('admin_view_job.html', job=job)
@app.route('/delete_jobs/<int:job_id>', methods=['POST'])
@login_required
def delete_jobs(job_id):
    if not session.get('admin'):
        abort(403)

    cur = mysql.cursor()
    cur.execute("DELETE FROM jobs WHERE id = %s", (job_id,))
    mysql.commit()
    cur.close()

    flash("Job deleted successfully!", "info")
    return redirect(url_for('admin_dashboard'))
@app.route('/find_jobs')
@login_required
def find_jobs():
    try:
        cur = mysql.cursor(pymysql.cursors.DictCursor)
        
        # Fetch jobs
        cur.execute("SELECT * FROM jobs")
        jobs = cur.fetchall()

        # Fetch current user's CV data
        cur.execute("SELECT cv_text, cv_file FROM users WHERE id = %s", (current_user.id,))
        user_cv = cur.fetchone()
        
        cur.close()

        return render_template('find_jobs.html', jobs=jobs, user_cv=user_cv)

    except Exception as e:
        print(f"Error fetching jobs or user CV data: {e}")
        flash(f"An error occurred while fetching jobs: {e}", "danger")
        return render_template('find_jobs.html', jobs=[], user_cv=None)
@app.route('/get_latest_cv')
@login_required
def get_latest_cv():
    try:
        cur = mysql.cursor(pymysql.cursors.DictCursor)
        # Get the latest CV data from job_user_actions
        cur.execute("""
            SELECT cv_text, cv_file FROM job_user_actions 
            WHERE user_id = %s 
            ORDER BY id DESC LIMIT 1
        """, (current_user.id,))
        cv_data = cur.fetchone()
        cur.close()
        
        return jsonify({
            'cv_text': cv_data['cv_text'] if cv_data else None,
            'cv_file': cv_data['cv_file'] if cv_data else None
        })
    except Exception as e:
        print(f"Error fetching CV data: {e}")
        return jsonify({'error': str(e)}), 500
@app.route('/apply_or_save_job/<int:job_id>/<string:action>', methods=['POST'])
@login_required  
def apply_or_save_job(job_id, action):
    try:
        user = current_user  
        cur = mysql.cursor(pymysql.cursors.DictCursor)  
 
        # Get the latest CV data
        cur.execute("""
            SELECT cv_text, cv_file FROM job_user_actions
            WHERE user_id = %s
            ORDER BY id DESC LIMIT 1
        """, (user.id,))
        last_cv = cur.fetchone()
 
        cv_text = None
        cv_file = None
 
        if action == 'apply':
            cv_choice = request.form.get('cv_choice')  
 
            if cv_choice == 'text' and last_cv and last_cv['cv_text']:
                cv_text = last_cv['cv_text']
            elif cv_choice == 'file' and last_cv and last_cv['cv_file']:
                cv_file = last_cv['cv_file']
            elif cv_choice == 'none':
                pass  # No CV will be attached
            else:
                flash("Invalid CV selection.", "danger")
                return redirect(url_for('find_jobs'))
 
        # Update job status
        if action == 'apply':
            cur.execute("UPDATE jobs SET status = 'Applied' WHERE id = %s", (job_id,))
        elif action == 'save':
            cur.execute("UPDATE jobs SET status = 'Saved' WHERE id = %s", (job_id,))
 
        # Insert into job_user_actions
        cur.execute("""
            INSERT INTO job_user_actions
            (user_id, job_id, action_type, first_name, last_name, email, phone, cv_text, cv_file)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            user.id, job_id, action,
            user.first_name, user.last_name, user.email, user.phone,
            cv_text, cv_file
        ))
 
        mysql.commit()
        cur.close()
        flash(f"Job {action.title()}ed successfully!", "success")
        return redirect(url_for('applications'))
 
    except Exception as e:
        print(f"Error: {e}")
        flash(f"An error occurred: {e}", "danger")
        return redirect(url_for('find_jobs'))


#user dashboard
# @app.route('/apply_or_save_job/<int:job_id>/<string:action>', methods=['POST'])
# @login_required  
# def apply_or_save_job(job_id, action):
#     try:
#         user = current_user  
#         cur = mysql.cursor()

        
#         if action == 'apply':
#             cur.execute("UPDATE jobs SET status = 'Applied' WHERE id = %s", (job_id,))
#         elif action == 'save':
#             cur.execute("UPDATE jobs SET status = 'Saved' WHERE id = %s", (job_id,))

#         # Insert into job_user_actions table
#         cur.execute("""
#             INSERT INTO job_user_actions (user_id, job_id, action_type, first_name, last_name, email, phone)
#             VALUES (%s, %s, %s, %s, %s, %s, %s)
#         """, (
#             user.id,
#             job_id,
#             action,
#             user.first_name,
#             user.last_name,
#             user.email,
#             user.phone
#         ))

#         mysql.commit()
#         cur.close()
#         flash(f"Job {action.title()}ed successfully!", "success")
#         return redirect(url_for('applications'))  # Redirect to applications or wherever

#     except Exception as e:
#         print(f"Error: {e}")
#         flash(f"An error occurred: {e}", "danger")
#         return redirect(url_for('find_jobs'))
#user dashboard
#user dashboard
# @app.route('/apply_or_save_job/<int:job_id>/<string:action>', methods=['POST'])
# @login_required  
# def apply_or_save_job(job_id, action):
#     try:
#         user = current_user  
#         cur = mysql.cursor()

        
#         if action == 'apply':
#             cur.execute("UPDATE jobs SET status = 'Applied' WHERE id = %s", (job_id,))
#         elif action == 'save':
#             cur.execute("UPDATE jobs SET status = 'Saved' WHERE id = %s", (job_id,))

#         # Insert into job_user_actions table
#         cur.execute("""
#             INSERT INTO job_user_actions (user_id, job_id, action_type, first_name, last_name, email, phone)
#             VALUES (%s, %s, %s, %s, %s, %s, %s)
#         """, (
#             user.id,
#             job_id,
#             action,
#             user.first_name,
#             user.last_name,
#             user.email,
#             user.phone
#         ))

#         mysql.commit()
#         cur.close()
#         flash(f"Job {action.title()}ed successfully!", "success")
#         return redirect(url_for('applications'))  # Redirect to applications or wherever

#     except Exception as e:
#         print(f"Error: {e}")
#         flash(f"An error occurred: {e}", "danger")
#         return redirect(url_for('find_jobs'))
# @app.route('/apply_or_save_job/<int:job_id>/<string:action>', methods=['POST'])
# def apply_or_save_job(job_id, action):
#     try:
#         cur = mysql.cursor()

#         if action == 'apply':
#             # Update job status and store user info in the jobs table
#             user = current_user
#             cur.execute("""
#                 UPDATE jobs 
#                 SET status = 'Applied',
#                     first_name = %s,
#                     last_name = %s,
#                     email = %s,
#                     phone = %s
#                 WHERE id = %s
#             """, (user.first_name, user.last_name, user.email, user.phone, job_id))

#         elif action == 'save':
#             cur.execute("UPDATE jobs SET status = 'Saved' WHERE id = %s", (job_id,))

#         mysql.commit()
#         cur.close()
#         return redirect(url_for('applications'))

#     except Exception as e:
#         print(f"Error updating job status: {e}")
#         flash(f"An error occurred while updating the job status: {e}", "danger")
#         return redirect(url_for('find_jobs'))
# @app.route('/apply_or_save_job/<int:job_id>/<string:action>', methods=['POST'])
# def apply_or_save_job(job_id, action):
#     try:
#         cur = mysql.cursor()
#         user = current_user

#         if action == 'apply':
#             # Insert application info instead of updating the job
#             cur.execute("""
#                 INSERT INTO job_applications (user_id, job_id, status, first_name, last_name, email, phone)
#                 VALUES (%s, %s, 'Applied', %s, %s, %s, %s)
#             """, (user.id, job_id, user.first_name, user.last_name, user.email, user.phone))

#         elif action == 'save':
#             # You could also log "Saved" in this same table or another if needed
#             cur.execute("""
#                 INSERT INTO job_applications (user_id, job_id, status, first_name, last_name, email, phone)
#                 VALUES (%s, %s, 'Saved', %s, %s, %s, %s)
#             """, (user.id, job_id, user.first_name, user.last_name, user.email, user.phone))

#         mysql.commit()
#         cur.close()
#         return redirect(url_for('applications'))

#     except Exception as e:
#         print(f"Error updating job status: {e}")
#         flash(f"An error occurred while updating the job status: {e}", "danger")
#         return redirect(url_for('find_jobs'))
# @app.route('/admin/applied-jobs')
# def admin_applied_jobs():
#     try:
#         cur = mysql.cursor(dictionary=True)  # So results come as dicts
#         cur.execute("""
#             SELECT 
#                 ja.id,
#                 j.title AS job_title,
#                 j.type AS job_type,
#                 j.company_name,
#                 ja.status,
#                 ja.first_name,
#                 ja.last_name,
#                 ja.email,
#                 ja.phone
#             FROM job_applications ja
#             JOIN jobs j ON ja.job_id = j.id
#             ORDER BY ja.applied_at DESC
#             LIMIT 0, 25
#         """)
#         applications = cur.fetchall()
#         cur.close()

#         return render_template('admin_applied_jobs.html', applications=applications)

#     except Exception as e:
#         print(f"Error loading applied jobs: {e}")
#         flash("Failed to load applied jobs.", "danger")
#         return redirect(url_for('admin_dashboard'))

@app.route('/add_job', methods=['POST'])
@login_required
def add_job():
    job_name = request.form['job_name']
    job_type = request.form['job_type']
    company_name = request.form['company_name']
    job_description = request.form['job_description']
    skills = request.form['skills']
    cur = mysql.cursor()
    cur.execute("""
        INSERT INTO jobs (job_name, job_type, company_name, job_description,skills, user_id)
        VALUES (%s, %s, %s, %s, %s)
    """, (job_name, job_type, company_name, job_description, skills, current_user.id))
    mysql.commit()
    cur.close()

    return redirect(url_for('profile', tab='applications'))

@app.route('/view_job/<int:job_id>')
def view_job(job_id):
    try:
        with mysql.cursor() as cursor:
            cursor.execute("SELECT * FROM jobs WHERE id = %s", (job_id,))
            job = cursor.fetchone()
            if not job:
                abort(404)
        return render_template('view_job.html', job=job)
    except Exception as e:
        print("Error fetching job:", e)
        abort(500)

@app.route('/job/<int:job_id>/save', methods=['POST'])
@login_required
def save_job(job_id):
    cur = mysql.cursor()
    cur.execute("UPDATE jobs SET status = %s WHERE id = %s AND user_id = %s", ('saved', job_id, current_user.id))
    mysql.commit()
    cur.close()
    flash('Job saved successfully!', 'info')
    return redirect(url_for('profile', tab='applications'))

@app.route('/job/<int:job_id>/apply', methods=['POST'])
@login_required
def apply_job(job_id):
    cur = mysql.cursor()
    cur.execute("UPDATE jobs SET status = %s WHERE id = %s AND user_id = %s", ('applied', job_id, current_user.id))
    mysql.commit()
    cur.close()
    flash('You have successfully applied for the job!', 'success')
    return redirect(url_for('profile', tab='applications'))

@app.route('/edit_job/<int:job_id>', methods=['GET', 'POST'])
@login_required
def edit_job(job_id):
    cur = mysql.cursor()

    if request.method == 'POST':
        job_name = request.form['job_name']
        company_name = request.form['company_name']
        job_type = request.form['job_type']
        job_description = request.form['job_description']
        skills = request.form['skills']
        cur.execute("""
            UPDATE jobs SET 
                job_name = %s, 
                company_name = %s, 
                job_type = %s, 
                job_description = %s,
                skills = %s
            WHERE id = %s AND user_id = %s
        """, (job_name, company_name, job_type, job_description,skills, job_id, current_user.id))
        mysql.commit()
        cur.close()
        flash("Job updated successfully!", "success")
        return redirect(url_for('profile', tab='applications'))  

    
    cur.execute("SELECT * FROM jobs WHERE id = %s AND user_id = %s", (job_id, current_user.id))
    job = cur.fetchone()
    cur.close()

    if not job:
        flash("Job not found or access denied", "danger")
        return redirect(url_for('profile', tab='applications'))

    return render_template('edit_job.html', job=job)

@app.route('/delete_job/<int:job_id>', methods=['POST'])
@login_required
def delete_job(job_id):
    cur = mysql.cursor()
    cur.execute("DELETE FROM jobs WHERE id = %s", (job_id,))
    mysql.commit()
    cur.close()
    flash("Job deleted successfully!", "info")
    return redirect(url_for('profile', tab='applications'))
# @app.route('/find_jobs')
# def find_jobs():
#     try:
#         cur = mysql.cursor(pymysql.cursors.DictCursor)  # return rows as dict
#         cur.execute("SELECT * FROM jobs")
#         jobs = cur.fetchall()
#         cur.close()
#         return render_template('find_jobs.html', jobs=jobs)
#     except Exception as e:
#         print(f"Error fetching jobs: {e}")
#         flash(f"An error occurred while fetching jobs: {e}", "danger")
#         return render_template('find_jobs.html', jobs=[])

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        phone = request.form['phone']
        address = request.form['address']

        cur = mysql.cursor()
        try:
            cur.execute(""" 
                UPDATE users 
                SET first_name = %s, last_name = %s, phone = %s, address = %s
                WHERE id = %s
            """, (first_name, last_name, phone, address, current_user.id))
            mysql.commit()
            flash('Profile updated successfully!', 'success')
        except Exception as e:
            flash(f'Error updating profile: {str(e)}', 'danger')
        finally:
            cur.close()

    return redirect(url_for('profile'))
@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if 'file' not in request.files:
        return "No file part", 400
    
    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400
    
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    
    file_size = round(os.path.getsize(filepath) / (1024 * 1024), 2)  
    upload_date = datetime.now().strftime('%Y-%m-%d')

    
    conn = mysql
    cur = conn.cursor()
    cur.execute(""" 
        INSERT INTO documents (name, type, size, upload_date, user_id) 
        VALUES (%s, %s, %s, %s, %s)
    """, (filename, 'PDF', file_size, upload_date, current_user.id))
    conn.commit()
    cur.close()

    return redirect(url_for('profile', tab='documents'))

@app.route('/delete/<filename>', methods=['DELETE'])
def delete_file(filename):
    try:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        if os.path.exists(file_path):
            os.remove(file_path)

            
            cur = mysql.cursor()
            cur.execute("DELETE FROM documents WHERE name = %s", (filename,))
            mysql.commit()
            cur.close()

            return jsonify({'message': 'File deleted successfully'}), 200
        else:
            return jsonify({'message': 'File not found'}), 404
    except Exception as e:
        return jsonify({'message': str(e)}), 500
@app.route('/download/<filename>')
def download_file(filename):
    try:
        
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    except FileNotFoundError:
        abort(404)  
@app.route('/view/<filename>')
def view_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
