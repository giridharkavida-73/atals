from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'super_secret_key_for_dashboard_session'

DB_FILE = 'users.db'

def init_db():
    """Initializes the local SQLite database and structures the user mapping schema."""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        ''')
        conn.commit()

@app.route('/')
def index():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles secure workspace user authentication and routing."""
    if 'user' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT password_hash FROM users WHERE email = ?", (email,))
            user = cursor.fetchone()
            
        if user and check_password_hash(user[0], password):
            session['user'] = email
            return redirect(url_for('dashboard'))
            
        flash("Invalid email or password.")
        
    return render_template('auth.html', title="Sign In to Atlas", button_text="Sign In", is_login_page=True)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles secure new user registration."""
    if 'user' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        if not email or not password:
            flash("All fields are required.")
            return redirect(url_for('register'))
        
        try:
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", 
                               (email, generate_password_hash(password)))
                conn.commit()
            flash("Account created successfully! Please log in.")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("This email is already registered.")
            
    return render_template('auth.html', title="Create Your Account", button_text="Create Account", is_login_page=False)

@app.route('/dashboard')
def dashboard():
    """Renders the secure main workstation interface."""
    if 'user' not in session:
        flash("Please log in to access the dashboard.")
        return redirect(url_for('login'))
    return render_template('dashboard.html', user=session['user'])

@app.route('/logout')
def logout():
    """Clears session and redirects to login."""
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)
