from flask import Flask, request, redirect, url_for, send_from_directory, session, abort, render_template, flash
from flask_mysqldb import MySQL
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash
import MySQLdb.cursors
import MySQLdb
import re

app = Flask(__name__)
app.secret_key = "yoursecretkey"

# ---------------- MySQL Config ----------------
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'racism'
mysql = MySQL(app)

# ---------------- Email Config ----------------
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'iatechnologies45@gmail.com'
app.config['MAIL_PASSWORD'] = 'vztgwznvieoatnnk'
mail = Mail(app)

serializer = URLSafeTimedSerializer(app.secret_key)

# ---------------- Serve static templates ----------------
@app.route('/')
def index():
    return redirect('/login.html')

@app.route('/<path:filename>')
def static_files(filename):
    return send_from_directory('templates', filename)

# ---------------- Registration ----------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return send_from_directory('templates', 'register.html')

    # POST
    username = request.form['username'].strip()
    email = request.form['email'].strip().lower()
    raw_password = request.form['password']
    dob = request.form['date_of_birth']
    gender = request.form['gender']

    # Password validation
    if len(raw_password) < 8:
        return "Password must be at least 8 characters long.", 400
    if not re.search(r'[A-Z]', raw_password):
        return "Password must contain at least one uppercase letter.", 400
    if not re.search(r'[^A-Za-z0-9]', raw_password):
        return "Password must contain at least one unique symbol.", 400

    password_hash = generate_password_hash(raw_password)
    token = serializer.dumps(email, salt='email-confirm')

    conn = mysql.connection
    cur = conn.cursor()
    try:
        # Check if email already exists
        cur.execute("SELECT id FROM users WHERE email=%s", (email,))
        if cur.fetchone():
            return "Email already registered.", 400

        cur.execute("""
            INSERT INTO users
            (username, email, password_hash, date_of_birth, gender,
             verification_token, registered_at, is_verified)
            VALUES (%s, %s, %s, %s, %s, %s, NOW(), 0)
        """, (username, email, password_hash, dob, gender, token))
        conn.commit()
    finally:
        cur.close()

    # Send verification email
    confirm_url = url_for('confirm_email', token=token, _external=True)
    msg = Message("Confirm Your Account", sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.html = f"""
    <div style="font-family:Arial,sans-serif">
      <h2>No Room for Racism</h2>
      <p>Hi <b>{username}</b>, please confirm your account:</p>
      <p><a href="{confirm_url}" style="background:#000;color:#ffd500;padding:10px 16px;border-radius:6px;text-decoration:none;">Confirm my email</a></p>
      <p style="color:#555">If you didn’t create this account, ignore this email.</p>
    </div>
    """
    mail.send(msg)

    return render_template("confirmation_pending.html", email=email)

# ---------------- Email confirmation ----------------
@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=3600)
    except (BadSignature, SignatureExpired):
        return render_template("confirmation_failed.html")

    cur = mysql.connection.cursor()
    try:
        cur.execute("UPDATE users SET is_verified=1, verification_token=NULL WHERE email=%s", (email,))
        mysql.connection.commit()
    finally:
        cur.close()

    return render_template("confirmation_success.html")

# ---------------- Login ----------------
@app.route('/login', methods=['POST'])
def login():
    username_email = request.form['username_email'].strip()
    password = request.form['password']

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        cur.execute("""
            SELECT * FROM users
            WHERE username=%s OR LOWER(email)=%s
        """, (username_email, username_email.lower()))
        user = cur.fetchone()
    finally:
        cur.close()

    if not user:
        return "Invalid credentials.", 401
    if not check_password_hash(user['password_hash'], password):
        return "Invalid credentials.", 401
    if not user['is_verified']:
        return "Please verify your email before logging in.", 403

    # Set session
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['is_admin'] = int(user.get('is_admin', 0))

    return redirect('/dashboard')

# ---------------- Dashboard ----------------
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login.html')
    return render_template('dashboard.html', username=session['username'])

# ---------------- User Details ----------------
@app.route('/details')
def details():
    if 'user_id' not in session:
        return redirect('/login.html')
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        cur.execute("SELECT username, email, date_of_birth, gender FROM users WHERE id=%s", (session['user_id'],))
        user = cur.fetchone()
    finally:
        cur.close()
    return render_template('details.html', user=user)

# ---------------- Update Details ----------------
@app.route('/update_details', methods=['GET', 'POST'])
def update_details():
    if 'user_id' not in session:
        return redirect('/login.html')
    if request.method == 'GET':
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        try:
            cur.execute("SELECT username, date_of_birth, gender FROM users WHERE id=%s", (session['user_id'],))
            user = cur.fetchone()
        finally:
            cur.close()
        return render_template('update_details.html', user=user)

    new_username = request.form['username'].strip()
    new_dob = request.form['date_of_birth']
    new_gender = request.form['gender']

    cur = mysql.connection.cursor()
    try:
        cur.execute("""
            UPDATE users
            SET username=%s, date_of_birth=%s, gender=%s
            WHERE id=%s
        """, (new_username, new_dob, new_gender, session['user_id']))
        mysql.connection.commit()
        session['username'] = new_username
    finally:
        cur.close()
    flash("Details updated successfully!", "success")
    return redirect('/details')

# ---------------- Others ----------------
@app.route('/others')
def others():
    if 'user_id' not in session:
        return redirect('/login.html')
    return render_template('others.html')

# ---------------- Logout ----------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login.html')

if __name__ == '__main__':
    app.run(debug=True)
