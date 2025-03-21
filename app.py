from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
import MySQLdb.cursors
from flask_bcrypt import Bcrypt

app = Flask(__name__)

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'new_password'
app.config['MYSQL_DB'] = 'Lab6'
app.secret_key = 'your_secret_key'

mysql = MySQL(app)
bcrypt = Bcrypt(app)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        # Hash the password before storing it
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        cur = mysql.connection.cursor()
        try:
            cur.execute("INSERT INTO users (username, password, email) VALUES (%s, %s, %s)", 
                        (username, hashed_password, email))
            mysql.connection.commit()
            flash('Registration successful! Please login.', 'success')
        except MySQLdb.IntegrityError:
            flash('Username or email already exists!', 'danger')
        finally:
            cur.close()

        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()

        print("User fetched from database:", user)  # Debug print
        if user:
            print("Stored password hash:", user['password'])  # Debug print
            print("Password verification result:", bcrypt.check_password_hash(user['password'], password))  # Debug print

        if user and bcrypt.check_password_hash(user['password'], password):
            session['user_id'] = user['id']  # Store user ID in session
            print("Session after login:", session)  # Debug print
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    print("Session in dashboard:", session)  # Debug print
    if 'user_id' not in session:  # Check if the user is logged in
        flash('Please log in first!', 'warning')
        return redirect(url_for('login'))

    # Fetch the logged-in user's details
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT username FROM users WHERE id = %s", (session['user_id'],))
    user = cur.fetchone()
    cur.close()

    if user:
        username = user['username']
    else:
        flash('User not found!', 'danger')
        return redirect(url_for('login'))

    # Render the dashboard template with the username
    return render_template('dashboard.html', username=username)

@app.route('/update_profile', methods=['GET', 'POST'])
def update_profile():
    if 'user_id' not in session:
        flash('Please log in first!', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_username = request.form['username']
        new_email = request.form['email']

        cur = mysql.connection.cursor()
        try:
            cur.execute("UPDATE users SET username = %s, email = %s WHERE id = %s", 
                        (new_username, new_email, session['user_id']))
            mysql.connection.commit()
            flash('Profile updated successfully!', 'success')
        except MySQLdb.IntegrityError:
            flash('Username or email already exists!', 'danger')
        finally:
            cur.close()

        return redirect(url_for('dashboard'))

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT username, email FROM users WHERE id = %s", (session['user_id'],))
    user = cur.fetchone()
    cur.close()

    return render_template('update_profile.html', user=user)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'user_id' not in session:
        flash('Please log in first!', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("SELECT password FROM users WHERE id = %s", (session['user_id'],))
        user = cur.fetchone()
        cur.close()

        if user and bcrypt.check_password_hash(user['password'], current_password):
            if new_password == confirm_password:
                hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                cur = mysql.connection.cursor()
                cur.execute("UPDATE users SET password = %s WHERE id = %s", 
                            (hashed_password, session['user_id']))
                mysql.connection.commit()
                cur.close()
                flash('Password updated successfully!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('New passwords do not match!', 'danger')
        else:
            flash('Current password is incorrect!', 'danger')

    return render_template('reset_password.html')

@app.route('/grades')
def grades():
    if 'user_id' not in session:  # Check if the user is logged in
        flash('Please log in first!', 'warning')
        return redirect(url_for('login'))

    # Fetch grades for the logged-in user
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM grades WHERE user_id = %s", (session['user_id'],))
    grades = cur.fetchall()
    cur.close()

    # Render the grades template with the fetched data
    return render_template('grades.html', grades=grades)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)