import os
from datetime import date
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import re 


# ======================
# Flask App Config
# ======================
app = Flask(__name__)
app.secret_key = "supersecretkey"

# ======================
# MySQL Configuration
# ======================
from urllib.parse import urlparse
import os
from dotenv import load_dotenv

load_dotenv()

db_url = os.getenv('DATABASE_URL')
if db_url:
    url = urlparse(db_url)
    app.config['MYSQL_HOST'] = url.hostname
    app.config['MYSQL_USER'] = url.username
    app.config['MYSQL_PASSWORD'] = url.password
    app.config['MYSQL_DB'] = url.path.lstrip('/')
    app.config['MYSQL_PORT'] = url.port or 3306
else:
    # fallback to local .env
    app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
    app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
    app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
    app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')
    app.config['MYSQL_PORT'] = int(os.getenv('MYSQL_PORT', 3306))

app.config['MYSQL_CHARSET'] = 'utf8mb4'

mysql = MySQL(app)


# ======================
# Activity Log 
# ======================
def log_activity(user_id, action, item_id=None, details=None):
    cur = mysql.connection.cursor()
    cur.execute("""
        INSERT INTO activity_log (user_id, action, item_id, details)
        VALUES (%s, %s, %s, %s)
    """, (user_id, action, item_id, details))
    mysql.connection.commit()
    cur.close()

# ======================
# Upload Folder
# ======================
UPLOAD_FOLDER = os.path.join(os.getcwd(), "static/uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# ======================
# Route
# ======================
@app.route('/')
def index():
    # Redirect straight to home or login
    if 'user_id' in session:
        return redirect(url_for('home'))
    else:
        return redirect(url_for('login'))

# ======================
# Home Page
# ======================
@app.route('/home')
def home():
    if 'user_id' in session:
        cur = mysql.connection.cursor()

        # Fetch unread notifications
        cur.execute("""
            SELECT id, message FROM notifications
            WHERE user_id = %s AND is_read = 0
        """, (session['user_id'],))
        notes = cur.fetchall()

        # Flash each unread notification
        for note in notes:
            flash(note[1], 'success')
            cur.execute("UPDATE notifications SET is_read = 1 WHERE id = %s", (note[0],))

        mysql.connection.commit()
        cur.close()

    return render_template('home.html')






# ======================
# Register
# ======================
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']

        # Email restriction (UTP only)
        if not email.endswith('@utp.edu.my'):
            flash('Registration only allowed for UTP community members.', 'error')
            return redirect(url_for('register'))

        # Password validation: min 8 chars, 1 upper, 1 lower, 1 number, 1 symbol
        pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).{8,}$'
        if not re.match(pattern, password):
            flash('Password must be at least 8 characters long and include 1 uppercase, 1 lowercase, 1 number, and 1 symbol.', 'error')
            return redirect(url_for('register'))


        # Check if email already exists
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        existing_user = cur.fetchone()
        if existing_user:
            flash('This email is already registered.', 'error')
            cur.close()
            return redirect(url_for('login'))

        # Hash password before saving
        hashed_pw = generate_password_hash(password)
        cur.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", (name, email, hashed_pw))
        mysql.connection.commit()
        cur.close()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')



# ======================
# Login
# ======================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()

        if user and check_password_hash(user[3], password):
            session['user_id'] = user[0]
            session['name'] = user[1]
            session['is_admin'] = user[4]
            flash(f"Welcome back, {user[1]}!", "info")

            if session.get('is_admin') == 1:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('home'))
        else:
            flash("Invalid email or password.", "error")

    return render_template('login.html')



# ======================
# Admin Access Decorator
# ======================
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('is_admin') != 1:
            flash("Access denied. Admins only.", "error")
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function


# ======================
# Admin Pages
# ======================
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    return render_template('admin/dashboard.html')


@app.route('/admin/users')
@admin_required
def admin_users():
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, name, email, is_admin FROM users")
    users = cur.fetchall()
    cur.close()
    return render_template('admin/users.html', users=users)


@app.route('/admin/set_admin/<int:user_id>', methods=['POST'])
@admin_required
def admin_set_admin(user_id):
    cur = mysql.connection.cursor()
    cur.execute("UPDATE users SET is_admin = 1 WHERE id = %s", (user_id,))
    mysql.connection.commit()
    cur.close()
    flash("User promoted to admin!", "success")
    return redirect(url_for('admin_users'))


@app.route('/admin/items')
@admin_required
def admin_items():
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT i.id, i.item_name, i.description, i.location, i.date_reported,
               i.photo, i.status, u.name, i.user_id
        FROM items i
        JOIN users u ON i.user_id = u.id
        ORDER BY i.date_reported DESC
    """)
    items = cur.fetchall()
    cur.close()
    return render_template('admin/items.html', items=items)

@app.route('/admin/items/<int:item_id>/delete', methods=['POST'])
@admin_required
def admin_delete_item(item_id):
    cur = mysql.connection.cursor()

    # Delete activity logs tied to this item first
    cur.execute("DELETE FROM activity_log WHERE item_id = %s", (item_id,))

    # Then delete the item itself
    cur.execute("DELETE FROM items WHERE id = %s", (item_id,))
    mysql.connection.commit()
    cur.close()

    flash("🗑️ Item and related logs deleted successfully!", "info")
    return redirect(url_for('admin_items'))




@app.route('/admin/claims')
@admin_required
def admin_claims():
    cur = mysql.connection.cursor()

    # ✅ Include all claims — pending, approved, and rejected
    cur.execute("""
        SELECT 
            id, item_name, description, location, date_reported,
            user_id, claimed_by, security_question, user_answer,
            claim_status, contact_number, utp_email, proof_photo
        FROM items
        WHERE claim_status IN ('pending', 'approved', 'rejected')
        ORDER BY FIELD(claim_status, 'pending', 'approved', 'rejected'),
                date_reported DESC
    """)





    
    claims = cur.fetchall()
    cur.close()

    return render_template('admin/claims.html', claims=claims)



@app.route('/admin/approve/<int:item_id>', methods=['POST'])
@admin_required
def admin_claim_approve(item_id):
    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT claimed_by, contact_number, utp_email
        FROM items
        WHERE id = %s
    """, (item_id,))
    result = cur.fetchone()

    if not result:
        flash("Item not found.", "error")
        cur.close()
        return redirect(url_for('admin_claims'))

    claimed_by, contact_number, utp_email = result

    if not claimed_by:
        flash("No claimer found for this item.", "warning")
        cur.close()
        return redirect(url_for('admin_claims'))

    cur.execute("""
        UPDATE items 
        SET claim_status = 'approved', status = 'claimed'
        WHERE id = %s
    """, (item_id,))

    message = (
        f"✅ Your claim has been approved!\n"
        f"Finder Contact: {contact_number}\n"
        f"Finder Email: {utp_email}"
    )

    cur.execute("""
        INSERT INTO notifications (user_id, message, is_read)
        VALUES (%s, %s, 0)
    """, (claimed_by, message))
    mysql.connection.commit()

    # ✅ Log admin approval
    log_activity(
        session['user_id'],
        "Approved Claim",
        item_id,
        f"Admin {session.get('name')} approved claim for item ID {item_id}."
    )

    cur.close()
    flash("✅ Claim approved and user notified!", "success")
    return redirect(url_for('admin_claims'))




@app.route('/admin/reject/<int:item_id>', methods=['POST'])
@admin_required
def admin_claim_reject(item_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT claimed_by FROM items WHERE id = %s", (item_id,))
    result = cur.fetchone()

    if not result:
        flash("Item not found.", "error")
        cur.close()
        return redirect(url_for('admin_claims'))

    claimed_by = result[0]

    cur.execute("""
        UPDATE items
        SET claim_status = 'rejected', status = 'found'
        WHERE id = %s
    """, (item_id,))

    message = (
        "❌ Your claim has been rejected by the admin.\n"
        "If you believe this was a mistake, please contact support or reattempt claim."
    )

    cur.execute("""
        INSERT INTO notifications (user_id, message, is_read)
        VALUES (%s, %s, 0)
    """, (claimed_by, message))
    mysql.connection.commit()

    # ✅ Log admin rejection
    log_activity(
        session['user_id'],
        "Rejected Claim",
        item_id,
        f"Admin {session.get('name')} rejected claim for item ID {item_id}."
    )

    cur.close()
    flash("Claim rejected and user notified.", "info")
    return redirect(url_for('admin_claims'))


@app.route('/admin/activity_log')
@admin_required
def admin_activity_log():
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT 
            a.id,
            u.name AS user_name,
            a.action,
            i.item_name,
            a.details,
            a.timestamp
        FROM activity_log a
        LEFT JOIN users u ON a.user_id = u.id
        LEFT JOIN items i ON a.item_id = i.id  -- ✅ FIXED: use i.id
        ORDER BY a.timestamp DESC
    """)
    logs = cur.fetchall()
    cur.close()
    return render_template('admin/activity_log.html', logs=logs)





# ======================
# Admin Edit Item Route
# ======================
@app.route('/admin/items/<int:item_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_item(item_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, item_name, description, location, date_reported, photo, status, security_question, user_answer FROM items WHERE id = %s", (item_id,))
    item = cur.fetchone()

    if not item:
        flash("Item not found.", "error")
        cur.close()
        return redirect(url_for('admin_items'))

    if request.method == 'POST':
        item_name = request.form['item_name']
        description = request.form['description']
        location = request.form['location']
        status = request.form['status']
        security_question = request.form['security_question']
        security_answer = request.form['security_answer']

        # optional photo
        photo = request.files.get('photo')
        photo_name = item[5]
        if photo and photo.filename:
            photo_name = secure_filename(photo.filename)
            photo.save(os.path.join(app.config['UPLOAD_FOLDER'], photo_name))

        cur.execute("""
            UPDATE items
            SET item_name=%s, description=%s, location=%s, status=%s,
                security_question=%s, user_answer=%s, photo=%s
            WHERE id=%s
        """, (item_name, description, location, status, security_question, security_answer, photo_name, item_id))
        mysql.connection.commit()
        cur.close()

        flash("Item updated successfully!", "success")
        return redirect(url_for('admin_items'))

    cur.close()
    return render_template('edit_item.html', item=item, admin=True)

# ======================
# ADMIN: Users
# ======================
@app.route('/admin/users/demote/<int:user_id>', methods=['POST'])
@admin_required
def demote_user(user_id):
    cur = mysql.connection.cursor()
    cur.execute("UPDATE users SET is_admin = 0 WHERE id = %s", (user_id,))
    mysql.connection.commit()
    cur.close()
    flash("⚠️ Admin rights removed successfully.", "info")
    return redirect(url_for('admin_users'))


@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
    mysql.connection.commit()
    cur.close()
    flash("❌ User deleted successfully.", "error")
    return redirect(url_for('admin_users'))

# ======================
# Report Item
# ======================
@app.route('/report_item', methods=['GET', 'POST'])
def report_item():
    if 'user_id' not in session:
        flash("Please log in to report an item.", "error")
        return redirect(url_for('login'))

    if request.method == 'POST':
        item_name = request.form['item_name']
        description = request.form['description']
        location = request.form['location']
        status = request.form.get('status', 'pending')
        security_question = request.form['security_question']
        security_answer = request.form['security_answer']
        date_reported = date.today()
        contact_number = request.form['contact_number']
        utp_email = request.form['utp_email']

        photo = request.files['photo']
        photo_name = None
        if photo and photo.filename:
            photo_name = secure_filename(photo.filename)
            photo.save(os.path.join(app.config['UPLOAD_FOLDER'], photo_name))

        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO items (
                item_name, description, location, date_reported, user_id, status,
                security_question, user_answer, photo, contact_number, utp_email
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            item_name, description, location, date_reported, session['user_id'], status,
            security_question, security_answer, photo_name, contact_number, utp_email
        ))
        mysql.connection.commit()

        # ✅ Get the newly created item ID for logging
        item_id = cur.lastrowid
        cur.close()

        # ✅ Log this action in the activity_log
        log_activity(
            session['user_id'],
            "Reported Item",
            item_id,
            f"Item '{item_name}' ({status}) reported by user."
        )

        flash("Item reported successfully!", "success")
        return redirect(url_for('admin_dashboard'))


    return render_template('report_item.html')


# ======================
# Edit Reported Item
# ======================
@app.route('/edit_item/<int:item_id>', methods=['GET', 'POST'])
def edit_item(item_id):
    # Check if user logged in
    if 'user_id' not in session:
        flash("Please log in to edit your item.", "error")
        return redirect(url_for('login'))

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM items WHERE id = %s AND user_id = %s", (item_id, session['user_id']))
    item = cur.fetchone()

    if not item:
        flash("You do not have permission to edit this item.", "error")
        cur.close()
        return redirect(url_for('view_items'))

    # POST — update item
    if request.method == 'POST':
        item_name = request.form['item_name']
        description = request.form['description']
        location = request.form['location']
        status = request.form['status']
        security_question = request.form['security_question']
        security_answer = request.form['security_answer']

        # Handle optional new photo
        photo = request.files['photo']
        photo_name = item[5]  # keep existing photo by default
        if photo and photo.filename:
            photo_name = secure_filename(photo.filename)
            photo.save(os.path.join(app.config['UPLOAD_FOLDER'], photo_name))

        # Update record
        cur.execute("""
            UPDATE items
            SET item_name = %s, description = %s, location = %s,
                status = %s, security_question = %s, user_answer = %s, photo = %s
            WHERE id = %s AND user_id = %s
        """, (item_name, description, location, status, security_question, security_answer, photo_name, item_id, session['user_id']))

        mysql.connection.commit()
        cur.close()
        flash("Item updated successfully!", "success")
        return redirect(url_for('view_items'))

    cur.close()
    return render_template('edit_item.html', item=item)


# ======================
# Item
# ======================
@app.route('/items')
def view_items():
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT i.id, i.item_name, i.description, i.location, i.date_reported,
            i.photo, i.status, u.name, i.user_id, i.claim_status
        FROM items i
        JOIN users u ON i.user_id = u.id
        ORDER BY i.date_reported DESC
    """)

    items = cur.fetchall()
    cur.close()

    # Anonymize reporter for normal users
    if not session.get('is_admin'):
        items = [(id, item_name, desc, loc, date, photo, status, "Anonymous", uid, claim_status)
                for (id, item_name, desc, loc, date, photo, status, name, uid, claim_status) in items]


    return render_template('items.html', items=items)



# ======================
# Claim Items (normal user)
# ======================
@app.route('/claim/<int:item_id>', methods=['GET', 'POST'])
def claim_item(item_id):
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT id, item_name, description, location, security_question, status,
               contact_number, utp_email
        FROM items
        WHERE id = %s
    """, (item_id,))
    item = cur.fetchone()

    if not item:
        flash("Item not found.", "error")
        return redirect(url_for('view_items'))

    if item[5] not in ('found', 'lost'):
        flash("Only found items can be claimed.", "warning")
        return redirect(url_for('view_items'))

    if request.method == 'POST':
        security_answer = request.form['security_answer']
        user_id = session.get('user_id')

        # Handle uploaded proof image
        proof_photo = request.files.get('proof_photo')
        proof_photo_name = None
        if proof_photo and proof_photo.filename:
            proof_photo_name = secure_filename(proof_photo.filename)
            proof_photo.save(os.path.join(app.config['UPLOAD_FOLDER'], proof_photo_name))

        # Update claim details (save proof photo + mark as pending claim)
        cur.execute("""
            UPDATE items 
            SET user_answer = %s,
                claimed_by = %s,
                proof_photo = %s,
                status = 'found',
                claim_status = 'pending'
            WHERE id = %s
        """, (security_answer, user_id, proof_photo_name, item_id))
        mysql.connection.commit()

        # ✅ Log the claim submission (INSIDE POST block)
        log_activity(
            user_id,
            "Submitted Claim",
            item_id,
            f"User {session.get('name')} submitted a claim with proof for item ID {item_id}."
        )

        cur.close()
        flash("✅ Claim submitted successfully with your proof photo! Waiting for admin approval.", "info")
        return redirect(url_for('view_items'))

    cur.close()
    return render_template('claim_item.html', item=item)


# ======================
# Search Items
# ======================
@app.route('/search', methods=['GET', 'POST'])
def search():
    query = ""
    status = "all"
    results = []

    if request.method == 'POST':
        query = request.form.get('query', '').strip()
        status = request.form.get('status', 'all')

        cur = mysql.connection.cursor()

        # Build query dynamically depending on status
        if status == "all":
            cur.execute("""
                SELECT i.id, i.item_name, i.description, i.location, i.date_reported,
                       i.photo, i.status, u.name, i.user_id
                FROM items i
                JOIN users u ON i.user_id = u.id
                WHERE i.item_name LIKE %s OR i.description LIKE %s OR i.location LIKE %s
                ORDER BY i.date_reported DESC
            """, (f"%{query}%", f"%{query}%", f"%{query}%"))
        else:
            cur.execute("""
                SELECT i.id, i.item_name, i.description, i.location, i.date_reported,
                       i.photo, i.status, u.name, i.user_id
                FROM items i
                JOIN users u ON i.user_id = u.id
                WHERE (i.item_name LIKE %s OR i.description LIKE %s OR i.location LIKE %s)
                      AND i.status = %s
                ORDER BY i.date_reported DESC
            """, (f"%{query}%", f"%{query}%", f"%{query}%", status))

        results = cur.fetchall()
        cur.close()

    return render_template('search.html', results=results, query=query, status=status)


# ======================
# Logout Page
# ======================
@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))


# ======================================================
# NOTIFICATIONS PAGE
# ======================================================
@app.route('/notifications')
def notifications():
    if 'user_id' not in session:
        flash("Please log in to view notifications.", "error")
        return redirect(url_for('login'))

    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT message, created_at, is_read
        FROM notifications
        WHERE user_id = %s
        ORDER BY created_at DESC
    """, (session['user_id'],))
    notes = cur.fetchall()

    # Mark all as read
    cur.execute("UPDATE notifications SET is_read = 1 WHERE user_id = %s", (session['user_id'],))
    mysql.connection.commit()
    cur.close()

    return render_template('notifications.html', notes=notes)


# ======================
# Run App
# ======================
if __name__ == '__main__':
    app.run(debug=True)

