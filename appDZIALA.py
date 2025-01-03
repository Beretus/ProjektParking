import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
from email.mime.text import MIMEText
import uuid
import os
import qrcode
import io
import base64
from flask_cors import CORS
from flask import jsonify, request



app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///parking.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Email configuration (using Gmail SMTP with App Password)
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SMTP_USERNAME = 'systemparkingowy0@gmail.com'
SMTP_PASSWORD = 'uueo qlvi dsun gltd'  # Use your generated App Password here

# JWT Helper Functions
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        print(f"Request headers: {request.headers}")  # Add this line to debug headers

        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            print(f"Received token: {token}")
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            user_from_token = User.query.filter_by(id=data['user_id']).first()

            if user_from_token is None:
                return jsonify({'message': 'User not found!'}), 401

        except Exception as e:
            print(f"Token verification failed: {str(e)}")
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(user_from_token, *args, **kwargs)
    return decorated

def api_or_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if the request is coming from an API (likely Flutter) or a web browser
        if request.headers.get('Accept') == 'application/json':
            # Use token authentication for API requests
            return token_required(f)(*args, **kwargs)
            # Use session authentication for web requests
            # Flask-Login's current_user is available directly in this case
            return f(current_user, *args, **kwargs)
    return decorated_function


# Route to serve CSS files
@app.route('/styles/<path:filename>')
def styles(filename):
    return send_from_directory('templates/styles', filename)

# Route to serve image files
@app.route('/img/<path:filename>')
def images(filename):
    return send_from_directory('templates/img', filename)

def send_email(to, subject, body):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SMTP_USERNAME
    msg['To'] = to

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(SMTP_USERNAME, to, msg.as_string())

# Database models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)  
    password = db.Column(db.String(150), nullable=False)
    first_name = db.Column(db.String(150), nullable=True)
    last_name = db.Column(db.String(150), nullable=True)
    phone_number = db.Column(db.String(20), nullable=True)
    address = db.Column(db.String(250), nullable=True)
    current_qr = db.Column(db.String(500), nullable=True)
    
class Vehicle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    model = db.Column(db.String(150), nullable=False)
    license_plate = db.Column(db.String(50), nullable=False)
    color = db.Column(db.String(50), nullable=True)
    user = db.relationship('User', backref=db.backref('vehicles', lazy=True))

class ParkingSpot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(10), nullable=False)

class ParkingSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    entry_time = db.Column(db.DateTime, nullable=False)
    exit_time = db.Column(db.DateTime)
    user = db.relationship('User', backref=db.backref('sessions', lazy=True))


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    spot_id = db.Column(db.Integer, db.ForeignKey('parking_spot.id'), nullable=False)
    notified = db.Column(db.Boolean, default=False)
    user = db.relationship('User', backref=db.backref('notifications', lazy=True))
    spot = db.relationship('ParkingSpot', backref=db.backref('notifications', lazy=True))


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if request.headers.get('accept') == 'application/json':
            data = request.get_json()
            username = data.get('username')
            email = data.get('email')
            password = data.get('password')
        else:
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']

        # Check if the email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            if request.headers.get('accept') == 'application/json':
                return jsonify({'success': False, 'message': 'Email already registered'}), 400
            else:
                flash('Email is already registered. Please use a different email address or login.', 'danger')
                return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        if request.headers.get('accept') == 'application/json':
            return jsonify({'success': True, 'message': 'Registration successful!'})
        else:
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            # Log the user in and create a session
            login_user(user)

            token = jwt.encode({
                'user_id': user.id,
                'exp': datetime.utcnow() + timedelta(hours=1)
            }, app.config['SECRET_KEY'], algorithm="HS256")

            # Convert token from bytes to string if necessary
            token_str = token.decode('utf-8') if isinstance(token, bytes) else token

            if request.is_json:
                return jsonify({'success': True, 'message': 'Login successful!', 'token': token_str})
            else:
                return redirect(url_for('index'))  # Redirect to the homepage after login

        else:
            if request.is_json:
                return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
            else:
                flash('Invalid credentials', 'danger')
                return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/update', methods=['GET'])
def update():
    for i in range(10):
        status = request.args.get(f'sensor{i}')
        if status is not None:
            spot = db.session.get(ParkingSpot, i+1)
            spot.status = 'Occupied' if status == '1' else 'Free'
            db.session.commit()
	    
            # Check for notifications
            if spot.status == 'Free':
                notifications = Notification.query.filter_by(spot_id=spot.id, notified=False).all()
                for notification in notifications:
                    user = User.query.get(notification.user_id)
                    if user and user.email:
                        send_email(user.email, 'Parking Spot Available', f'Spot {spot.id} is now free!')
                        notification.notified = True
                        db.session.commit()
                    flash(f"Spot {spot.id} is now free! Email sent to {user.email}", "success")
    return "Status received"


@app.route('/status', methods=['GET'])
def status():
    spots = ParkingSpot.query.all()
    
    if request.headers.get('accept') == 'application/json':
        spots_data = [{'id': spot.id, 'status': spot.status} for spot in spots]
        return jsonify(spots_data)
    else:
        return render_template('status.html', spots=spots)


@app.route('/generate_qr', methods=['GET'])
@api_or_login_required
def generate_qr(current_user):
    # current_user will either come from Flask-Login or token_required
    username = current_user.username  
    qr_data = f"{username}-{uuid.uuid4()}"  
    qr = qrcode.make(qr_data)
    qr_io = io.BytesIO()
    qr.save(qr_io, 'PNG')
    qr_code_data = base64.b64encode(qr_io.getvalue()).decode('utf-8')
    current_user.current_qr = qr_data  # Update the QR data in the user model
    db.session.commit()
    
    if request.headers.get('Accept') == 'application/json':
        return jsonify({'qr_code': qr_code_data})
    else:
        return render_template('qr_code.html', qr_code=qr_code_data)


@app.route('/qr_scan', methods=['POST'])
def qr_scan():
    try:
        qr_data = request.json.get('qr_data')
        user = User.query.filter_by(current_qr=qr_data).first()
        if not user:
            return jsonify({'error': 'Invalid QR Code'}), 400

        active_session = ParkingSession.query.filter_by(user_id=user.id, exit_time=None).first()

        if active_session:
            # End the session
            active_session.exit_time = datetime.now()  # Ensure this works now
            db.session.commit()
            duration = active_session.exit_time - active_session.entry_time
            user.current_qr = None
            db.session.commit()
            return jsonify({'message': 'Session ended', 'duration': str(duration)})
        else:
            # Start a new session
            entry_time = datetime.now()  # Correct datetime usage
            session = ParkingSession(user_id=user.id, entry_time=entry_time)
            db.session.add(session)
            db.session.commit()
            return jsonify({'message': 'Session started', 'session_id': session.id})

    except Exception as e:
        print(f"An error occurred: {e}")
        return jsonify({'error': 'An internal server error occurred'}), 500


@app.route('/sesje')
@login_required
def sesje():
    sessions = ParkingSession.query.filter_by(user_id=current_user.id).all()
    return render_template('sesje.html', sessions=sessions)

@app.route('/notify/<int:spot_id>', methods=['POST'])
@login_required
def notify(spot_id):
    spot = db.session.get(ParkingSpot, spot_id)
    if spot and spot.status == 'Occupied':
        new_notification = Notification(user_id=current_user.id, spot_id=spot_id)
        db.session.add(new_notification)
        db.session.commit()
        flash('You will be notified when the spot is free.', 'info')
    else:
        flash('This spot is already free or does not exist.', 'warning')
    return redirect(url_for('status'))
    
    
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_user.first_name = request.form['first_name']
        current_user.last_name = request.form['last_name']
        current_user.phone_number = request.form['phone_number']
        current_user.address = request.form['address']
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
    
    vehicles = Vehicle.query.filter_by(user_id=current_user.id).all()
    sessions = ParkingSession.query.filter_by(user_id=current_user.id).all()
    return render_template('profile.html', vehicles=vehicles, sessions=sessions)

@app.route('/add_vehicle', methods=['POST'])
@login_required
def add_vehicle():
    model = request.form['model']
    license_plate = request.form['license_plate']
    color = request.form['color']
    new_vehicle = Vehicle(user_id=current_user.id, model=model, license_plate=license_plate, color=color)
    db.session.add(new_vehicle)
    db.session.commit()
    flash('Vehicle added successfully!', 'success')
    return redirect(url_for('profile'))
    


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Add parking spots to the database (once, comment after the first run)
        for i in range(10):
            if db.session.get(ParkingSpot, i+1) is None:
                db.session.add(ParkingSpot(id=i+1, status='Free'))
        db.session.commit()
    app.run(host='0.0.0.0', port=5000)
