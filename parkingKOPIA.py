from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
from email.mime.text import MIMEText
import uuid
import os

app = Flask(__name__)
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
SMTP_PASSWORD = 'parking123'  # Use your generated App Password here

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
    email = db.Column(db.String(150), unique=True, nullable=False)  # Email column
    password = db.Column(db.String(150), nullable=False)
    current_qr = db.Column(db.String(500), nullable=True)

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
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('status'))
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
    return render_template('status.html', spots=spots)

@app.route('/generate_qr', methods=['GET'])
@login_required
def generate_qr():
    username = current_user.username  
    qr_data = f"{username}-{uuid.uuid4()}"  
    # Implement QR code generation here
    return "QR Code generated"

@app.route('/qr_scan', methods=['POST'])
def qr_scan():
    qr_data = request.json.get('qr_data')
    user = User.query.filter_by(current_qr=qr_data).first()
    if not user:
        return jsonify({'error': 'Invalid QR Code'}), 400

    active_session = ParkingSession.query.filter_by(user_id=user.id, exit_time=None).first()

    if active_session:
        # End the session
        active_session.exit_time = datetime.now()
        db.session.commit()
        duration = active_session.exit_time - active_session.entry_time
        user.current_qr = None
        db.session.commit()
        return jsonify({'message': 'Session ended', 'duration': str(duration)})
    else:
        # Start a new session
        entry_time = datetime.now()
        session = ParkingSession(user_id=user.id, entry_time=entry_time)
        db.session.add(session)
        db.session.commit()
        return jsonify({'message': 'Session started', 'session_id': session.id})

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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Add parking spots to the database (once, comment after the first run)
        for i in range(10):
            if db.session.get(ParkingSpot, i+1) is None:
                db.session.add(ParkingSpot(id=i+1, status='Free'))
        db.session.commit()
    app.run(host='0.0.0.0', port=5000)
