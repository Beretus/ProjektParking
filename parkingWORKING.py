from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_cors import CORS

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///parking.db'
db = SQLAlchemy(app)

CORS(app)

class ParkingSpot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(10), nullable=False)

class ParkingSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    spot_id = db.Column(db.Integer, nullable=False)
    entry_time = db.Column(db.DateTime, nullable=False)
    exit_time = db.Column(db.DateTime)

@app.route('/update', methods=['GET'])
def update():
    for i in range(10):
        status = request.args.get(f'sensor{i}')
        if status is not None:
            spot = ParkingSpot.query.get(i+1)
            spot.status = 'Occupied' if status == '1' else 'Free'
            db.session.commit()
    return "Status received"

@app.route('/status', methods=['GET'])
def status():
    spots = ParkingSpot.query.all()
    return jsonify([{ 'id': spot.id, 'status': spot.status } for spot in spots])

@app.route('/start_session', methods=['POST'])
def start_session():
    spot_id = request.json.get('spot_id')
    entry_time = datetime.now()
    session = ParkingSession(spot_id=spot_id, entry_time=entry_time)
    db.session.add(session)
    db.session.commit()
    return jsonify({'session_id': session.id})

@app.route('/end_session', methods=['POST'])
def end_session():
    session_id = request.json.get('session_id')
    session = ParkingSession.query.get(session_id)
    session.exit_time = datetime.now()
    db.session.commit()
    duration = session.exit_time - session.entry_time
    return jsonify({'session_id': session.id, 'duration': str(duration)})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Dodanie miejsc parkingowych do bazy danych (raz, skomentować po pierwszym uruchomieniu)
        for i in range(10):
            if ParkingSpot.query.get(i+1) is None:
                db.session.add(ParkingSpot(id=i+1, status='Free'))
        db.session.commit()
    app.run(host='0.0.0.0', port=5000)



