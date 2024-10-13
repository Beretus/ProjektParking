import unittest
from app import app, db, User, ParkingSession
from flask import json
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app, db, User

class QRTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
        self.client = app.test_client()
        with app.app_context():
            db.create_all()

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_generate_qr(self):
        # Rejestracja i logowanie użytkownika
        self.client.post('/register', data=json.dumps({
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'password123'
        }), content_type='application/json')

        response = self.client.get('/generate_qr')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data.decode())
        self.assertIn('qr_code', data)

if __name__ == '__main__':
    unittest.main()
