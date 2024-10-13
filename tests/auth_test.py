import unittest
from app import app, db, User
from flask import json
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app, db, User

class AuthTestCase(unittest.TestCase):
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

    def test_registration(self):
        response = self.client.post('/register', data=json.dumps({
            'username': 'testfesfesuser',
            'email': 'test@examplfese.com',
            'password': 'passwordfes123'
        }), content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data.decode())
        self.assertTrue(data['success'])

    def test_login(self):
       

        response = self.client.post('/login', data=json.dumps({
            'username': 'testfesfesuser',
            'password': 'testfesfesuser'
        }), content_type='application/json')

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data.decode())
        self.assertIn('token', data)

if __name__ == '__main__':
    unittest.main()
