import unittest
import requests


class JWKSAuthTest(unittest.TestCase):

    def test_valid_jwt(self):
        response = requests.post('http://127.0.0.1:8080/auth')
        self.assertEqual(response.status_code, 200)
        token = response.json().get('token')
        self.assertIsNotNone(token)

    def test_expired_jwt(self):
        response = requests.post('http://127.0.0.1:8080/auth?expired=true')
        self.assertEqual(response.status_code, 200)
        token = response.json().get('token')
        self.assertIsNotNone(token)

    def test_jwks(self):
        response = requests.get('http://127.0.0.1:8080/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)
        jwks = response.json().get('keys')
        self.assertIsInstance(jwks, list)
        self.assertGreater(len(jwks), 0)


if __name__ == '__main__':
    unittest.main()
