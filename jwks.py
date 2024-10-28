import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime

# Server settings
hostName = "localhost"
serverPort = 8080

# SQLite database setup
DB_NAME = 'totally_not_my_privateKeys.db'


# Initialize the SQLite database
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


# Store a private key in the database
def store_private_key(pem, exp):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (pem, exp))
    conn.commit()
    conn.close()


# Fetch a key from the database based on expiration
# (expired if True, valid if False)
def fetch_key(expired=False):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    if expired:
        c.execute('SELECT key FROM keys WHERE exp <= ?',
                  (int(datetime.datetime.utcnow().timestamp()),))
    else:
        c.execute('SELECT key FROM keys WHERE exp > ?',
                  (int(datetime.datetime.utcnow().timestamp()),))
    result = c.fetchone()
    conn.close()
    return result[0] if result else None


# Convert an integer to Base64URL-encoded string
def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


# Helper to generate RSA keys,
# and store one expired and one valid key on startup
def generate_and_store_keys():
    # Generate private key (valid)
    private_key = rsa.generate_private_key(public_exponent=65537,
                                           key_size=2048)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
        )
    exp_time_valid = int(
        (datetime.datetime.utcnow() + datetime.timedelta(hours=1)).timestamp()
        )
    store_private_key(pem, exp_time_valid)

    # Generate private key (expired)
    expired_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
        )
    expired_pem = expired_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
        )
    exp_time_expired = int(
        (datetime.datetime.utcnow() - datetime.timedelta(hours=1)).timestamp()
        )
    store_private_key(expired_pem, exp_time_expired)


# Deserialize a PEM-formatted key
# back to an RSA private key object
def deserialize_private_key(pem):
    return serialization.load_pem_private_key(
        pem, password=None, backend=default_backend()
        )


class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            # Determine whether to use an expired or valid key
            expired = 'expired' in params

            # Fetch the appropriate key from the database
            pem = fetch_key(expired=expired)
            if not pem:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"No valid key found")
                return

            # Deserialize the key
            # private_key = deserialize_private_key(pem) !TAKE THIS OUT IF BAD!

            headers = {
                "kid": "expiredKID" if expired else "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            if expired:
                token_payload["exp"] = (datetime.datetime.utcnow() -
                                        datetime.timedelta(hours=1))

            encoded_jwt = jwt.encode(token_payload, pem,
                                     algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            # Fetch all valid keys from the database
            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            c.execute('SELECT key FROM keys WHERE exp > ?',
                      (int(datetime.datetime.utcnow().timestamp()),))
            keys = []
            for row in c.fetchall():
                private_key = deserialize_private_key(row[0])
                numbers = private_key.private_numbers()
                keys.append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "goodKID",
                    "n": int_to_base64(numbers.public_numbers.n),
                    "e": int_to_base64(numbers.public_numbers.e),
                })
            conn.close()

            response = json.dumps({"keys": keys})
            self.wfile.write(bytes(response, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()


if __name__ == "__main__":
    # Initialize DB and keys
    init_db()
    generate_and_store_keys()

    # Start the web server
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print(f"Server started at http://{hostName}:{serverPort}")
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("Server stopped.")
