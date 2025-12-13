"""
VaultGuard MFA Server
Multi-Factor Authentication server with secure SSL/TLS communication
"""
import socket
import ssl
import threading
import time
import hashlib
import hmac
import base64
import json
import sqlite3
import os
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import secrets
import logging

# Logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class MFAServer:
    def __init__(self, host='0.0.0.0', port=8443):
        self.host = host
        self.port = port
        self.clients = {}      # Registered devices
        self.sessions = {}     # Active sessions
        self.otp_secrets = {}  # Temporary secrets for OTP
        self.db_path = 'vaultguard.db'
        
        # Initialize database
        self.init_database()
        
        # Setup SSL certificates
        self.setup_ssl()
        
        # Communication encryption key
        self.comm_key = self.generate_communication_key()
    
    def init_database(self):
        """Initialize database for storing user and device information"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                master_password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Devices table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                device_name TEXT NOT NULL,
                device_key TEXT NOT NULL,
                registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        ''')
        
        # OTP table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS otps (
                otp_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                otp_code TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                used BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully.")
    
    def setup_ssl(self):
        """Check SSL certificate presence"""
        cert_dir = 'ssl_certs'
        if not os.path.exists(cert_dir):
            os.makedirs(cert_dir)
        
        cert_file = os.path.join(cert_dir, 'certificate.pem')
        key_file = os.path.join(cert_dir, 'private_key.pem')
        
        if not os.path.exists(cert_file) or not os.path.exists(key_file):
            logger.warning("SSL certificate files not found. Valid SSL certificates are required in production.")
    
    def generate_communication_key(self):
        """Generate encryption key for secure communication"""
        key = Fernet.generate_key()
        with open('communication.key', 'wb') as f:
            f.write(key)
        return key
    
    def derive_key_from_password(self, password, salt):
        """Derive encryption key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def hash_password(self, password, salt=None):
        """Hash password using PBKDF2 (simulating Argon2)"""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=310000,
        )
        password_hash = kdf.derive(password.encode())
        return password_hash, salt
    
    def generate_totp(self, user_id):
        """Generate a time-based OTP valid for 60 seconds"""
        secret = base64.b32encode(os.urandom(10)).decode('utf-8')
        
        time_counter = int(time.time()) // 30
        time_bytes = time_counter.to_bytes(8, byteorder='big')
        
        secret_bytes = base64.b32decode(secret)
        hmac_hash = hmac.new(secret_bytes, time_bytes, hashlib.sha1).digest()
        
        offset = hmac_hash[-1] & 0x0F
        binary = ((hmac_hash[offset] & 0x7F) << 24 |
                  (hmac_hash[offset + 1] & 0xFF) << 16 |
                  (hmac_hash[offset + 2] & 0xFF) << 8 |
                  (hmac_hash[offset + 3] & 0xFF))
        
        otp = binary % 1000000
        otp_str = str(otp).zfill(6)
        
        expires_at = datetime.now() + timedelta(seconds=60)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO otps (user_id, otp_code, expires_at, used)
            VALUES (?, ?, ?, ?)
        ''', (user_id, otp_str, expires_at, False))
        conn.commit()
        conn.close()
        
        self.otp_secrets[user_id] = {
            'secret': secret,
            'otp': otp_str,
            'expires': expires_at
        }
        
        logger.info(f"OTP generated for user {user_id}: {otp_str}")
        return otp_str
    
    def verify_otp(self, user_id, otp_code):
        """Verify OTP code"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM otps 
            WHERE user_id = ? AND otp_code = ? AND expires_at > ? AND used = 0
        ''', (user_id, otp_code, datetime.now()))
        
        otp_record = cursor.fetchone()
        
        if otp_record:
            cursor.execute('''
                UPDATE otps SET used = 1 WHERE otp_id = ?
            ''', (otp_record[0],))
            conn.commit()
            logger.info(f"OTP verified for user {user_id}")
            return True
        
        conn.close()
        logger.warning(f"OTP verification failed for user {user_id}")
        return False
    
    def register_user(self, user_id, master_password):
        """Register a new user"""
        password_hash, salt = self.hash_password(master_password)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO users (user_id, master_password_hash, salt)
                VALUES (?, ?, ?)
            ''', (user_id, password_hash.hex(), salt.hex()))
            conn.commit()
            logger.info(f"New user registered: {user_id}")
            return True
        except sqlite3.IntegrityError:
            logger.error(f"User already exists: {user_id}")
            return False
        finally:
            conn.close()
    
    def register_device(self, user_id, device_id, device_name, device_key):
        """Register a new mobile device"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO devices (device_id, user_id, device_name, device_key)
                VALUES (?, ?, ?, ?)
            ''', (device_id, user_id, device_name, device_key))
            conn.commit()
            logger.info(f"Device {device_name} registered for user {user_id}")
            return True
        except sqlite3.IntegrityError:
            logger.error(f"Device already exists: {device_id}")
            return False
        finally:
            conn.close()
    
    def verify_device(self, device_id, device_key):
        """Verify device identity"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM devices 
            WHERE device_id = ? AND device_key = ?
        ''', (device_id, device_key))
        
        device = cursor.fetchone()
        conn.close()
        
        if device:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE devices SET last_seen = ? WHERE device_id = ?
            ''', (datetime.now(), device_id))
            conn.commit()
            conn.close()
            
            logger.info(f"Device verified: {device_id}")
            return True
        
        logger.warning(f"Device verification failed: {device_id}")
        return False
    
    def handle_client(self, client_socket, client_address):
        """Handle incoming client connection"""
        logger.info(f"New connection from {client_address}")
        
        try:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile='ssl_certs/certificate.pem',
                                   keyfile='ssl_certs/private_key.pem')
            ssl_socket = context.wrap_socket(client_socket, server_side=True)
            
            while True:
                try:
                    data = ssl_socket.recv(4096)
                    if not data:
                        break
                    
                    request = json.loads(data.decode('utf-8'))
                    response = self.process_request(request)
                    
                    ssl_socket.send(json.dumps(response).encode('utf-8'))
                
                except (json.JSONDecodeError, ssl.SSLError) as e:
                    logger.error(f"Error processing request: {e}")
                    break
        
        except Exception as e:
            logger.error(f"Client handling error for {client_address}: {e}")
        finally:
            client_socket.close()
            logger.info(f"Connection closed: {client_address}")
    
    def process_request(self, request):
        """Process client request"""
        action = request.get('action')
        
        if action == 'register_user':
            return self.handle_register_user(request)
        elif action == 'register_device':
            return self.handle_register_device(request)
        elif action == 'verify_device':
            return self.handle_verify_device(request)
        elif action == 'generate_otp':
            return self.handle_generate_otp(request)
        elif action == 'verify_otp':
            return self.handle_verify_otp(request)
        elif action == 'verify_login':
            return self.handle_verify_login(request)
        else:
            return {'status': 'error', 'message': 'Unknown action'}
    
    def handle_register_user(self, request):
        """Handle new user registration"""
        user_id = request.get('user_id')
        master_password = request.get('master_password')
        
        if not user_id or not master_password:
            return {'status': 'error', 'message': 'Missing required fields'}
        
        success = self.register_user(user_id, master_password)
        
        if success:
            return {'status': 'success', 'message': 'User registered successfully'}
        else:
            return {'status': 'error', 'message': 'User registration failed'}
    
    def handle_register_device(self, request):
        """Handle device registration"""
        user_id = request.get('user_id')
        device_id = request.get('device_id')
        device_name = request.get('device_name')
        device_key = request.get('device_key')
        
        if not all([user_id, device_id, device_name, device_key]):
            return {'status': 'error', 'message': 'Missing required fields'}
        
        success = self.register_device(user_id, device_id, device_name, device_key)
        
        if success:
            return {'status': 'success', 'message': 'Device registered successfully'}
        else:
            return {'status': 'error', 'message': 'Device registration failed'}
    
    def handle_verify_device(self, request):
        """Handle device verification"""
        device_id = request.get('device_id')
        device_key = request.get('device_key')
        
        if not device_id or not device_key:
            return {'status': 'error', 'message': 'Missing required fields'}
        
        success = self.verify_device(device_id, device_key)
        
        if success:
            return {'status': 'success', 'message': 'Device verified successfully'}
        else:
            return {'status': 'error', 'message': 'Device verification failed'}
    
    def handle_generate_otp(self, request):
        """Handle OTP generation"""
        user_id = request.get('user_id')
        
        if not user_id:
            return {'status': 'error', 'message': 'User ID is required'}
        
        otp = self.generate_totp(user_id)
        
        if otp:
            return {
                'status': 'success',
                'otp': otp,
                'expires_in': 60,
                'timestamp': datetime.now().isoformat()
            }
        else:
            return {'status': 'error', 'message': 'OTP generation failed'}
    
    def handle_verify_otp(self, request):
        """Handle OTP verification"""
        user_id = request.get('user_id')
        otp_code = request.get('otp_code')
        
        if not user_id or not otp_code:
            return {'status': 'error', 'message': 'Missing required fields'}
        
        success = self.verify_otp(user_id, otp_code)
        
        if success:
            return {'status': 'success', 'message': 'OTP verified successfully'}
        else:
            return {'status': 'error', 'message': 'Invalid OTP'}
    
    def handle_verify_login(self, request):
        """Handle login verification"""
        user_id = request.get('user_id')
        master_password = request.get('master_password')
        
        if not user_id or not master_password:
            return {'status': 'error', 'message': 'Missing required fields'}
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT master_password_hash, salt FROM users WHERE user_id = ?', (user_id,))
        user_data = cursor.fetchone()
        conn.close()
        
        if not user_data:
            return {'status': 'error', 'message': 'User not found'}
        
        stored_hash = bytes.fromhex(user_data[0])
        salt = bytes.fromhex(user_data[1])
        
        password_hash, _ = self.hash_password(master_password, salt)
        
        if password_hash == stored_hash:
            return {'status': 'success', 'message': 'Master password verified'}
        else:
            return {'status': 'error', 'message': 'Incorrect master password'}
    
    def start(self):
        """Start MFA server"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        
        logger.info(f"MFA server running on {self.host}:{self.port}")
        
        try:
            while True:
                client_socket, client_address = server_socket.accept()
                
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()
        
        except KeyboardInterrupt:
            logger.info("Stopping server...")
        finally:
            server_socket.close()

# Main execution
if __name__ == "__main__":
    cert_file = 'ssl_certs/certificate.pem'
    key_file = 'ssl_certs/private_key.pem'
    
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        print("Warning: SSL certificate files are missing.")
        print("To generate test certificates, run:")
        print("openssl req -x509 -newkey rsa:4096 -keyout ssl_certs/private_key.pem -out ssl_certs/certificate.pem -days 365 -nodes")
        print("Continue without SSL? (yes/no): ")
        
        response = input().strip().lower()
        
        if response != 'yes':
            exit(1)
    
    server = MFAServer()
    server.start()
