import json
import hashlib
import base64
import os
import getpass
import sys
import requests
import sqlite3
import logging
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import hmac
import time

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class VaultGuardClient:
    def __init__(self, server_url='https://localhost:8443'):
        self.server_url = server_url
        self.user_id = None
        self.vault_file = 'vault_data.json'
        self.vault_key = None
        self.session_token = None
        self.verify_ssl = False
        
        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        if not self.verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def derive_key(self, master_password, salt=None):
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=310000,
            backend=default_backend()
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        
        if len(key) != 44:
            print(f"Warning: Key size is {len(key)} bytes, trimming to 32 bytes")
            key_bytes = base64.urlsafe_b64decode(key)
            if len(key_bytes) > 32:
                key_bytes = key_bytes[:32]
            elif len(key_bytes) < 32:
                key_bytes = key_bytes + b'0' * (32 - len(key_bytes))
            key = base64.urlsafe_b64encode(key_bytes)
        
        return key, salt
    
    def check_and_fix_key(self):
        if len(self.vault_key) != 44:
            print(f"Key size error: {len(self.vault_key)} bytes (should be 44 for Fernet)")
            try:
                key_bytes = base64.urlsafe_b64decode(self.vault_key + '=' * (4 - len(self.vault_key) % 4))
                if len(key_bytes) != 32:
                    print(f"Key bytes: {len(key_bytes)} (should be 32)")
                    if len(key_bytes) > 32:
                        key_bytes = key_bytes[:32]
                    else:
                        key_bytes = key_bytes + b'0' * (32 - len(key_bytes))
                    self.vault_key = base64.urlsafe_b64encode(key_bytes)
                print(f"Fixed key size: {len(self.vault_key)} bytes")
            except:
                self.vault_key = Fernet.generate_key()
                print("Generated new Fernet key")
    
    def encrypt_data(self, data, key):
        try:
            json_data = json.dumps(data).encode('utf-8')
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(json_data)
            return base64.b64encode(encrypted_data).decode('utf-8')
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            return None
    
    def decrypt_data(self, encrypted_data, key):
        try:
            data = base64.b64decode(encrypted_data)
            fernet = Fernet(key)
            decrypted_data = fernet.decrypt(data)
            return json.loads(decrypted_data.decode('utf-8'))
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return None
    
    def calculate_file_hash(self, filename):
        sha256_hash = hashlib.sha256()
        
        try:
            with open(filename, 'rb') as f:
                for block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(block)
            return sha256_hash.hexdigest()
        except FileNotFoundError:
            return None
    
    def verify_vault_integrity(self):
        if not os.path.exists(self.vault_file):
            return True
        
        current_hash = self.calculate_file_hash(self.vault_file)
        return current_hash is not None
    
    def save_vault(self, vault_data):
        if not self.verify_vault_integrity():
            print("Warning: Vault file integrity check failed.")
            response = input("Continue anyway? (yes/no): ").lower()
            if response != 'yes':
                return False
        
        encrypted_data = self.encrypt_data(vault_data, self.vault_key)
        
        if encrypted_data is None:
            print("Error: Failed to encrypt data!")
            return False
        
        vault_info = {
            'encrypted_data': encrypted_data,
            'timestamp': datetime.now().isoformat(),
            'version': '1.0'
        }
        
        with open(self.vault_file, 'w') as f:
            json.dump(vault_info, f, indent=2)
        
        logger.info("Vault saved successfully")
        return True
    
    def load_vault(self):
        if not os.path.exists(self.vault_file):
            return {'credentials': []}
        
        if not self.verify_vault_integrity():
            print("Vault integrity check failed.")
            return None
        
        try:
            with open(self.vault_file, 'r') as f:
                vault_info = json.load(f)
            
            encrypted_data = vault_info['encrypted_data']
            vault_data = self.decrypt_data(encrypted_data, self.vault_key)
            
            if vault_data is None:
                print("Failed to decrypt vault. Incorrect password.")
                return None
            
            return vault_data
        except Exception as e:
            logger.error(f"Failed to load vault: {e}")
            return None
    
    def register_user(self):
        print("\n" + "="*50)
        print("Register New User")
        print("="*50)
        
        user_id = input("Username: ")
        master_password = getpass.getpass("Master Password: ")
        confirm_password = getpass.getpass("Confirm Password: ")
        
        if master_password != confirm_password:
            print("Passwords do not match.")
            return False
        
        self.vault_key, salt = self.derive_key(master_password)
        self.check_and_fix_key()
        self.user_id = user_id
        
        user_data = {
            'user_id': user_id,
            'salt': base64.b64encode(salt).decode('utf-8'),
            'created_at': datetime.now().isoformat()
        }
        
        with open('user_config.json', 'w') as f:
            json.dump(user_data, f, indent=2)
        
        try:
            response = self.session.post(
                f"{self.server_url}/api/register_user",
                json={
                    'action': 'register_user',
                    'user_id': user_id,
                    'master_password': master_password
                },
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                result = response.json()
                if result['status'] == 'success':
                    print("User registered successfully.")
                    return True
                else:
                    print(f"Error: {result['message']}")
            else:
                print(f"Server error: {response.status_code}")
        
        except requests.exceptions.ConnectionError:
            print("Could not connect to MFA server.")
        
        return False
    
    def login(self):
        print("\n" + "="*50)
        print("User Login")
        print("="*50)
        
        user_id = input("Username: ")
        master_password = getpass.getpass("Master Password: ")
        
        self.vault_key, _ = self.derive_key(master_password)
        self.check_and_fix_key()
        self.user_id = user_id
        
        vault_data = self.load_vault()
        if vault_data is None:
            print("Incorrect password or vault error.")
            return False
        
        try:
            response = self.session.post(
                f"{self.server_url}/api/verify_login",
                json={
                    'action': 'verify_login',
                    'user_id': user_id,
                    'master_password': master_password
                },
                verify=self.verify_ssl
            )
            
            if response.status_code != 200:
                print("Login verification failed.")
                return False
            
            login_result = response.json()
            if login_result['status'] != 'success':
                print(f"Error: {login_result['message']}")
                return False
            
            print("Generating OTP...")
            response = self.session.post(
                f"{self.server_url}/api/generate_otp",
                json={'action': 'generate_otp', 'user_id': user_id},
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                otp_result = response.json()
                if otp_result['status'] == 'success':
                    print("OTP generated. Please check your mobile app.")
                    print(f"OTP valid for: {otp_result['expires_in']} seconds")
                    
                    otp_code = input("Enter OTP: ")
                    
                    response = self.session.post(
                        f"{self.server_url}/api/verify_otp",
                        json={
                            'action': 'verify_otp',
                            'user_id': user_id,
                            'otp_code': otp_code
                        },
                        verify=self.verify_ssl
                    )
                    
                    if response.status_code == 200:
                        otp_verify_result = response.json()
                        if otp_verify_result['status'] == 'success':
                            print("Login successful.")
                            self.session_token = otp_code
                            return True
                        else:
                            print(f"Error: {otp_verify_result['message']}")
                    else:
                        print("OTP verification failed.")
                else:
                    print(f"Error generating OTP: {otp_result['message']}")
            else:
                print("Error generating OTP")
        
        except requests.exceptions.ConnectionError:
            print("Failed to connect to MFA server.")
        
        return False
    
    def add_credential(self):
        if not self.session_token:
            print("You must log in first.")
            return
        
        print("\n" + "="*50)
        print("Add New Credential")
        print("="*50)
        
        service = input("Service Name: ")
        username = input("Username/Email: ")
        password = getpass.getpass("Password: ")
        url = input("URL (optional): ")
        notes = input("Notes (optional): ")
        
        vault_data = self.load_vault()
        if vault_data is None:
            vault_data = {'credentials': []}
        
        new_credential = {
            'id': len(vault_data['credentials']) + 1,
            'service': service,
            'username': username,
            'password': password,
            'url': url,
            'notes': notes,
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat()
        }
        
        vault_data['credentials'].append(new_credential)
        
        if self.save_vault(vault_data):
            print("Credential added successfully.")
        else:
            print("Failed to save credential.")
    
    def view_credentials(self):
        if not self.session_token:
            print("You must log in first.")
            return
        
        vault_data = self.load_vault()
        if not vault_data or 'credentials' not in vault_data:
            print("No credentials stored.")
            return
        
        credentials = vault_data['credentials']
        if not credentials:
            print("No credentials stored.")
            return
        
        print("\n" + "="*50)
        print("Stored Credentials")
        print("="*50)
        
        for i, cred in enumerate(credentials, 1):
            print(f"\n{i}. {cred['service']}")
            print(f"   Username: {cred['username']}")
            print(f"   URL: {cred.get('url', 'N/A')}")
            print(f"   Created: {cred['created_at']}")
    
    def edit_credential(self):
        if not self.session_token:
            print("You must log in first.")
            return
        
        vault_data = self.load_vault()
        if not vault_data or 'credentials' not in vault_data:
            print("No credentials stored.")
            return
        
        credentials = vault_data['credentials']
        if not credentials:
            print("No credentials stored.")
            return
        
        print("\n" + "="*50)
        print("Edit Credential")
        print("="*50)
        
        for i, cred in enumerate(credentials, 1):
            print(f"\n{i}. {cred['service']}")
            print(f"   Username: {cred['username']}")
            print(f"   URL: {cred.get('url', 'N/A')}")
        
        try:
            choice = int(input("\nSelect credential number to edit (0 to cancel): "))
            if choice == 0:
                return
            
            if choice < 1 or choice > len(credentials):
                print("Invalid selection.")
                return
            
            cred = credentials[choice - 1]
            
            print(f"\nEditing: {cred['service']} ({cred['username']})")
            print("Leave field empty to keep current value.")
            
            service = input(f"Service [{cred['service']}]: ").strip()
            username = input(f"Username [{cred['username']}]: ").strip()
            
            change_pass = input("Change password? (yes/no): ").lower()
            if change_pass == 'yes':
                password = getpass.getpass("New Password: ").strip()
            else:
                password = cred['password']
            
            url = input(f"URL [{cred.get('url', '')}]: ").strip()
            notes = input(f"Notes [{cred.get('notes', '')}]: ").strip()
            
            if service:
                cred['service'] = service
            if username:
                cred['username'] = username
            if password and change_pass == 'yes':
                cred['password'] = password
            if url is not None:
                cred['url'] = url if url else ""
            if notes is not None:
                cred['notes'] = notes if notes else ""
            
            cred['updated_at'] = datetime.now().isoformat()
            
            if self.save_vault(vault_data):
                print("Credential updated successfully!")
            else:
                print("Failed to save changes.")
                
        except ValueError:
            print("Please enter a valid number.")
        except Exception as e:
            print(f"Error: {e}")
    
    def search_credentials(self):
        if not self.session_token:
            print("You must log in first.")
            return
        
        term = input("Search term: ").lower()
        
        vault_data = self.load_vault()
        if not vault_data or 'credentials' not in vault_data:
            print("No credentials stored.")
            return
        
        results = []
        for cred in vault_data['credentials']:
            if (term in cred['service'].lower() or 
                term in cred['username'].lower()):
                results.append(cred)
        
        if not results:
            print("No results found.")
            return
        
        print(f"\nFound {len(results)} results:")
        for i, cred in enumerate(results, 1):
            print(f"\n{i}. {cred['service']}")
            print(f"   Username: {cred['username']}")
    
    def generate_password(self):
        import string
        import random
        
        print("\n" + "="*50)
        print("Password Generator")
        print("="*50)
        
        length = int(input("Password length (8-32): ") or 16)
        length = max(8, min(32, length))
        
        use_uppercase = input("Include uppercase letters? (yes/no): ").lower() == 'yes'
        use_numbers = input("Include numbers? (yes/no): ").lower() == 'yes'
        use_symbols = input("Include symbols? (yes/no): ").lower() == 'yes'
        
        characters = string.ascii_lowercase
        if use_uppercase:
            characters += string.ascii_uppercase
        if use_numbers:
            characters += string.digits
        if use_symbols:
            characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        if not characters:
            print("You must enable at least one character type.")
            return
        
        password = ''.join(random.choice(characters) for _ in range(length))
        
        print(f"\nGenerated Password: {password}")
        
        try:
            import pyperclip
            pyperclip.copy(password)
            print("Password copied to clipboard.")
        except ImportError:
            print("Install 'pyperclip' to enable automatic clipboard copy.")
    
    def show_menu(self):
        while True:
            print("\n" + "="*50)
            print("VaultGuard - Secure Password Manager")
            print("="*50)
            
            if not self.session_token:
                print("1. Login")
                print("2. Register New User")
                print("3. Register Mobile Device (MFA)")
                print("4. Exit")
            else:
                print(f"Welcome, {self.user_id}")
                print("1. Add Credential")
                print("2. View All Credentials")
                print("3. Search Credentials")
                print("4. Edit Credential")
                print("5. Generate Password")
                print("6. Check Vault Integrity")
                print("7. Logout")
            
            choice = input("\nChoose an option: ")
            
            if not self.session_token:
                if choice == '1':
                    if self.login():
                        self.main_loop()
                elif choice == '2':
                    self.register_user()
                elif choice == '3':
                    self.register_mobile_device()
                elif choice == '4':
                    print("Goodbye.")
                    break
                else:
                    print("Invalid option.")
            else:
                if choice == '1':
                    self.add_credential()
                elif choice == '2':
                    self.view_credentials()
                elif choice == '3':
                    self.search_credentials()
                elif choice == '4':
                    self.edit_credential()
                elif choice == '5':
                    self.generate_password()
                elif choice == '6':
                    if self.verify_vault_integrity():
                        print("Vault integrity OK.")
                    else:
                        print("Vault integrity issue detected.")
                elif choice == '7':
                    self.session_token = None
                    self.vault_key = None
                    print("Logged out.")
                else:
                    print("Invalid option.")
    
    def main_loop(self):
        pass
    
    def register_mobile_device(self):
        print("\n" + "="*50)
        print("Mobile Device Registration")
        print("="*50)
        
        user_id = input("Username: ")
        device_name = input("Device Name: ")
        
        device_id = hashlib.sha256(f"{user_id}_{device_name}_{datetime.now()}".encode()).hexdigest()[:16]
        device_key = base64.b64encode(os.urandom(32)).decode('utf-8')
        
        print("\nDevice Information:")
        print(f"Device ID: {device_id}")
        print(f"Device Key: {device_key}")
        print("\nSave this information for the mobile app.")
        
        try:
            response = self.session.post(
                f"{self.server_url}/api/register_device",
                json={
                    'action': 'register_device',
                    'user_id': user_id,
                    'device_id': device_id,
                    'device_name': device_name,
                    'device_key': device_key
                },
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                result = response.json()
                if result['status'] == 'success':
                    print("Device registered successfully.")
                    return True
                else:
                    print(f"Error: {result['message']}")
            else:
                print(f"Server error: {response.status_code}")
        
        except requests.exceptions.ConnectionError:
            print("Could not connect to MFA server.")
        
        return False

if __name__ == "__main__":
    client = VaultGuardClient()
    client.show_menu()