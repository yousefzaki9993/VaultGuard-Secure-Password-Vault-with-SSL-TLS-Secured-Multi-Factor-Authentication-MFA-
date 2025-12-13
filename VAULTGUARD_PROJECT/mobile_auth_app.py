"""
VaultGuard Mobile Authentication App
Mobile simulation app for receiving OTP codes
"""
import json
import requests
import time
import os
import sys
import logging
from datetime import datetime
import hashlib
import base64

# Logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class MobileAuthApp:
    def __init__(self, server_url='https://localhost:8443'):
        self.server_url = server_url
        self.device_id = None
        self.device_key = None
        self.user_id = None
        self.verify_ssl = False
        
        # Requests session
        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        if not self.verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Config file
        self.config_file = 'mobile_config.json'
    
    def load_config(self):
        """Load saved configuration"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                
                self.device_id = config.get('device_id')
                self.device_key = config.get('device_key')
                self.user_id = config.get('user_id')
                return True
            except Exception as e:
                logger.error(f"Error loading config: {e}")
        
        return False
    
    def save_config(self):
        """Save configuration"""
        config = {
            'device_id': self.device_id,
            'device_key': self.device_key,
            'user_id': self.user_id,
            'last_updated': datetime.now().isoformat()
        }
        
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Error saving config: {e}")
            return False
    
    def register_device(self):
        """Register device with the server"""
        print("\n" + "="*50)
        print("Register New Mobile Device")
        print("="*50)
        
        if self.load_config():
            print("A device is already registered.")
            print(f"User: {self.user_id}")
            print(f"Device ID: {self.device_id}")
            response = input("Do you want to register a new device? (yes/no): ").lower()
            if response != 'yes':
                return True
        
        print("\nEnter registration details:")
        user_id = input("User ID: ")
        device_id = input("Device ID (from VaultGuard): ")
        device_key = input("Device Key (from VaultGuard): ")
        device_name = input("Device Name (e.g., iPhone 12): ")
        
        # Verify device with server
        try:
            response = self.session.post(
                f"{self.server_url}/api/verify_device",
                json={
                    'action': 'verify_device',
                    'device_id': device_id,
                    'device_key': device_key
                },
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                result = response.json()
                if result['status'] == 'success':
                    self.device_id = device_id
                    self.device_key = device_key
                    self.user_id = user_id
                    
                    if self.save_config():
                        print("Device registered successfully!")
                        return True
                    else:
                        print("Error saving config.")
                else:
                    print(f"Error: {result['message']}")
            else:
                print(f"Server communication error: {response.status_code}")
        
        except requests.exceptions.ConnectionError:
            print("Could not connect to MFA server. Make sure the server is running.")
        
        return False
    
    def get_otp(self):
        """Request new OTP"""
        if not self.device_id or not self.device_key:
            print("You must register the device first!")
            return
        
        print(f"\nRequesting OTP for user: {self.user_id}")
        
        # Verify device
        try:
            verify_response = self.session.post(
                f"{self.server_url}/api/verify_device",
                json={
                    'action': 'verify_device',
                    'device_id': self.device_id,
                    'device_key': self.device_key
                },
                verify=self.verify_ssl
            )
            
            if verify_response.status_code != 200:
                print("Device verification failed")
                return
            
            verify_result = verify_response.json()
            if verify_result['status'] != 'success':
                print(f"Verification error: {verify_result['message']}")
                return
            
            # Request OTP
            response = self.session.post(
                f"{self.server_url}/api/generate_otp",
                json={
                    'action': 'generate_otp',
                    'user_id': self.user_id
                },
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                result = response.json()
                if result['status'] == 'success':
                    otp = result['otp']
                    expires_in = result['expires_in']
                    timestamp = result['timestamp']
                    
                    print("\n" + "="*50)
                    print("🔐 VaultGuard - OTP Code")
                    print("="*50)
                    print(f"User: {self.user_id}")
                    print(f"OTP: {otp}")
                    print(f"Valid For: {expires_in} seconds")
                    print(f"Time: {timestamp}")
                    print("="*50)
                    print("\nUse this code to log in to VaultGuard.")
                    
                    # Countdown timer
                    self.show_countdown(expires_in, otp)
                    
                    return otp
                else:
                    print(f"Error: {result['message']}")
            else:
                print(f"Server communication error: {response.status_code}")
        
        except requests.exceptions.ConnectionError:
            print("Could not connect to MFA server. Make sure the server is running.")
    
    def show_countdown(self, seconds, otp):
        """Display countdown for OTP expiration"""
        import threading
        
        def countdown():
            remaining = seconds
            while remaining > 0:
                mins, secs = divmod(remaining, 60)
                timer = f"{mins:02d}:{secs:02d}"
                print(f"⏳ OTP expires in: {timer}", end='\r')
                time.sleep(1)
                remaining -= 1
            
            print("\n❌ OTP has expired!                        ")
        
        countdown_thread = threading.Thread(target=countdown)
        countdown_thread.daemon = True
        countdown_thread.start()
    
    def monitor_otp_requests(self):
        """Automatically detect OTP requests"""
        if not self.device_id or not self.device_key:
            print("You must register the device first!")
            return
        
        print("\n" + "="*50)
        print("Automatic OTP Request Monitoring")
        print("="*50)
        print("Monitoring OTP requests...")
        print("Press Ctrl+C to stop")
        print("="*50)
        
        try:
            while True:
                try:
                    response = self.session.post(
                        f"{self.server_url}/api/check_otp_requests",
                        json={
                            'action': 'check_otp_requests',
                            'device_id': self.device_id,
                            'device_key': self.device_key
                        },
                        verify=self.verify_ssl
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        if result['status'] == 'success' and result.get('has_pending'):
                            print("\n📱 New login request detected!")
                            self.get_otp()
                
                except requests.exceptions.ConnectionError:
                    print("Connection lost. Retrying...")
                
                time.sleep(10)
        
        except KeyboardInterrupt:
            print("\nMonitoring stopped.")
    
    def show_menu(self):
        """Main app menu"""
        while True:
            print("\n" + "="*50)
            print("📱 VaultGuard Mobile Authentication App")
            print("="*50)
            
            if self.user_id:
                print(f"User: {self.user_id}")
                print(f"Device ID: {self.device_id}")
                print("="*50)
            
            print("1. Register New Device")
            print("2. Get OTP")
            print("3. Monitor OTP Requests Automatically")
            print("4. Show Device Info")
            print("5. Exit")
            
            choice = input("\nChoose an option: ")
            
            if choice == '1':
                self.register_device()
            elif choice == '2':
                self.get_otp()
            elif choice == '3':
                self.monitor_otp_requests()
            elif choice == '4':
                self.show_device_info()
            elif choice == '5':
                print("Thank you for using VaultGuard Mobile!")
                break
            else:
                print("Invalid option!")
    
    def show_device_info(self):
        """Display device info"""
        if not self.user_id:
            print("No device registered.")
            return
        
        print("\n" + "="*50)
        print("Device Information")
        print("="*50)
        print(f"User: {self.user_id}")
        print(f"Device ID: {self.device_id}")
        print(f"Device Key: {self.device_key[:20]}...")
        
        if os.path.exists(self.config_file):
            stat = os.stat(self.config_file)
            print(f"Last Updated: {datetime.fromtimestamp(stat.st_mtime)}")
        
        print("="*50)

# Main function
if __name__ == "__main__":
    app = MobileAuthApp()
    
    # Auto-load configuration
    if app.load_config():
        print(f"Configuration loaded for user: {app.user_id}")
    
    app.show_menu()
