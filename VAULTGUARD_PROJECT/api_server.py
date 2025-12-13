"""
VaultGuard REST API Server
API server for VaultGuard applications
"""
from flask import Flask, request, jsonify
import ssl
import logging
from vaultguard_server import MFAServer

app = Flask(__name__)
mfa_server = MFAServer()

# Logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.route('/api/register_user', methods=['POST'])
def api_register_user():
    """API to register a new user"""
    data = request.json
    result = mfa_server.handle_register_user(data)
    return jsonify(result)

@app.route('/api/register_device', methods=['POST'])
def api_register_device():
    """API to register a new device"""
    data = request.json
    result = mfa_server.handle_register_device(data)
    return jsonify(result)

@app.route('/api/verify_device', methods=['POST'])
def api_verify_device():
    """API to verify a device"""
    data = request.json
    result = mfa_server.handle_verify_device(data)
    return jsonify(result)

@app.route('/api/generate_otp', methods=['POST'])
def api_generate_otp():
    """API to generate a new OTP"""
    data = request.json
    result = mfa_server.handle_generate_otp(data)
    return jsonify(result)

@app.route('/api/verify_otp', methods=['POST'])
def api_verify_otp():
    """API to verify an OTP"""
    data = request.json
    result = mfa_server.handle_verify_otp(data)
    return jsonify(result)

@app.route('/api/verify_login', methods=['POST'])
def api_verify_login():
    """API to verify a login attempt"""
    data = request.json
    result = mfa_server.handle_verify_login(data)
    return jsonify(result)

@app.route('/api/check_otp_requests', methods=['POST'])
def api_check_otp_requests():
    """API to check pending OTP requests"""
    data = request.json
    device_id = data.get('device_id')
    device_key = data.get('device_key')
    
    # Verify device
    if not mfa_server.verify_device(device_id, device_key):
        return jsonify({'status': 'error', 'message': 'Device verification failed'})
    
    # Logic for checking pending OTP requests can be added here
    return jsonify({'status': 'success', 'has_pending': False})

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'service': 'VaultGuard MFA Server'})

if __name__ == '__main__':
    # SSL configuration
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('ssl_certs/certificate.pem', 'ssl_certs/private_key.pem')
    
    # Run server
    app.run(host='0.0.0.0', port=8443, ssl_context=context, debug=False)
