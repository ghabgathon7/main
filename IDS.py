from flask import Flask, request, jsonify
from datetime import datetime, timedelta

app = Flask(__name__)

failed_login_attempts = {}

# Define threshold for failed login attempts
FAILED_LOGIN_THRESHOLD = 3
TIME_WINDOW = timedelta(minutes=5)

def log_failed_login_attempt(ip_address):
    """
    Log failed login attempts for each IP address.
    """
    if ip_address in failed_login_attempts:
        failed_login_attempts[ip_address]['count'] += 1
        failed_login_attempts[ip_address]['last_attempt'] = datetime.now()
    else:
        failed_login_attempts[ip_address] = {
            'count': 1,
            'last_attempt': datetime.now()
        }

def check_intrusion(ip_address):
    """
    Check for suspicious login attempts.
    """
    if ip_address in failed_login_attempts:
        attempts_data = failed_login_attempts[ip_address]
        if attempts_data['count'] >= FAILED_LOGIN_THRESHOLD:
            if datetime.now() - attempts_data['last_attempt'] <= TIME_WINDOW:
                return True
    return False

@app.route('/login', methods=['POST'])
def login():
    """
    Endpoint to handle login requests.
    """
    ip_address = request.remote_addr
    if check_intrusion(ip_address):
        # Intrusion detected
        print(f"Suspicious Activity Detected from IP address: {ip_address}")
        return jsonify({'message': 'Suspicious Activity Detected!'}), 403
    else:
        # Perform login logic here
        # For demonstration purposes, check if password is 'password'
        if request.form['password'] == 'password':
            print(f"Login successful from IP address: {ip_address}")
            return jsonify({'message': 'Login successful'}), 200
        else:
            # Log failed login attempt
            log_failed_login_attempt(ip_address)
            print(f"Login failed from IP address: {ip_address}")
            return jsonify({'message': 'Login failed'}), 401

if __name__ == '__main__':
    app.run(debug=True)
