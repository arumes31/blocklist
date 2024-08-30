from flask import Flask, request, jsonify, render_template, Response, redirect, url_for, session, send_from_directory, abort
from datetime import datetime, timedelta
import os
import json
import logging
import ipaddress
import redis
import geoip2.database
from pyotp import TOTP
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from redis import Redis

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'supersecretkey')

# Configure logging level based on the LOGWEB environment variable
log_level = logging.INFO if os.getenv('LOGWEB', 'false').lower() == 'true' else logging.WARNING
log_level = logging.DEBUG

# Configure Flask logging
app.logger.setLevel(log_level)

app.logger.info(" ____    ____   ")
app.logger.info("|  _ \  |  _ \  ╔═════════════════════════╗")
app.logger.info("| | | | | |_) | ║    blocklist            ║")
app.logger.info("| |_| | |  _ <  ║    app                  ║")
app.logger.info("|____/  |_| \_\ ╚═════════════════════════╝")
app.logger.info("starting.....")

# Connect to Redis
redis_host = os.getenv('REDIS_HOST', 'redis')
redis_port = int(os.getenv('REDIS_PORT', 6379))
redis_db = int(os.getenv('REDIS_DB', 0))
r = redis.StrictRedis(host=redis_host, port=redis_port, db=redis_db)

# Connect to Redis for rate limiter storage
limiter_redis = redis.StrictRedis(host=os.getenv('REDIS_HOST', 'redis'),
                                  port=int(os.getenv('REDIS_PORT', 6379)),
                                  db=int(os.getenv('REDIS_LIM_DB', 1)))

# Path to the GeoLite2 City database
geoip_db_path = '/usr/share/GeoIP/GeoLite2-City.mmdb'

# Initialize GeoIP reader
geoip_reader = geoip2.database.Reader(geoip_db_path)

# Apply ProxyFix middleware to handle reverse proxy headers
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

def is_valid_ip_range(ip_range):
    """Check if a given IP range is valid."""
    try:
        ipaddress.ip_network(ip_range)
        return True
    except ValueError:
        return False

# Load blocked ranges from environment variable
blocked_ranges_str = os.getenv('BLOCKED_RANGES', '')
blocked_ranges = blocked_ranges_str.split(',')

# Optionally, trim whitespace from each IP range
blocked_ranges = [range.strip() for range in blocked_ranges]

# Filter out any empty strings or invalid IP ranges
blocked_ranges = [range for range in blocked_ranges if range and is_valid_ip_range(range)]

# Format the blocked_ranges for logging
formatted_blocked_ranges = ", ".join([f"'{range}'" for range in blocked_ranges])

# Ensure all ranges are valid before proceeding
for range in blocked_ranges:
    app.logger.info("Valid IP range: '%s'", range)

# Output the loaded blocked_ranges to Flask logger
app.logger.info("Loaded webhook blocked_ranges: %s", blocked_ranges)

# Load allowed IPs for webhook2 from the environment variable
webhook2_allowed_ips_str = os.getenv('WEBHOOK2_ALLOWED_IPS', '127.0.0.1,127.0.0.1')
webhook2_allowed_ips = set(ip.strip() for ip in webhook2_allowed_ips_str.split(','))

# Output the loaded blocked_ranges to Flask logger
app.logger.info("Loaded webhook2_allowed_ips: %s", webhook2_allowed_ips)

####---USER WEBHOOK LOGIN
# Load usernames and passwords from environment variables
USERS = {}
user_count = 1
while True:
    user = os.getenv(f'USER{user_count}', None)
    password = os.getenv(f'UPW{user_count}', None)
    if user is None or password is None:
        break
    USERS[user] = generate_password_hash(password)
    user_count += 1

def webhook_check_auth(username, password):
    """Check if username and password are correct."""
    stored_password_hash = USERS.get(username)
    return stored_password_hash and check_password_hash(stored_password_hash, password)

def webhook_authenticate():
    """Sends a 401 response that enables basic auth."""
    return jsonify({'error': 'Unauthorized'}), 401

def webhook_requires_auth(f):
    """Decorator function to enforce authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.get_json()
        if not auth or not webhook_check_auth(auth.get('username'), auth.get('password')):
            return webhook_authenticate()
        return f(*args, **kwargs)
    return decorated

###---TOTP ADMIN LOGIN
# Load admin credentials and token from environment variables
ADMIN_USERNAME = os.getenv('GUIAdmin')
ADMIN_PASSWORD = os.getenv('GUIPassword')
ADMIN_TOKEN = os.getenv('GUIToken') or random_base32()

# Create TOTP object
totp = TOTP(ADMIN_TOKEN)

# Hash the password once at startup
ADMIN_PASSWORD_HASH = generate_password_hash(ADMIN_PASSWORD)

def check_auth(username, password):
    """Check if username, password, and token are correct."""
    return (username == ADMIN_USERNAME and
            check_password_hash(ADMIN_PASSWORD_HASH, password))

def authenticate():
    """Redirects to login page if authentication fails."""
    return redirect(url_for('login'))

def login_required(f):
    """Decorator function to enforce login."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return authenticate()
        return f(*args, **kwargs)
    return decorated_function

def get_client_ip():
    """Get the real client IP address using X-Forwarded-For header or request.remote_addr"""
    return request.headers.get('X-Forwarded-For', request.remote_addr)

# Initialize Flask-Limiter specifying custom key_func // RateLimiter
limiter = Limiter(
    key_func=get_client_ip,
    app=app,
    storage_uri=f"redis://{os.getenv('REDIS_HOST', 'localhost')}:{os.getenv('REDIS_PORT', 6379)}/{os.getenv('REDIS_LIM_DB', 1)}",
    default_limits=["100 per minute"]
)

#Validate-BlockedIPs
def is_valid_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        for range in blocked_ranges:
            if ip_obj in ipaddress.ip_network(range):
                return False
        return True
    except ValueError:
        return False

#Ignore-BlockedIPs
def is_valid_ip_webhook2(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def get_geoip_data(ip):
    """Get geolocation data for an IP address."""
    try:
        response = geoip_reader.city(ip)
        return {
            'country': response.country.iso_code,
            'city': response.city.name,
            'latitude': response.location.latitude,
            'longitude': response.location.longitude
        }
    except geoip2.errors.AddressNotFoundError:
        app.logger.warning(f"GeoIP data not found for IP: {ip}")
        return None
    except Exception as e:
        app.logger.error(f"Error fetching GeoIP data for IP {ip}: {e}")
        return None

@app.route('/')
def index():
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        token = request.form.get('token')

        # Debug prints to verify credentials
        # app.logger.debug(f"Submitted username: {username}")
        # app.logger.debug(f"Submitted password: {password}")
        # app.logger.debug(f"Submitted token: {token}")
        # app.logger.debug(f"Expected username: {ADMIN_USERNAME}")
        # app.logger.debug(f"Expected token: {ADMIN_TOKEN}")
        # app.logger.debug(f"Password hash check: {check_password_hash(ADMIN_PASSWORD_HASH, password)}")

        # Get the remote client IP address
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)

        # Verify TOTP token
        if check_auth(username, password) and totp.verify(token):
            session['logged_in'] = True
            app.logger.info("Admin User logged in successfully from IP: %s", client_ip)
            redirect_url = request.url_root + 'dashboard'
            return redirect(redirect_url)
        else:
            app.logger.warning("Failed login attempt for username '%s' from IP: %s", username, client_ip)
            return render_template('login.html', error='Invalid credentials')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    ips_with_dates = r.hgetall('ips')
    decoded_ips_with_dates = {}

    for ip, date in ips_with_dates.items():
        ip_str = ip.decode('utf-8')
        date_str = date.decode('utf-8')
        try:
            decoded_ips_with_dates[ip_str] = json.loads(date_str)
        except json.JSONDecodeError as e:
            app.logger.error(f"Error decoding JSON for IP {ip_str}: {e}")
            decoded_ips_with_dates[ip_str] = {"error": "invalid JSON format", "data": date_str}

    total_ips = len(decoded_ips_with_dates)  # Get the total number of IPs
    return render_template('dashboard.html', ips_with_dates=decoded_ips_with_dates, total_ips=total_ips)

@app.route('/unblock', methods=['POST'])
@login_required
def unblock():
    data = request.get_json()
    ip_to_unblock = data.get('ip')

    if ip_to_unblock:
        r.hdel('ips', ip_to_unblock)
        return jsonify({'status': 'success'}), 200
    else:
        return jsonify({'status': 'missing IP'}), 400

@app.route('/block', methods=['POST'])
@login_required
def block():
    data = request.get_json()
    ip_to_block = data.get('ip')
    persist = data.get('persist')
    reason = '~~manually-added'

    if os.getenv('LOGWEB', 'false').lower() == 'true':
        app.logger.info(f"Blocking IP: {ip_to_block}")

    if ip_to_block and is_valid_ip(ip_to_block):
        current_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        if persist:
            current_time = datetime.utcnow()
            current_time += timedelta(days=70000)
            current_time = current_time.strftime('%Y-%m-%d %H:%M:%S UTC')
            reason = '~~manually-added--persist'
        geo_data = get_geoip_data(ip_to_block)
        entry_data = {
            'timestamp': current_time,
            'geolocation': geo_data,
            'reason': reason
        }
        r.hset('ips', ip_to_block, json.dumps(entry_data))
        return jsonify({'status': 'success'}), 200
    else:
        return jsonify({'status': 'invalid IP'}), 400

@app.route('/webhook', methods=['POST'])
@webhook_requires_auth
def webhook():
    data = request.get_json()
    ip = data.get('ip')
    reason = data.get('reason', 'none')
    act = data.get('act', 'ban')

    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)

    if os.getenv('LOGWEB', 'false').lower() == 'true':
        app.logger.info(f"Incoming webhook from {client_ip}: {json.dumps(data)}")

    if ip and is_valid_ip(ip):
        if act in ['ban', 'ban-ip']:
            current_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
            geo_data = get_geoip_data(ip)
            entry_data = {
                'timestamp': current_time,
                'geolocation': geo_data,
                'reason': reason
            }
            r.hset('ips', ip, json.dumps(entry_data))
            return jsonify({'status': 'IP banned', 'ip': ip}), 200
        elif act in ['unban', 'delete-ban']:
            if r.hexists('ips', ip):
                r.hdel('ips', ip)
                return jsonify({'status': 'IP unbanned', 'ip': ip}), 200
            else:
                return jsonify({'status': 'IP not found', 'ip': ip}), 404
        else:
            return jsonify({'status': 'action not implemented', 'action': act}), 501
    else:
        return jsonify({'status': 'invalid IP'}), 400

@app.route('/webhook2_whitelist', methods=['POST'])
@webhook_requires_auth
def webhook2():
    data = request.get_json()
    act = data.get('act', 'add')

    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    ip = client_ip

    if os.getenv('LOGWEB', 'false').lower() == 'true':
        app.logger.info(f"Incoming webhook2 from {client_ip}: {json.dumps(data)}")

    if ip and is_valid_ip_webhook2(ip):
        if act in ['add']:
            current_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
            geo_data = get_geoip_data(ip)
            entry_data = {
                'timestamp': current_time,
                'geolocation': geo_data
            }
            r.hset('ips_webhook2_whitelist', ip, json.dumps(entry_data))
            return jsonify({'status': 'IP added', 'ip': ip}), 200
        else:
            return jsonify({'status': 'action not implemented', 'action': act}), 501
    else:
        return jsonify({'status': 'invalid IP'}), 400

@app.route('/raw', methods=['GET'])
@limiter.limit("3 per minute")
def raw_ips():
    ips = r.hkeys('ips')
    ip_list = "\n".join(ip.decode('utf-8') for ip in ips)
    return Response(ip_list, mimetype='text/plain')
    
@app.route('/raw_whitelist', methods=['GET'])
@limiter.limit("3 per minute")
def raw_ips_whitelist():
    client_ip = request.remote_addr
    if client_ip not in webhook2_allowed_ips:
        app.logger.warning(f"Unauthorized access attempt from IP: {client_ip}")
        abort(403)  # Forbidden
    ips = r.hkeys('ips_webhook2_whitelist')
    ip_list = "\n".join(ip.decode('utf-8') for ip in ips)
    return Response(ip_list, mimetype='text/plain')

@app.route('/ips', methods=['GET'])
@limiter.limit("3 per minute")
def get_ips():
    ips = r.hkeys('ips')
    return jsonify([ip.decode('utf-8') for ip in ips])

@app.route('/js/<path:filename>')
@limiter.limit("20 per minute")
def serve_js(filename):
    return send_from_directory('static/js', filename)

@app.route('/cd/<path:filename>')
@limiter.limit("20 per minute")
def serve_cd(filename):
    return send_from_directory('static/cd', filename)
    
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
