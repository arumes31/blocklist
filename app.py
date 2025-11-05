from gevent import monkey
monkey.patch_all()

from flask import Flask, request, jsonify, render_template, Response, redirect, url_for, session, send_from_directory, abort, send_file
from datetime import datetime, timedelta
import os
import json
import logging
import ipaddress
import redis
import geoip2.database
import requests
from pyotp import TOTP, random_base32
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from redis import Redis
import secrets
from io import BytesIO
import qrcode
import base64
import time
import threading

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'supersecretkey')
app.permanent_session_lifetime = timedelta(hours=1)

# Configure logging level based on the LOGWEB environment variable
log_level = logging.INFO if os.getenv('LOGWEB', 'false').lower() == 'true' else logging.WARNING
log_level = logging.DEBUG

# Configure Flask logging
app.logger.setLevel(log_level)

# Version
app.logger.info("V1.8c")
app.logger.info("----------------")
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
pool = redis.ConnectionPool(host=redis_host, port=redis_port, db=redis_db, decode_responses=False)
r = redis.Redis(connection_pool=pool)

# Connect to Redis for rate limiter storage
limiter_redis = redis.StrictRedis(host=os.getenv('REDIS_HOST', 'redis'),
                                  port=int(os.getenv('REDIS_PORT', 6379)),
                                  db=int(os.getenv('REDIS_LIM_DB', 1)))

# Path to the GeoLite2 City database
geoip_db_path = '/usr/share/GeoIP/GeoLite2-City.mmdb'

# Initialize GeoIP reader
geoip_reader = None
try:
    geoip_reader = geoip2.database.Reader(geoip_db_path)
    app.logger.info("GeoIP database loaded successfully.")
except Exception as e:
    app.logger.warning(f"Failed to load GeoIP database: {e}. GeoIP features will be disabled.")

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

# Function to get all admin accounts, combining env vars with Redis
def get_admin_accounts():
    admin_accounts = {
        ADMIN_USERNAME: {
            'password_hash': generate_password_hash(ADMIN_PASSWORD),
            'token': ADMIN_TOKEN
        }
    }
    try:
        stored_admins = r.hgetall('admin_accounts')
        for username, data in stored_admins.items():
            admin_accounts[username.decode('utf-8')] = json.loads(data.decode('utf-8'))
    except Exception as e:
        app.logger.error(f"Error loading admin accounts from Redis: {e}")
    return admin_accounts

def check_auth(username, password, token):
    """Check if username, password, and token are correct."""
    admin_accounts = get_admin_accounts()
    if username not in admin_accounts:
        return False
    admin_data = admin_accounts[username]
    return (check_password_hash(admin_data['password_hash'], password) and
            TOTP(admin_data['token']).verify(token))

def authenticate():
    """Redirects to login page if authentication fails."""
    return redirect(url_for('login'))

def login_required(f):
    """Decorator function to enforce login, session timeout, and IP consistency."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return authenticate()

        # Check session age
        login_time_str = session.get('login_time')
        if not login_time_str:
            session.clear()
            return authenticate()

        try:
            login_time = datetime.fromisoformat(login_time_str)
            current_time = datetime.utcnow()
            session_age = current_time - login_time
            if session_age > timedelta(hours=1):
                app.logger.info("Session expired for user %s due to 1-hour timeout", session.get('username', 'unknown'))
                session.clear()
                return authenticate()
        except ValueError:
            app.logger.error("Invalid login_time format in session for user %s", session.get('username', 'unknown'))
            session.clear()
            return authenticate()

        # Check client IP
        current_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        stored_ip = session.get('client_ip')
        if not stored_ip or current_ip != stored_ip:
            app.logger.info("Session invalidated for user %s due to IP change (stored: %s, current: %s)",
                           session.get('username', 'unknown'), stored_ip, current_ip)
            session.clear()
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
    default_limits=["200 per minute"]
)

def get_whitelisted_ips():
    try:
        whitelisted_ips = r.hkeys('ips_webhook2_whitelist')
        return set(ip.decode('utf-8') for ip in whitelisted_ips)
    except redis.RedisError as e:
        app.logger.error(f"Error fetching whitelist from Redis: {e}")
        return set()

# Validate-BlockedIPs
def is_valid_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        # Reload whitelist
        whitelisted_ips = get_whitelisted_ips()

        # Check if IP is in the whitelist --> Deny Blocklist Entry
        if ip in whitelisted_ips:
            app.logger.info(f"IP banned FAILED - IP IS WHITELISTED: {ip}")
            return False

        for range in blocked_ranges:
            if ip_obj in ipaddress.ip_network(range):
                app.logger.info(f"IP banned FAILED - IP RANGE IS BLACKLISTED: {ip}")
                return False
        return True
    except ValueError:
        return False

# Ignore-BlockedIPs
def is_valid_ip_webhook2(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def get_geoip_data(ip):
    """Get geolocation data for an IP address."""
    if geoip_reader is None:
        app.logger.debug(f"GeoIP reader not available for IP: {ip}")
        return None
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

def compute_filtered_ips():
    """Compute the list of filtered IPs based on expiration windows."""
    ips = r.hkeys('ips')
    now = datetime.utcnow()
    filtered_ips = []
    delta_high = timedelta(hours=24, minutes=1)
    delta_low = timedelta(hours=23, minutes=54)
    for ip_bytes in ips:
        ip = ip_bytes.decode('utf-8')
        data_bytes = r.hget('ips', ip_bytes)
        if data_bytes:
            try:
                entry = json.loads(data_bytes.decode('utf-8'))
                timestamp_str = entry.get('timestamp')
                if timestamp_str:
                    timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S UTC")
                    expire_time = timestamp + timedelta(hours=24)
                    remaining = expire_time - now
                    if remaining >= delta_high or remaining <= delta_low:
                        filtered_ips.append(ip)
            except (json.JSONDecodeError, ValueError) as e:
                app.logger.error(f"Error processing IP {ip}: {e}")
    return filtered_ips

# Background cache update for /ips_automate
def update_ips_automate_cache():
    cache_key = 'cached_ips_automate'
    lock_key = 'lock_ips_automate_update'
    while True:
        time.sleep(30)  # Update every 30 seconds
        lock = r.lock(lock_key, timeout=60, blocking_timeout=10)
        acquired = False
        try:
            acquired = lock.acquire()
            if acquired:
                filtered_ips = compute_filtered_ips()
                cached_data = json.dumps(filtered_ips)
                r.setex(cache_key, 300, cached_data)  # Cache for 5 minutes
                app.logger.debug("Updated cache for /ips_automate")
        except Exception as e:
            app.logger.error(f"Error updating /ips_automate cache: {e}")
        finally:
            if acquired:
                lock.release()

# Start the background thread
cache_update_thread = threading.Thread(target=update_ips_automate_cache, daemon=True)
cache_update_thread.start()

@app.route('/')
def index():
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        totp = request.form.get('totp')

        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)

        if check_auth(username, password, totp):
            session.permanent = True
            session['logged_in'] = True
            session['username'] = username
            session['login_time'] = datetime.utcnow().isoformat()
            session['client_ip'] = client_ip
            app.logger.info("Admin User %s logged in successfully from IP: %s", username, client_ip)
            redirect_url = request.url_root + 'dashboard'
            return redirect(redirect_url)
        else:
            app.logger.warning("Failed login attempt for username '%s' from IP: %s", username, client_ip)
            return render_template('login.html', error='Invalid credentials')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
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
    reason = data.get('reason', '~~manually-added')
    added_by = session.get('username', 'Unknown')  # Use logged-in username if available

    if os.getenv('LOGWEB', 'false').lower() == 'true':
        app.logger.info(f"Blocking IP: {ip_to_block} by {added_by}")

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
            'reason': reason,
            'added_by': added_by
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
    added_by = 'Webhook'  # Hardcode for webhook bans

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
                'reason': reason,
                'added_by': added_by
            }
            r.hset('ips', ip, json.dumps(entry_data))
            app.logger.info(f"IP banned: {ip}")
            return jsonify({'status': 'IP banned', 'ip': ip}), 200
        elif act in ['unban', 'delete-ban']:
            if r.hexists('ips', ip):
                r.hdel('ips', ip)
                app.logger.info(f"IP unbanned: {ip}")
                return jsonify({'status': 'IP unbanned', 'ip': ip}), 200
            else:
                app.logger.info(f"IP unbanned failed, ip not found in database: {ip}")
                return jsonify({'status': 'IP not found', 'ip': ip}), 404
        else:
            app.logger.info(f"action not implemented")
            return jsonify({'status': 'action not implemented', 'action': act}), 501
    else:
        app.logger.info(f"invalid IP")
        return jsonify({'status': 'invalid IP'}), 400

@app.route('/webhook2_whitelist', methods=['POST'])
@webhook_requires_auth
def webhook2():
    data = request.get_json()
    act = data.get('act', 'add')
    added_by = 'Webhook'  # Hardcode for webhook whitelist

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
                'geolocation': geo_data,
                'added_by': added_by,
                'reason': 'Webhook auto-whitelist'
            }
            r.hset('ips_webhook2_whitelist', ip, json.dumps(entry_data))
            return jsonify({'status': 'IP added', 'ip': ip}), 200
        else:
            return jsonify({'status': 'action not implemented', 'action': act}), 501
    else:
        return jsonify({'status': 'invalid IP'}), 400

@app.route('/raw', methods=['GET'])
@limiter.limit("50 per minute")
def raw_ips():
    ips = r.hkeys('ips')
    ip_list = "\n".join(ip.decode('utf-8') for ip in ips)
    return Response(ip_list, mimetype='text/plain')

@app.route('/raw_whitelist', methods=['GET'])
def raw_ips_whitelist():
    client_ip = request.remote_addr
    if client_ip not in webhook2_allowed_ips:
        app.logger.warning(f"Unauthorized access attempt from IP: {client_ip}")
        abort(403)  # Forbidden

    # Bypass rate limiting for allowed IPs
    if client_ip in webhook2_allowed_ips:
        limiter.enabled = False

    ips = r.hkeys('ips_webhook2_whitelist')
    ip_list = "\n".join(ip.decode('utf-8') for ip in ips)

    if client_ip in webhook2_allowed_ips:
        limiter.enabled = True  # Re-enable limiter for other requests

    return Response(ip_list, mimetype='text/plain')

@app.route('/whitelist', methods=['GET'])
@login_required
def whitelist():
    whitelisted_ips_raw = r.hgetall('ips_webhook2_whitelist')
    whitelisted_ips = {}
    now = datetime.utcnow()

    for ip, data in whitelisted_ips_raw.items():
        ip_str = ip.decode('utf-8')
        try:
            entry = json.loads(data.decode('utf-8'))
            timestamp_str = entry.get('timestamp')
            expires_in = 'Unknown'

            if timestamp_str:
                try:
                    timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S UTC")
                    expire_time = timestamp + timedelta(hours=24)
                    remaining_time = expire_time - now
                    if remaining_time.total_seconds() > 0:
                        hours = int(remaining_time.total_seconds() // 3600)
                        minutes = int((remaining_time.total_seconds() % 3600) // 60)
                        expires_in = f"{hours}h {minutes}m"
                    else:
                        expires_in = "Expired"
                except ValueError:
                    app.logger.error(f"Invalid timestamp format for IP {ip_str}: {timestamp_str}")

            whitelisted_ips[ip_str] = {
                'timestamp': timestamp_str,
                'added_by': entry.get('added_by', 'Unknown'),
                'reason': entry.get('reason', 'No reason provided'),
                'geolocation': entry.get('geolocation', {'country': 'N/A', 'city': 'N/A'}),
                'expires_in': expires_in
            }
        except json.JSONDecodeError:
            app.logger.error(f"Error decoding JSON for IP {ip_str}")
            whitelisted_ips[ip_str] = {'added_by': 'Manually Added', 'reason': 'No reason provided', 'expires_in': 'Unknown'}

    # Load blocked subnets from environment variable
    blocked_subnets = os.getenv('BLOCKED_RANGES', '').split(',')
    blocked_subnets = [subnet.strip() for subnet in blocked_subnets if subnet.strip()]

    return render_template('whitelist.html', whitelisted_ips=whitelisted_ips, blocked_subnets=blocked_subnets)

@app.route('/add_whitelist', methods=['POST'])
@login_required
def add_whitelist():
    data = request.get_json()
    ip_to_whitelist = data.get('ip')
    reason = data.get('reason', 'No reason provided')
    added_by = session.get('username', 'Manually Added')  # Use logged-in username if available

    if ip_to_whitelist and is_valid_ip(ip_to_whitelist):
        current_time = datetime.utcnow() + timedelta(days=70000)
        geo_data = get_geoip_data(ip_to_whitelist)
        entry_data = {
            'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'geolocation': geo_data,
            'added_by': added_by,
            'reason': reason
        }
        r.hset('ips_webhook2_whitelist', ip_to_whitelist, json.dumps(entry_data))

        # Log whitelisted IP, reason, and geolocation data
        if geo_data:
            app.logger.info(f"IP Whitelisted: {ip_to_whitelist}, Country: {geo_data.get('country', 'N/A')}, City: {geo_data.get('city', 'N/A')}, Reason: {reason}, Added By: {added_by}")
        else:
            app.logger.info(f"IP Whitelisted: {ip_to_whitelist}, GeoIP Data: Not Found, Reason: {reason}, Added By: {added_by}")

        return jsonify({'status': 'success'}), 200
    else:
        return jsonify({'status': 'invalid IP'}), 400

@app.route('/remove_whitelist', methods=['POST'])
@login_required
def remove_whitelist():
    data = request.get_json()
    ip_to_remove = data.get('ip')

    if ip_to_remove and r.hexists('ips_webhook2_whitelist', ip_to_remove):
        r.hdel('ips_webhook2_whitelist', ip_to_remove)
        return jsonify({'status': 'success'}), 200
    else:
        return jsonify({'status': 'IP not found'}), 404

@app.route('/benchmark', methods=['GET'])
@limiter.limit("100000 per minute")
def benchmark():
    client_ip = request.remote_addr
    if client_ip not in webhook2_allowed_ips:
        app.logger.warning(f"Unauthorized access attempt from IP: {client_ip}")
        abort(403)  # Forbidden
    return "ok", 200

@app.route('/ips', methods=['GET'])
@limiter.limit("200 per minute")
def get_ips():
    ips = r.hkeys('ips')
    return jsonify([ip.decode('utf-8') for ip in ips])

@app.route('/ips_automate', methods=['GET'])
@limiter.limit("300 per minute")
def get_ips_automate():
    cache_key = 'cached_ips_automate'
    cached = r.get(cache_key)
    if cached:
        app.logger.debug("Serving cached /ips_automate")
        return jsonify(json.loads(cached.decode('utf-8')))
    else:
        app.logger.debug("Cache miss on /ips_automate, returning empty list")
        return jsonify([])

@app.route('/js/<path:filename>')
@limiter.limit("20 per minute")
def serve_js(filename):
    return send_from_directory('static/js', filename)

@app.route('/cd/<path:filename>')
@limiter.limit("20 per minute")
def serve_cd(filename):
    return send_from_directory('static/cd', filename)

# Admin Management Routes
@app.route('/admin_management', methods=['GET'])
@login_required
def admin_management():
    if session.get('username') != ADMIN_USERNAME:
        return jsonify({'error': 'Only GUIAdmin can manage accounts'}), 403

    admin_accounts = get_admin_accounts()
    admin_list = {k: {'token': '******'} for k in admin_accounts.keys()}
    return render_template('admin_management.html', admins=admin_list)

@app.route('/create_admin', methods=['POST'])
@login_required
def create_admin():
    if session.get('username') != ADMIN_USERNAME:
        return jsonify({'error': 'Only GUIAdmin can create accounts'}), 403

    data = request.get_json()
    new_username = data.get('username')
    new_password = data.get('password')

    if not new_username or not new_password:
        return jsonify({'error': 'Username and password are required'}), 400

    admin_accounts = get_admin_accounts()
    if new_username in admin_accounts:
        return jsonify({'error': 'Username already exists'}), 400

    new_token = random_base32()
    new_password_hash = generate_password_hash(new_password)

    admin_data = {
        'password_hash': new_password_hash,
        'token': new_token
    }

    # Store in Redis
    r.hset('admin_accounts', new_username, json.dumps(admin_data))

    return jsonify({'status': 'success', 'username': new_username}), 200

@app.route('/get_qr/<username>', methods=['GET'])
@login_required
def get_qr(username):
    if session.get('username') != ADMIN_USERNAME:
        return jsonify({'error': 'Only GUIAdmin can view QR codes'}), 403

    admin_accounts = get_admin_accounts()
    if username not in admin_accounts:
        return jsonify({'error': 'Admin not found'}), 404

    totp = TOTP(admin_accounts[username]['token'])
    qr_uri = totp.provisioning_uri(username, issuer_name="Blocklist App")

    img = qrcode.make(qr_uri)
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)

    return send_file(buf, mimetype='image/png')

@app.route('/delete_admin', methods=['POST'])
@login_required
def delete_admin():
    if session.get('username') != ADMIN_USERNAME:
        return jsonify({'error': 'Only GUIAdmin can delete accounts'}), 403

    data = request.get_json()
    username_to_delete = data.get('username')

    if username_to_delete == ADMIN_USERNAME:
        return jsonify({'error': 'Cannot delete GUIAdmin'}), 400

    admin_accounts = get_admin_accounts()
    if username_to_delete not in admin_accounts:
        return jsonify({'error': 'Admin not found'}), 404

    r.hdel('admin_accounts', username_to_delete)

    return jsonify({'status': 'success'}), 200

@app.route('/change_admin_password', methods=['POST'])
@login_required
def change_admin_password():
    if session.get('username') != ADMIN_USERNAME:
        return jsonify({'error': 'Only GUIAdmin can change passwords'}), 403

    data = request.get_json()
    username = data.get('username')
    new_password = data.get('new_password')

    if not username or not new_password:
        return jsonify({'error': 'Username and new password are required'}), 400

    admin_accounts = get_admin_accounts()
    if username not in admin_accounts:
        return jsonify({'error': 'Admin not found'}), 404

    if username == ADMIN_USERNAME:
        return jsonify({'error': 'Cannot change GUIAdmin password via this endpoint'}), 400

    # Update password
    admin_data = admin_accounts[username]
    admin_data['password_hash'] = generate_password_hash(new_password)
    r.hset('admin_accounts', username, json.dumps(admin_data))

    app.logger.info(f"Password changed for admin: {username}")
    return jsonify({'status': 'success'}), 200

@app.route('/change_admin_totp', methods=['POST'])
@login_required
def change_admin_totp():
    if session.get('username') != ADMIN_USERNAME:
        return jsonify({'error': 'Only GUIAdmin can change TOTP'}), 403

    data = request.get_json()
    username = data.get('username')

    if not username:
        return jsonify({'error': 'Username is required'}), 400

    admin_accounts = get_admin_accounts()
    if username not in admin_accounts:
        return jsonify({'error': 'Admin not found'}), 404

    if username == ADMIN_USERNAME:
        return jsonify({'error': 'Cannot change GUIAdmin TOTP via this endpoint'}), 400

    # Generate new TOTP token
    admin_data = admin_accounts[username]
    new_token = random_base32()
    admin_data['token'] = new_token
    r.hset('admin_accounts', username, json.dumps(admin_data))

    # Generate QR code image
    totp = TOTP(new_token)
    qr_uri = totp.provisioning_uri(username, issuer_name="Blocklist App")
    img = qrcode.make(qr_uri)
    buf = BytesIO()
    img.save(buf, format="PNG")
    qr_image_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    buf.close()

    app.logger.info(f"TOTP changed for admin: {username}")
    return jsonify({'status': 'success', 'qr_image': f'data:image/png;base64,{qr_image_base64}'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)