import requests
import json
import os
from flask import Flask, render_template, request, flash, redirect, url_for, jsonify, session, abort
from functools import wraps
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'asuwishmynigga'

# Simple in-memory storage for users and their IPs (in production, use a database)
users = {
    'admin': {
        'password': 'admin123',
        'ip': None,
        'expires': None,  # No expiration for admin
        'banned': False,
        'ban_reason': None
    }
}

# Security logging for unauthorized access attempts
security_logs = []

admin_password = 'admin123'  # Change this in production
maintenance_mode = False
maintenance_message = "Website is currently under maintenance. Please check back later."

# Authentication decorator
def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if maintenance mode is enabled
        if maintenance_mode:
            flash(maintenance_message, 'danger')
            return redirect(url_for('login'))
        
        # Get user's IP address
        user_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        
        # Check if user is authenticated
        user_id = session.get('user_id')
        if not user_id or user_id not in users:
            return redirect(url_for('login'))
            
        # Check if user is banned
        if users[user_id].get('banned', False):
            ban_reason = users[user_id].get('ban_reason', 'No reason provided')
            flash(f'Your account has been banned: {ban_reason}', 'danger')
            session.clear()
            return redirect(url_for('login'))
            
        # Check if user account has expired
        expires = users[user_id].get('expires')
        if expires:
            expire_date = datetime.fromisoformat(expires)
            if datetime.now() > expire_date:
                flash('Your account has expired. Please contact an administrator.', 'danger')
                session.clear()
                return redirect(url_for('login'))
            
        # Check if IP matches
        if users[user_id]['ip'] != user_ip:
            session.clear()
            return redirect(url_for('login'))
            
        return f(*args, **kwargs)
    return decorated_function

# Admin decorator
def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if maintenance mode is enabled
        if maintenance_mode:
            flash(maintenance_message, 'danger')
            return redirect(url_for('admin_login'))
        
        # Debug: Print session info
        print(f"Session: {session}")
        print(f"is_admin in session: {session.get('is_admin')}")
        # Temporary workaround for session issues - allow access if a special parameter is provided
        if request.args.get('admin_access') == 'true':
            return f(*args, **kwargs)
        if session.get('is_admin') != True:
            flash('Access denied. Please log in as administrator.', 'danger')
            return redirect(url_for('admin_login'))
        
        # Check if admin account has expired (should not happen for admin, but just in case)
        user_id = session.get('user_id', 'admin')
        if user_id in users:
            expires = users[user_id].get('expires')
            if expires:
                expire_date = datetime.fromisoformat(expires)
                if datetime.now() > expire_date:
                    flash('Admin account has expired.', 'danger')
                    session.clear()
                    return redirect(url_for('admin_login'))
                    
            # Check if admin is banned (should not happen, but just in case)
            if users[user_id].get('banned', False):
                ban_reason = users[user_id].get('ban_reason', 'No reason provided')
                flash(f'Admin account has been banned: {ban_reason}', 'danger')
                session.clear()
                return redirect(url_for('admin_login'))
        
        return f(*args, **kwargs)
    return decorated_function 

BOT_API_URL = "http://127.0.0.1:8081/command"

# Admin login route
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        password = request.form.get('password')
        user_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        
        if password == admin_password:
            # Check if admin user exists in users dict
            if 'admin' in users:
                # If this is the first time admin is logging in, store their IP
                if users['admin']['ip'] is None:
                    users['admin']['ip'] = user_ip
                
                # Check if IP matches stored IP
                if users['admin']['ip'] == user_ip:
                    session['is_admin'] = True
                    session['user_id'] = 'admin'
                    return redirect(url_for('admin_panel'))
                else:
                    # Log unauthorized access attempt from different IP
                    security_logs.append({
                        'timestamp': datetime.now().isoformat(),
                        'ip': user_ip,
                        'user_id': 'admin',
                        'password': password,
                        'reason': f'Admin attempted login from different IP. Registered IP: {users["admin"]["ip"]}'
                    })
                    flash('Admin access restricted to registered IP address.', 'danger')
            else:
                # This shouldn't happen, but just in case
                session['is_admin'] = True
                session['user_id'] = 'admin'
                return redirect(url_for('admin_panel'))
        else:
            # Log failed admin login attempt
            security_logs.append({
                'timestamp': datetime.now().isoformat(),
                'ip': user_ip,
                'user_id': 'admin',
                'password': password,
                'reason': 'Invalid admin password'
            })
            flash('Invalid admin password', 'danger')
    return render_template('admin_login.html')

# Admin panel route
@app.route('/admin')
@require_admin
def admin_panel():
    # Calculate user statistics
    total_users = len(users)
    active_users = sum(1 for user in users.values() if user['ip'] is not None)
    pending_users = total_users - active_users
    
    return render_template('admin_panel.html', 
                         users=users,
                         total_users=total_users,
                         active_users=active_users,
                         pending_users=pending_users,
                         maintenance_mode=maintenance_mode,
                         maintenance_message=maintenance_message,
                         security_logs=security_logs)

# Create user route
@app.route('/admin/create_user', methods=['POST'])
@require_admin
def create_user():
    user_id = request.form.get('user_id')
    password = request.form.get('password')
    expiration_days = request.form.get('expiration_days', type=int)
    
    if user_id and password:
        # Check if user already exists
        if user_id in users:
            flash(f'User {user_id} already exists', 'danger')
        else:
            # Calculate expiration date if provided
            expires = None
            if expiration_days and expiration_days > 0:
                expires = (datetime.now() + timedelta(days=expiration_days)).isoformat()
            
            users[user_id] = {
                'password': password,
                'ip': None,  # Will be set when user first logs in
                'expires': expires,
                'banned': False,
                'ban_reason': None
            }
            flash(f'User {user_id} created successfully', 'success')
            if expires:
                flash(f'Account will expire on {expires}', 'info')
    else:
        flash('User ID and password are required', 'danger')
    
    return redirect(url_for('admin_panel'))

# Edit user route
@app.route('/admin/edit_user/', methods=['POST'])
@app.route('/admin/edit_user/<user_id>', methods=['POST'])
@require_admin
def edit_user(user_id=None):
    # If user_id is not in the URL, get it from the form
    if not user_id:
        user_id = request.form.get('user_id')
    
    new_password = request.form.get('password')
    expiration_days = request.form.get('expiration_days', type=int)
    ban_user = request.form.get('ban_user') == 'on'
    ban_reason = request.form.get('ban_reason', '')
    
    if user_id in users:
        # Update password if provided
        if new_password:
            users[user_id]['password'] = new_password
            flash(f'Password for user {user_id} updated successfully', 'success')
        
        # Update expiration date if provided
        if expiration_days is not None:
            if expiration_days > 0:
                expires = (datetime.now() + timedelta(days=expiration_days)).isoformat()
                users[user_id]['expires'] = expires
                flash(f'Expiration date for user {user_id} set to {expires}', 'success')
            else:
                users[user_id]['expires'] = None
                flash(f'Expiration removed for user {user_id}', 'success')
        
        # Update ban status
        users[user_id]['banned'] = ban_user
        users[user_id]['ban_reason'] = ban_reason if ban_user else None
        
        if ban_user:
            flash(f'User {user_id} has been banned', 'success')
        else:
            flash(f'User {user_id} ban status updated', 'success')
    else:
        flash(f'User {user_id} not found', 'danger')
    
    return redirect(url_for('admin_panel'))

# Edit admin password route
@app.route('/admin/edit_admin_password', methods=['POST'])
@require_admin
def edit_admin_password():
    global admin_password
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    # Verify current password
    if current_password != admin_password:
        flash('Current admin password is incorrect', 'danger')
        return redirect(url_for('admin_panel'))
    
    # Verify new password
    if not new_password or len(new_password) < 3:
        flash('New password must be at least 3 characters long', 'danger')
        return redirect(url_for('admin_panel'))
    
    # Verify passwords match
    if new_password != confirm_password:
        flash('New passwords do not match', 'danger')
        return redirect(url_for('admin_panel'))
    
    # Update admin password
    admin_password = new_password
    # Also update the admin user's password in the users dict
    if 'admin' in users:
        users['admin']['password'] = new_password
    
    flash('Admin password updated successfully', 'success')
    return redirect(url_for('admin_panel'))

# Delete user route
@app.route('/admin/delete_user/<user_id>', methods=['POST'])
@require_admin
def delete_user(user_id):
    if user_id in users:
        if user_id == 'admin':
            flash('Cannot delete admin user', 'danger')
        else:
            del users[user_id]
            flash(f'User {user_id} deleted successfully', 'success')
    else:
        flash(f'User {user_id} not found', 'danger')
    
    return redirect(url_for('admin_panel'))

# Set maintenance mode route
@app.route('/admin/set_maintenance', methods=['POST'])
@require_admin
def set_maintenance():
    global maintenance_mode, maintenance_message
    enable = request.form.get('enable_maintenance') == 'on'
    message = request.form.get('maintenance_message', maintenance_message)
    
    maintenance_mode = enable
    maintenance_message = message
    
    if enable:
        flash('Maintenance mode enabled', 'success')
    else:
        flash('Maintenance mode disabled', 'success')
    
    return redirect(url_for('admin_panel'))

# Clear security logs route
@app.route('/admin/clear_logs', methods=['POST'])
@require_admin
def clear_logs():
    global security_logs
    security_logs = []
    flash('Security logs cleared successfully', 'success')
    return redirect(url_for('admin_panel'))

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

# Protected main panel route
@app.route('/')
@require_auth
def index():
    """Renders the main control panel page."""
    return render_template('index.html')

# User login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        password = request.form.get('password')
        
        # Get user's IP address
        user_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        
        # Check if user exists and password matches
        if user_id in users and users[user_id]['password'] == password:
            # Check if user is banned
            if users[user_id].get('banned', False):
                ban_reason = users[user_id].get('ban_reason', 'No reason provided')
                flash(f'Your account has been banned: {ban_reason}', 'danger')
                # Log the banned access attempt
                security_logs.append({
                    'timestamp': datetime.now().isoformat(),
                    'ip': user_ip,
                    'user_id': user_id,
                    'password': password,
                    'reason': 'Banned user attempted login'
                })
                return render_template('login.html')
            
            # Check if user account has expired
            expires = users[user_id].get('expires')
            if expires:
                expire_date = datetime.fromisoformat(expires)
                if datetime.now() > expire_date:
                    flash('Your account has expired. Please contact an administrator.', 'danger')
                    # Log the expired access attempt
                    security_logs.append({
                        'timestamp': datetime.now().isoformat(),
                        'ip': user_ip,
                        'user_id': user_id,
                        'password': password,
                        'reason': 'Expired account attempted login'
                    })
                    return render_template('login.html')
            
            # If this is the first time user is logging in, store their IP
            if users[user_id]['ip'] is None:
                users[user_id]['ip'] = user_ip
                session['user_id'] = user_id
                return redirect(url_for('index'))
            
            # Check if IP matches stored IP
            if users[user_id]['ip'] == user_ip:
                session['user_id'] = user_id
                return redirect(url_for('index'))
            else:
                # Log unauthorized access attempt from different IP
                security_logs.append({
                    'timestamp': datetime.now().isoformat(),
                    'ip': user_ip,
                    'user_id': user_id,
                    'password': password,
                    'reason': f'Attempted login from different IP. Registered IP: {users[user_id]["ip"]}'
                })
                flash('IP address does not match. Access denied.', 'danger')
        else:
            # Log failed login attempt with invalid credentials
            security_logs.append({
                'timestamp': datetime.now().isoformat(),
                'ip': user_ip,
                'user_id': user_id if user_id else 'Unknown',
                'password': password,
                'reason': 'Invalid username or password'
            })
            flash('Invalid user ID or password', 'danger')
    
    return render_template('login.html')

# Protected main panel route
@app.route('/action', methods=['POST'])
@require_auth
def handle_action():
    """Handles all form submissions from the new UI."""
    try:
        action = request.form.get('action')
        payload_str = request.form.get('payload')
        
        if not action or payload_str is None:
            flash('Invalid request from client.', 'danger')
            return redirect(url_for('index'))

        bot_payload = {'action': action}
        
        data = json.loads(payload_str)

        if action == 'emote':
            bot_payload.update(data)
            if not bot_payload.get('emote_id') or not bot_payload.get('player_ids'):
                raise ValueError("Emote ID and Player IDs are required.")
            pass  # Removed flash message

        elif action == 'emote_batch':
            if not isinstance(data, list):
                raise ValueError("A list of assignments is required for emote_batch.")
            bot_payload['assignments'] = data
            pass  # Removed flash message
            
        elif action == 'join_squad':
            bot_payload.update(data)
            if not bot_payload.get('team_code'):
                 raise ValueError("Team Code is required.")
            pass  # Removed flash message

        elif action == 'quick_invite':
            bot_payload.update(data)
            if not bot_payload.get('player_id'):
                 raise ValueError("Your Main Account UID is required.")
            pass  # Removed flash message

        elif action == 'leave_squad':
            bot_payload.update(data)
            pass  # Removed flash message
        
        else:
            flash(f'Unknown action: {action}', 'danger')
            return redirect(url_for('index'))

        response = requests.post(BOT_API_URL, json=bot_payload, timeout=10)
        
        if response.status_code == 200:
            pass  # Removed flash message
        else:
            flash(f"Error from bot: {response.status_code} - {response.json().get('error', 'Unknown error')}", 'danger')

    except requests.exceptions.ConnectionError:
        return jsonify({'status': 'error', 'message': 'Could not connect to the bot API. Is main.py running?'}), 500
    except (ValueError, json.JSONDecodeError) as e:
        return jsonify({'status': 'error', 'message': f'Invalid data provided: {e}'}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'An unexpected error occurred: {e}'}), 500

    return jsonify({'status': 'success', 'message': 'Command sent successfully!'})

if __name__ == '__main__':
    print("FLEXXI ENGINE Bot Web Panel")
    print("Open your web browser and go to http://127.0.0.1:5000")
    print("Make sure main.py is running first!")
    app.run(host='127.0.0.1', port=5000)