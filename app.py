import os
import time
import uuid
import hashlib
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, jsonify, send_file, g, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import json
import zipfile
from io import BytesIO
import re
from flask_cors import CORS
import unicodedata

# ==================== SECURITY CONFIGURATION ====================
# Forbidden system directories (Linux & Windows)
FORBIDDEN_DIRS = [
    # Linux system directories
    '/', '/root', '/etc', '/bin', '/sbin', '/usr', '/var', '/tmp',
    '/proc', '/sys', '/dev', '/boot', '/lib', '/lib64', '/opt',
    '/home', '/mnt', '/media', '/srv', '/run', '/lost+found',
    '/usr/bin', '/usr/sbin', '/usr/local', '/usr/lib', '/usr/lib64',
    '/var/log', '/var/run', '/var/tmp', '/var/cache', '/var/spool',
    '/etc/passwd', '/etc/shadow', '/etc/hosts', '/etc/fstab',
    '/etc/sudoers', '/etc/ssh', '/etc/nginx', '/etc/apache2',
    '/etc/mysql', '/etc/postgresql', '/etc/redis', '/etc/mongodb',
    '/root/.ssh', '/root/.bash_history', '/root/.bashrc',
    # Windows system directories
    'C:\\', 'D:\\', 'E:\\', 'F:\\', 'C:/', 'D:/', 'E:/', 'F:/',
    'C:\\Windows', 'C:\\Program Files', 'C:\\Program Files (x86)',
    'C:\\Windows\\System32', 'C:\\Windows\\SysWOW64',
    'C:\\Users', 'C:\\Documents and Settings',
    'C:\\ProgramData', 'C:\\Boot', 'C:\\System Volume Information',
    # Path traversal patterns
    '..', '../', '..\\', './../', '.\\..\\',
    # Special patterns
    '~', '~/', '~\\',
]

# Hidden/system files to block
FORBIDDEN_FILES = [
    '.htaccess', '.htpasswd', '.git', '.svn', '.env',
    'config.php', 'wp-config.php', 'settings.py',
    'passwd', 'shadow', 'sudoers', 'fstab',
    '.bash_history', '.bashrc', '.profile', '.ssh',
    'id_rsa', 'id_dsa', 'known_hosts',
    '.npmrc', '.pypirc', '.dockercfg', '.kube',
]

# Path traversal patterns
PATH_TRAVERSAL_PATTERNS = [
    '..', '../', '..\\', './../', '.\\..\\',
    '%2e%2e', '%2e%2e%2f', '%2e%2e%5c',
    '%252e%252e', '%252e%252e%252f',
    '%c0%ae%c0%ae', '%c0%ae%c0%ae%c0%af',
]

def safe_filename(filename):
    """
    Safe filename handling with Chinese character support
    Preserves Chinese, letters, numbers, dots, underscores, hyphens
    """
    if '.' in filename:
        name, ext = filename.rsplit('.', 1)
        ext = '.' + ext
    else:
        name = filename
        ext = ''
    
    # Remove path traversal characters
    name = name.replace('..', '').replace('/', '').replace('\\', '')
    
    # Keep only safe characters
    name = re.sub(r'[^\u4e00-\u9fff\u3400-\u4dbfa-zA-Z0-9\s\-_]', '', name)
    name = name.strip()
    
    if not name:
        name = '未命名文件'
    
    if len(name) > 200:
        name = name[:200]
    
    return name + ext

def is_path_traversal(path):
    """
    Check if path contains traversal attempts
    """
    if not path:
        return False
    
    path_lower = path.lower()
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if pattern in path_lower:
            return True
    
    # Check for encoded traversal
    decoded_path = path
    for _ in range(3):  # Try to decode multiple times
        decoded_path = decoded_path.replace('%2e', '.').replace('%2f', '/').replace('%5c', '\\')
    
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if pattern in decoded_path.lower():
            return True
    
    return False

def is_system_path(path):
    """
    Check if path points to system directory
    """
    if not path:
        return False
    
    # Normalize path
    normalized = os.path.normpath(path).replace('\\', '/')
    
    for forbidden in FORBIDDEN_DIRS:
        forbidden_norm = os.path.normpath(forbidden).replace('\\', '/')
        if normalized == forbidden_norm or normalized.startswith(forbidden_norm + '/'):
            return True
    
    return False

def is_forbidden_filename(filename):
    """
    Check if filename is forbidden
    """
    if not filename:
        return False
    
    filename_lower = filename.lower()
    for forbidden in FORBIDDEN_FILES:
        if forbidden in filename_lower or filename_lower == forbidden:
            return True
    
    return False

def validate_user_path(user_path, username):
    """
    Validate that path is within user's directory
    Returns the validated absolute path or None if invalid
    """
    if not username:
        return None
    
    # Get user's base directory
    user_base = os.path.abspath(os.path.join(app.config['UPLOAD_FOLDER'], username))
    
    # Construct full path
    if user_path:
        full_path = os.path.abspath(os.path.join(user_base, user_path))
    else:
        full_path = user_base
    
    # Check path traversal
    if is_path_traversal(user_path):
        print(f"[SECURITY] Path traversal detected: {user_path} by user {username}")
        return None
    
    # Check if trying to access system directory
    if is_system_path(full_path):
        print(f"[SECURITY] System directory access blocked: {full_path} by user {username}")
        return None
    
    # Check if path is within user's directory
    if not full_path.startswith(user_base):
        print(f"[SECURITY] User {username} tried to access outside directory: {full_path}")
        return None
    
    return full_path

def get_user_base_path(username):
    """
    Get user's base directory path
    """
    return os.path.abspath(os.path.join(app.config['UPLOAD_FOLDER'], username))

# ==================== APP CONFIGURATION ====================
app = Flask(__name__)
CORS(app)

app.config['SECRET_KEY'] = 'dvs-cloud-drive-secret-key-2025'

UPLOAD_BASE = os.path.join(os.getcwd(), 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_BASE
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024 * 100  # 100GB
app.config['DATABASE'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cloud_storage.db')

# Invitation code
INVITATION_CODE = "Test"

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Log directory
os.makedirs('log', exist_ok=True)

# ==================== DATABASE FUNCTIONS ====================
def get_db():
    """Get database connection"""
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    """Close database connection"""
    if hasattr(g, 'db'):
        g.db.close()

def init_db():
    """Initialize database"""
    with app.app_context():
        db = get_db()
        
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                is_vip INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        ''')
        
        db.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                path TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                size INTEGER,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_shared INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        db.execute('''
            CREATE TABLE IF NOT EXISTS shares (
                share_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                original_path TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                downloads INTEGER DEFAULT 0,
                is_dir INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        db.execute('''
            CREATE TABLE IF NOT EXISTS access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip TEXT,
                method TEXT,
                path TEXT,
                user_agent TEXT,
                referer TEXT,
                username TEXT
            )
        ''')
        
        db.commit()
        
        # Default admin user
        admin_password_hash = hashlib.sha256("admin123456".encode()).hexdigest()
        try:
            db.execute(
                'INSERT OR IGNORE INTO users (username, password_hash, is_vip) VALUES (?, ?, ?)',
                ('admin', admin_password_hash, 1)
            )
            db.commit()
        except:
            pass

def get_user_by_username(username):
    """Get user by username"""
    db = get_db()
    user = db.execute(
        'SELECT * FROM users WHERE username = ? COLLATE NOCASE',
        (username,)
    ).fetchone()
    return dict(user) if user else None

def add_user(username, password_hash, is_vip=False):
    """Add user"""
    db = get_db()
    try:
        db.execute(
            'INSERT INTO users (username, password_hash, is_vip) VALUES (?, ?, ?)',
            (username, password_hash, 1 if is_vip else 0)
        )
        db.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def update_user_password(username, password_hash):
    """Update user password"""
    db = get_db()
    db.execute(
        'UPDATE users SET password_hash = ? WHERE username = ? COLLATE NOCASE',
        (password_hash, username)
    )
    db.commit()

def is_vip_user(username):
    """Check if user is VIP"""
    user = get_user_by_username(username)
    return user and user['is_vip'] == 1

def sha256_hash(password):
    """Calculate SHA256 hash"""
    return hashlib.sha256(password.encode()).hexdigest()

# ==================== LOGGING FUNCTION ====================
def log_access(ip=None, username=None):
    """Log access to database"""
    try:
        if ip is None:
            if request.headers.get('X-Forwarded-For'):
                ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
            elif request.headers.get('X-Real-IP'):
                ip = request.headers.get('X-Real-IP')
            else:
                ip = request.remote_addr
        
        if username is None:
            username = session.get('username', '未登录')
        
        db = get_db()
        db.execute(
            '''INSERT INTO access_logs 
               (ip, method, path, user_agent, referer, username) 
               VALUES (?, ?, ?, ?, ?, ?)''',
            (ip, request.method, request.path, 
             request.headers.get('User-Agent', ''), 
             request.headers.get('Referer', ''), 
             username)
        )
        db.commit()
        return True
    except Exception as e:
        print(f"Log error: {e}")
        return False

# ==================== SECURITY FILTER ====================
@app.before_request
def security_filter():
    """Global security filter - executed before each request"""
    # Skip login/register pages
    if request.path in ['/login', '/register']:
        return
    
    # Check if user is logged in for protected routes
    if 'username' not in session:
        return
    
    # Check GET parameters
    for key, values in request.args.lists():
        for value in values:
            if is_path_traversal(value):
                print(f"[SECURITY] Blocked traversal in GET: {request.url}")
                abort(403, "Access denied")
    
    # Check POST parameters
    if request.method == 'POST':
        for key, values in request.form.lists():
            for value in values:
                if is_path_traversal(value):
                    print(f"[SECURITY] Blocked traversal in POST: {key}={value}")
                    abort(403, "Access denied")
                
                # Check for forbidden filenames in uploads
                if key == 'file' and is_forbidden_filename(value):
                    print(f"[SECURITY] Blocked forbidden filename: {value}")
                    abort(403, "File name not allowed")

# ==================== HELPER FUNCTIONS ====================
def format_size(bytes):
    """Format file size for display"""
    if bytes is None:
        return '0 B'
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    i = 0
    while bytes >= 1024 and i < len(units) - 1:
        bytes /= 1024
        i += 1
    return f'{bytes:.2f} {units[i]}'

def format_time(timestamp):
    """Format timestamp for display"""
    dt = datetime.fromtimestamp(timestamp)
    return dt.strftime('%Y-%m-%d %H:%M:%S')

def login_required(f):
    """Decorator to require login"""
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please login first', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# ==================== ROUTES ====================

# Main index route
@app.route('/')
@login_required
def index():
    username = session['username']
    path = request.args.get('path', '')
    
    # Validate path
    full_path = validate_user_path(path, username)
    if full_path is None:
        flash('Invalid path', 'danger')
        return redirect(url_for('index'))
    
    log_access()
    
    # Ensure user directory exists
    user_base = get_user_base_path(username)
    os.makedirs(user_base, exist_ok=True)
    
    # Get directory contents
    items = []
    if os.path.exists(full_path) and os.path.isdir(full_path):
        for item in os.listdir(full_path):
            item_path = os.path.join(full_path, item)
            item_rel_path = os.path.join(path, item) if path else item
            
            # Skip hidden files starting with .
            if item.startswith('.'):
                continue
            
            if os.path.isdir(item_path):
                items.append({
                    'name': item,
                    'path': item_rel_path,
                    'is_dir': True,
                    'size': '-',
                    'modified': format_time(os.path.getmtime(item_path))
                })
            else:
                file_ext = item.rsplit('.', 1)[1].lower() if '.' in item else ''
                items.append({
                    'name': item,
                    'path': item_rel_path,
                    'is_dir': False,
                    'size': format_size(os.path.getsize(item_path)),
                    'modified': format_time(os.path.getmtime(item_path)),
                    'ext': file_ext,
                    'previewable': file_ext in {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mp3', 'pdf', 'txt'}
                })
    
    # Sort: folders first, then by name
    items.sort(key=lambda x: (0 if x['is_dir'] else 1, x['name'].lower()))
    
    # Build breadcrumbs
    breadcrumbs = []
    parts = path.split(os.sep) if path else []
    current_path = ''
    breadcrumbs.append({'name': 'Root', 'path': ''})
    
    for part in parts:
        current_path = os.path.join(current_path, part) if current_path else part
        breadcrumbs.append({'name': part, 'path': current_path})
    
    # Calculate storage usage
    total_size = 0
    if os.path.exists(user_base):
        for dirpath, dirnames, filenames in os.walk(user_base):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                try:
                    total_size += os.path.getsize(filepath)
                except OSError:
                    continue
    
    storage_usage = {
        'used': total_size,
        'used_formatted': format_size(total_size),
        'total_formatted': 'Unlimited',
        'free_formatted': 'Unlimited'
    }
    
    vip_user = is_vip_user(username)
    
    return render_template('index.html', 
                          items=items, 
                          breadcrumbs=breadcrumbs, 
                          path=path, 
                          vip_user=vip_user,
                          storage_usage=storage_usage,
                          username=username)

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Please enter username and password', 'danger')
            return render_template('login.html')
        
        # Block system usernames
        if username in ['root', 'admin', 'administrator', 'system', 'user']:
            pass  # Allow admin login with correct password
        
        password_hash = sha256_hash(password)
        user = get_user_by_username(username)
        
        if user and user['password_hash'] == password_hash:
            session['username'] = username
            session['vip'] = bool(user['is_vip'])
            
            db = get_db()
            db.execute(
                'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE username = ? COLLATE NOCASE',
                (username,)
            )
            db.commit()
            
            log_access()
            flash('Login successful', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm-password', '')
        invitation_code = request.form.get('invitation_code', '')
        
        # Validate username
        if not username or len(username) < 3:
            flash('Username must be at least 3 characters', 'danger')
            return redirect(url_for('register'))
        
        # Block system usernames
        if username.lower() in ['root', 'admin', 'administrator', 'system', 'bin', 'daemon', 'nobody']:
            flash('Username not allowed', 'danger')
            return redirect(url_for('register'))
        
        if get_user_by_username(username):
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))
        
        if len(password) < 6:
            flash('Password must be at least 6 characters', 'danger')
            return redirect(url_for('register'))
        
        if invitation_code != INVITATION_CODE:
            flash('Invalid invitation code', 'danger')
            return redirect(url_for('register'))
        
        password_hash = sha256_hash(password)
        
        if add_user(username, password_hash, is_vip=False):
            # Create user directory
            user_base = get_user_base_path(username)
            os.makedirs(user_base, exist_ok=True)
            
            log_access()
            flash('Registration successful, please login', 'success')
            return redirect(url_for('login'))
        else:
            flash('Registration failed', 'danger')
    
    return render_template('register.html')

# Change password route
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    username = session['username']
    log_access()
    
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        user = get_user_by_username(username)
        if not user or user['password_hash'] != sha256_hash(current_password):
            flash('Current password is incorrect', 'danger')
            return redirect(url_for('change_password'))
        
        if len(new_password) < 6:
            flash('New password must be at least 6 characters', 'danger')
            return redirect(url_for('change_password'))
        
        if new_password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('change_password'))
        
        update_user_password(username, sha256_hash(new_password))
        flash('Password changed successfully', 'success')
        return redirect(url_for('index'))
    
    return render_template('change_password.html')

# Logout route
@app.route('/logout')
def logout():
    log_access()
    session.pop('username', None)
    session.pop('vip', None)
    flash('Logged out', 'info')
    return redirect(url_for('login'))

# File upload route
@app.route('/upload', methods=['POST'])
@login_required
def upload():
    username = session['username']
    path = request.form.get('path', '')
    
    # Validate path
    full_path = validate_user_path(path, username)
    if full_path is None:
        flash('Invalid path', 'danger')
        return redirect(url_for('index'))
    
    log_access()
    
    if 'file' not in request.files:
        flash('No file uploaded', 'danger')
        return redirect(url_for('index', path=path))
    
    files = request.files.getlist('file')
    
    if not files or files[0].filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('index', path=path))
    
    success_count = 0
    error_count = 0
    
    for file in files:
        if file:
            # Check forbidden filename
            if is_forbidden_filename(file.filename):
                error_count += 1
                continue
            
            filename = safe_filename(file.filename)
            
            # Validate filename doesn't contain path traversal
            if is_path_traversal(filename):
                error_count += 1
                continue
            
            file_path = os.path.join(full_path, filename)
            
            # Handle duplicate files
            if os.path.exists(file_path):
                name_without_ext, ext = os.path.splitext(filename)
                i = 1
                while os.path.exists(os.path.join(full_path, f"{name_without_ext}({i}){ext}")):
                    i += 1
                filename = f"{name_without_ext}({i}){ext}"
                file_path = os.path.join(full_path, filename)
            
            try:
                file.save(file_path)
                
                user = get_user_by_username(username)
                user_id = user['id'] if user else None
                
                if user_id:
                    file_id = str(uuid.uuid4())
                    db = get_db()
                    db.execute(
                        'INSERT INTO files (id, name, path, user_id, size) VALUES (?, ?, ?, ?, ?)',
                        (file_id, filename, os.path.join(path, filename), user_id, os.path.getsize(file_path))
                    )
                    db.commit()
                
                success_count += 1
            except Exception as e:
                error_count += 1
                print(f"Upload failed: {str(e)}")
    
    if success_count > 0:
        flash(f'Successfully uploaded {success_count} file(s)', 'success')
    if error_count > 0:
        flash(f'Failed to upload {error_count} file(s)', 'danger')
    
    return redirect(url_for('index', path=path))

# Create folder route
@app.route('/create_folder', methods=['POST'])
@login_required
def create_folder():
    username = session['username']
    path = request.form.get('path', '')
    folder_name = request.form.get('folder_name', '').strip()
    
    # Validate path
    full_path = validate_user_path(path, username)
    if full_path is None:
        flash('Invalid path', 'danger')
        return redirect(url_for('index'))
    
    log_access()
    
    if not folder_name:
        flash('Folder name cannot be empty', 'danger')
        return redirect(url_for('index', path=path))
    
    # Check forbidden folder name
    if is_forbidden_filename(folder_name) or is_path_traversal(folder_name):
        flash('Invalid folder name', 'danger')
        return redirect(url_for('index', path=path))
    
    folder_path = os.path.join(full_path, folder_name)
    
    if os.path.exists(folder_path):
        flash('Folder already exists', 'danger')
        return redirect(url_for('index', path=path))
    
    try:
        os.makedirs(folder_path)
        flash(f'Folder "{folder_name}" created successfully', 'success')
    except Exception as e:
        flash(f'Failed to create folder: {str(e)}', 'danger')
    
    return redirect(url_for('index', path=path))

# Rename route
@app.route('/rename', methods=['POST'])
@login_required
def rename():
    username = session['username']
    path = request.form.get('path', '')
    item_path = request.form.get('item_path', '')
    new_name = request.form.get('new_name', '').strip()
    
    # Validate paths
    full_parent_path = validate_user_path(path, username)
    if full_parent_path is None:
        flash('Invalid path', 'danger')
        return redirect(url_for('index'))
    
    full_item_path = validate_user_path(item_path, username)
    if full_item_path is None:
        flash('Invalid item path', 'danger')
        return redirect(url_for('index', path=path))
    
    log_access()
    
    if not item_path or not new_name:
        flash('Invalid request', 'danger')
        return redirect(url_for('index', path=path))
    
    if is_forbidden_filename(new_name) or is_path_traversal(new_name):
        flash('Invalid name', 'danger')
        return redirect(url_for('index', path=path))
    
    old_full_path = full_item_path
    new_full_path = os.path.join(os.path.dirname(old_full_path), new_name)
    
    if not os.path.exists(old_full_path):
        flash('File or folder does not exist', 'danger')
        return redirect(url_for('index', path=path))
    
    if os.path.exists(new_full_path):
        flash('Target name already exists', 'danger')
        return redirect(url_for('index', path=path))
    
    # Verify new path is still within user directory
    new_validated = validate_user_path(os.path.join(path, new_name), username)
    if new_validated is None:
        flash('Invalid target path', 'danger')
        return redirect(url_for('index', path=path))
    
    try:
        os.rename(old_full_path, new_full_path)
        
        user = get_user_by_username(username)
        user_id = user['id'] if user else None
        
        if user_id and os.path.isfile(new_full_path):
            db = get_db()
            new_db_path = os.path.join(os.path.dirname(item_path), new_name)
            db.execute(
                'UPDATE files SET name = ?, path = ? WHERE user_id = ? AND path = ?',
                (new_name, new_db_path, user_id, item_path)
            )
            db.commit()
        
        flash('Renamed successfully', 'success')
    except Exception as e:
        flash(f'Rename failed: {str(e)}', 'danger')
    
    return redirect(url_for('index', path=path))

# Delete route
@app.route('/delete', methods=['POST'])
@login_required
def delete():
    username = session['username']
    path = request.form.get('path', '')
    item_path = request.form.get('item_path', '')
    
    # Validate paths
    full_item_path = validate_user_path(item_path, username)
    if full_item_path is None:
        flash('Invalid item path', 'danger')
        return redirect(url_for('index', path=path))
    
    log_access()
    
    if not item_path:
        flash('Invalid path', 'danger')
        return redirect(url_for('index', path=path))
    
    try:
        if os.path.isdir(full_item_path):
            # Delete folder and its contents
            for root, dirs, files in os.walk(full_item_path, topdown=False):
                for name in files:
                    os.remove(os.path.join(root, name))
                for name in dirs:
                    os.rmdir(os.path.join(root, name))
            os.rmdir(full_item_path)
            flash(f'Folder "{os.path.basename(item_path)}" deleted', 'success')
        else:
            os.remove(full_item_path)
            
            user = get_user_by_username(username)
            user_id = user['id'] if user else None
            
            if user_id:
                db = get_db()
                db.execute(
                    'DELETE FROM files WHERE user_id = ? AND path = ?',
                    (user_id, item_path)
                )
                db.commit()
            
            flash(f'File "{os.path.basename(item_path)}" deleted', 'success')
    except Exception as e:
        flash(f'Delete failed: {str(e)}', 'danger')
    
    return redirect(url_for('index', path=path))

# Download route
@app.route('/download/<path:file_path>')
@login_required
def download(file_path):
    username = session['username']
    
    # Validate path
    full_path = validate_user_path(file_path, username)
    if full_path is None:
        flash('Invalid file path', 'danger')
        return redirect(url_for('index'))
    
    log_access()
    
    if not os.path.exists(full_path) or os.path.isdir(full_path):
        flash('File not found', 'danger')
        return redirect(url_for('index', path=os.path.dirname(file_path)))
    
    try:
        return send_from_directory(
            os.path.dirname(full_path),
            os.path.basename(full_path),
            as_attachment=True
        )
    except Exception as e:
        flash(f'Download failed: {str(e)}', 'danger')
        return redirect(url_for('index', path=os.path.dirname(file_path)))

# Preview route
@app.route('/preview/<path:file_path>')
@login_required
def preview(file_path):
    username = session['username']
    
    # Validate path
    full_path = validate_user_path(file_path, username)
    if full_path is None:
        flash('Invalid file path', 'danger')
        return redirect(url_for('index'))
    
    log_access()
    
    if not os.path.exists(full_path) or os.path.isdir(full_path):
        flash('File not found', 'danger')
        return redirect(url_for('index', path=os.path.dirname(file_path)))
    
    file_ext = os.path.splitext(file_path)[1].lower()
    
    if file_ext in {'.png', '.jpg', '.jpeg', '.gif', '.txt'}:
        return send_from_directory(os.path.dirname(full_path), os.path.basename(full_path))
    elif file_ext == '.pdf':
        return render_template('preview_pdf.html', file_path=url_for('download', file_path=file_path))
    elif file_ext == '.mp4':
        return render_template('preview_video.html', file_path=url_for('download', file_path=file_path))
    elif file_ext == '.mp3':
        return render_template('preview_audio.html', file_path=url_for('download', file_path=file_path))
    
    flash('Preview not supported', 'warning')
    return redirect(url_for('index', path=os.path.dirname(file_path)))

# Search route
@app.route('/search')
@login_required
def search():
    username = session['username']
    query = request.args.get('query', '').lower()
    path = request.args.get('path', '')
    
    # Validate path
    full_path = validate_user_path(path, username)
    if full_path is None:
        flash('Invalid path', 'danger')
        return redirect(url_for('index'))
    
    log_access()
    
    results = []
    
    if os.path.exists(full_path) and os.path.isdir(full_path):
        for root, dirs, files in os.walk(full_path):
            for dir_name in dirs:
                if query in dir_name.lower():
                    rel_dir = os.path.relpath(os.path.join(root, dir_name), full_path)
                    results.append({
                        'name': dir_name,
                        'path': os.path.join(path, rel_dir),
                        'is_dir': True,
                        'size': '-',
                        'modified': format_time(os.path.getmtime(os.path.join(root, dir_name)))
                    })
            
            for file_name in files:
                if query in file_name.lower():
                    rel_file = os.path.relpath(os.path.join(root, file_name), full_path)
                    file_path = os.path.join(path, rel_file)
                    file_ext = file_name.rsplit('.', 1)[1].lower() if '.' in file_name else ''
                    results.append({
                        'name': file_name,
                        'path': file_path,
                        'is_dir': False,
                        'size': format_size(os.path.getsize(os.path.join(root, file_name))),
                        'modified': format_time(os.path.getmtime(os.path.join(root, file_name))),
                        'ext': file_ext,
                        'previewable': file_ext in {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mp3', 'pdf', 'txt'}
                    })
    
    results.sort(key=lambda x: (0 if x['is_dir'] else 1, x['name'].lower()))
    
    breadcrumbs = []
    parts = path.split(os.sep) if path else []
    current_path = ''
    breadcrumbs.append({'name': 'Root', 'path': ''})
    
    for part in parts:
        current_path = os.path.join(current_path, part) if current_path else part
        breadcrumbs.append({'name': part, 'path': current_path})
    
    breadcrumbs.append({'name': f'Search: {query}', 'path': ''})
    
    vip_user = is_vip_user(username)
    
    return render_template('search_results.html', results=results, breadcrumbs=breadcrumbs, path=path, query=query, vip_user=vip_user)

# Batch download route
@app.route('/batch_download', methods=['POST'])
@login_required
def batch_download():
    username = session['username']
    selected_items = request.form.getlist('selected_items')
    path = request.form.get('path', '')
    
    log_access()
    
    if not selected_items:
        flash('Please select files to download', 'warning')
        return redirect(url_for('index', path=path))
    
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for item_path in selected_items:
            # Validate each item
            full_path = validate_user_path(item_path, username)
            if full_path is None:
                continue
            
            if os.path.isdir(full_path):
                for root, dirs, files in os.walk(full_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, get_user_base_path(username))
                        zipf.write(file_path, arcname)
            else:
                arcname = os.path.relpath(full_path, get_user_base_path(username))
                zipf.write(full_path, arcname)
    
    buffer.seek(0)
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f'dvs_download_{datetime.now().strftime("%Y%m%d_%H%M%S")}.zip',
        mimetype='application/zip'
    )

# Batch delete route
@app.route('/batch_delete', methods=['POST'])
@login_required
def batch_delete():
    username = session['username']
    selected_items = request.form.getlist('selected_items')
    path = request.form.get('path', '')
    
    log_access()
    
    if not selected_items:
        flash('Please select items to delete', 'warning')
        return redirect(url_for('index', path=path))
    
    success_count = 0
    error_count = 0
    
    for item_path in selected_items:
        full_path = validate_user_path(item_path, username)
        if full_path is None:
            error_count += 1
            continue
        
        try:
            if os.path.isdir(full_path):
                for root, dirs, files in os.walk(full_path, topdown=False):
                    for name in files:
                        os.remove(os.path.join(root, name))
                    for name in dirs:
                        os.rmdir(os.path.join(root, name))
                os.rmdir(full_path)
            else:
                os.remove(full_path)
                
                user = get_user_by_username(username)
                user_id = user['id'] if user else None
                
                if user_id:
                    db = get_db()
                    db.execute(
                        'DELETE FROM files WHERE user_id = ? AND path = ?',
                        (user_id, item_path)
                    )
                    db.commit()
            
            success_count += 1
        except Exception as e:
            error_count += 1
            print(f"Delete failed: {str(e)}")
    
    if success_count > 0:
        flash(f'Successfully deleted {success_count} item(s)', 'success')
    if error_count > 0:
        flash(f'Failed to delete {error_count} item(s)', 'danger')
    
    return redirect(url_for('index', path=path))

# Share route
@app.route('/share', methods=['POST'])
@login_required
def share():
    username = session['username']
    item_path = request.form.get('item_path', '')
    
    # Validate path
    full_path = validate_user_path(item_path, username)
    if full_path is None:
        flash('Invalid item path', 'danger')
        return redirect(url_for('index'))
    
    log_access()
    
    if not item_path or not os.path.exists(full_path):
        flash('Invalid file/folder', 'danger')
        return redirect(url_for('index', path=os.path.dirname(item_path)))
    
    user = get_user_by_username(username)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('index', path=os.path.dirname(item_path)))
    
    share_id = hashlib.sha256(f"{username}{item_path}{time.time()}".encode()).hexdigest()[:10]
    
    db = get_db()
    db.execute(
        'INSERT INTO shares (share_id, user_id, original_path, is_dir) VALUES (?, ?, ?, ?)',
        (share_id, user['id'], item_path, 1 if os.path.isdir(full_path) else 0)
    )
    db.commit()
    
    share_url = url_for('download_shared', share_id=share_id, _external=True)
    flash(f'Share link created: <a href="{share_url}" target="_blank">{share_url}</a>', 'success')
    
    return redirect(url_for('index', path=os.path.dirname(item_path)))

# Unshare route
@app.route('/unshare', methods=['POST'])
@login_required
def unshare():
    username = session['username']
    share_id = request.form.get('share_id', '')
    
    log_access()
    
    user = get_user_by_username(username)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('shared_files'))
    
    db = get_db()
    share = db.execute(
        'SELECT * FROM shares WHERE share_id = ? AND user_id = ?',
        (share_id, user['id'])
    ).fetchone()
    
    if share:
        db.execute('DELETE FROM shares WHERE share_id = ?', (share_id,))
        db.commit()
        flash('Share cancelled', 'success')
    else:
        flash('Invalid share ID or no permission', 'danger')
    
    return redirect(url_for('shared_files'))

# Shared files list route
@app.route('/shared_files')
@login_required
def shared_files():
    username = session['username']
    log_access()
    
    user = get_user_by_username(username)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('index'))
    
    db = get_db()
    user_shares = db.execute(
        'SELECT * FROM shares WHERE user_id = ? ORDER BY created_at DESC',
        (user['id'],)
    ).fetchall()
    
    shares_list = []
    for share in user_shares:
        name = os.path.basename(share['original_path'])
        ext = name.rsplit('.', 1)[1].lower() if not share['is_dir'] and '.' in name else ''
        shares_list.append({
            'share_id': share['share_id'],
            'name': name,
            'path': share['original_path'],
            'ext': ext,
            'created_at': share['created_at'],
            'downloads': share['downloads'],
            'is_dir': bool(share['is_dir'])
        })
    
    return render_template('shared_files.html', shared_items=shares_list, vip_user=is_vip_user(username))

# Download shared file route (public, no login required)
@app.route('/s/<share_id>')
def download_shared(share_id):
    log_access()
    
    db = get_db()
    share_info = db.execute(
        'SELECT s.*, u.username FROM shares s JOIN users u ON s.user_id = u.id WHERE s.share_id = ?',
        (share_id,)
    ).fetchone()
    
    if not share_info:
        flash('Invalid share link', 'danger')
        return redirect(url_for('index'))
    
    # Validate path for the original user
    username = share_info['username']
    original_path = share_info['original_path']
    full_path = validate_user_path(original_path, username)
    
    if full_path is None or not os.path.exists(full_path):
        flash('File has been deleted', 'danger')
        return redirect(url_for('index'))
    
    # Update download count
    db.execute(
        'UPDATE shares SET downloads = downloads + 1 WHERE share_id = ?',
        (share_id,)
    )
    db.commit()
    
    if os.path.isdir(full_path):
        # If folder, create ZIP
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(full_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, os.path.dirname(full_path))
                    zipf.write(file_path, arcname)
        
        buffer.seek(0)
        folder_name = os.path.basename(full_path)
        return send_file(
            buffer,
            as_attachment=True,
            download_name=f'{folder_name}.zip',
            mimetype='application/zip'
        )
    
    # If file, direct download
    return send_from_directory(
        os.path.dirname(full_path),
        os.path.basename(full_path),
        as_attachment=True
    )

# API: Storage usage
@app.route('/api/storage_usage')
@login_required
def get_storage_usage():
    username = session['username']
    user_base = get_user_base_path(username)
    
    total_size = 0
    if os.path.exists(user_base):
        for dirpath, dirnames, filenames in os.walk(user_base):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                try:
                    total_size += os.path.getsize(filepath)
                except OSError:
                    continue
    
    return jsonify({
        'used': total_size,
        'used_formatted': format_size(total_size),
        'free': '∞',
        'free_formatted': '∞',
        'total': '∞',
        'total_formatted': '∞'
    })

# ==================== MAIN ====================
if __name__ == '__main__':
    init_db()
    
    # Ensure all user directories exist
    with app.app_context():
        db = get_db()
        users = db.execute('SELECT username FROM users').fetchall()
        for user in users:
            user_base = get_user_base_path(user['username'])
            os.makedirs(user_base, exist_ok=True)
    
    app.run(debug=True, host='0.0.0.0', port=8080)
