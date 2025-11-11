from flask import Flask, render_template, request, session, redirect, url_for, flash, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from pymongo import MongoClient
from datetime import datetime, timezone, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
import logging
import os
import secrets
from os.path import exists
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import mimetypes
from PIL import Image
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
import tempfile

# Load environment variables
load_dotenv()

# Configure logging
log_level = logging.DEBUG if os.getenv('DEBUG', 'False').lower() == 'true' else logging.INFO
logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Security: Use environment variable or generate strong secret key
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# Security headers
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# CORS configuration for production
ALLOWED_ORIGINS = os.getenv('ALLOWED_ORIGINS', '*')
if ALLOWED_ORIGINS != '*':
    ALLOWED_ORIGINS = ALLOWED_ORIGINS.split(',')

# Initialize SocketIO with production settings
socketio = SocketIO(
    app,
    cors_allowed_origins=ALLOWED_ORIGINS,
    async_mode='eventlet',  # Better for production
    logger=log_level == logging.DEBUG,
    engineio_logger=log_level == logging.DEBUG,
    ping_timeout=60,
    ping_interval=25,
    max_http_buffer_size=16 * 1024 * 1024
)

# Configure upload folders
UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', 'static/uploads')
ATTACHMENTS_FOLDER = os.getenv('ATTACHMENTS_FOLDER', 'static/attachments')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'pdf', 'doc', 'docx', 'txt', 'zip', 'mp3', 'mp4', 'webm', 'ogg'}

# Create folders if they don't exist
for folder in [UPLOAD_FOLDER, ATTACHMENTS_FOLDER]:
    if not exists(folder):
        os.makedirs(folder)
        logger.info(f"✅ Created folder: {folder}")

# Initialize MongoDB client with retry logic
MAX_RETRIES = 3
for attempt in range(MAX_RETRIES):
    try:
        mongo_uri = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
        client = MongoClient(
            mongo_uri,
            serverSelectionTimeoutMS=5000,
            connectTimeoutMS=10000,
            socketTimeoutMS=10000
        )
        client.server_info()  # Force connection test
        
        db_name = os.getenv('DB_NAME', 'chatapp')
        db = client[db_name]
        users_collection = db['users']
        messages_collection = db['messages']
        reactions_collection = db['reactions']
        
        # Create indexes for better performance
        users_collection.create_index('username', unique=True)
        messages_collection.create_index([('room', 1), ('timestamp', -1)])
        
        logger.info(f"✅ MongoDB connected successfully to database: {db_name}")
        break
    except Exception as e:
        logger.error(f"❌ MongoDB connection attempt {attempt + 1} failed: {e}")
        if attempt == MAX_RETRIES - 1:
            logger.critical("❌ Could not connect to MongoDB after multiple attempts")
            raise

# Store active users, typing status, and unread counts
active_users = {}
typing_users = {}
unread_counts = {}

# IST timezone (UTC+5:30)
IST = timezone(timedelta(hours=5, minutes=30))

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_current_time():
    """Get current time in IST"""
    return datetime.now(IST).isoformat()

@app.route('/')
def index():
    """Redirect to login page"""
    if 'username' in session:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Username and password are required!', 'error')
            return render_template('login.html')
        
        try:
            user = users_collection.find_one({'username': username})
            if user and check_password_hash(user['password'], password):
                session.permanent = True
                session['username'] = username
                session['user_id'] = str(user['_id'])
                
                users_collection.update_one(
                    {'username': username},
                    {'$set': {'last_seen': get_current_time(), 'online': True}}
                )
                logger.info(f"✅ User logged in: {username}")
                return redirect(url_for('chat'))
            else:
                flash('Invalid username or password!', 'error')
                logger.warning(f"⚠️ Failed login attempt: {username}")
        except Exception as e:
            logger.error(f"❌ Login error: {e}")
            flash('An error occurred. Please try again.', 'error')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Handle user registration"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        email = request.form.get('email', '').strip()
        
        if not username or not password:
            flash('Username and password are required!', 'error')
            return render_template('signup.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters!', 'error')
            return render_template('signup.html')
        
        try:
            existing_user = users_collection.find_one({'username': username})
            if existing_user:
                flash('Username already exists!', 'error')
                return render_template('signup.html')
            
            user_id = users_collection.insert_one({
                'username': username,
                'password': generate_password_hash(password),
                'email': email,
                'bio': '',
                'profile_picture': '',
                'created_at': get_current_time(),
                'last_seen': get_current_time(),
                'online': False,
                'theme': 'light'
            }).inserted_id
            
            logger.info(f"✅ New user registered: {username}")
            flash('Signup successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            logger.error(f"❌ Signup error: {e}")
            flash('An error occurred. Please try again.', 'error')
    
    return render_template('signup.html')

@app.route('/logout')
def logout():
    """Handle user logout"""
    username = session.pop('username', None)
    session.pop('user_id', None)
    
    if username:
        try:
            users_collection.update_one(
                {'username': username},
                {'$set': {'online': False, 'last_seen': get_current_time()}}
            )
            if username in active_users:
                del active_users[username]
            if username in unread_counts:
                del unread_counts[username]
            logger.info(f"✅ User logged out: {username}")
        except Exception as e:
            logger.error(f"❌ Logout error: {e}")
    
    return redirect(url_for('login'))

@app.route('/chat')
def chat():
    """Main chat page"""
    if 'username' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('login'))
    
    try:
        user = users_collection.find_one({'username': session['username']})
        all_users = list(users_collection.find({}, {'password': 0}))
        return render_template('chat.html', username=session['username'], user=user, all_users=all_users)
    except Exception as e:
        logger.error(f"❌ Chat page error: {e}")
        flash('An error occurred. Please try again.', 'error')
        return redirect(url_for('login'))

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    """Handle profile editing"""
    if 'username' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('login'))
    
    user = users_collection.find_one({'username': session['username']})
    
    if request.method == 'POST':
        bio = request.form.get('bio', '').strip()
        theme = request.form.get('theme', 'light')
        profile_picture = request.files.get('profile_picture')
        
        update_data = {'bio': bio, 'theme': theme}
        
        if profile_picture and profile_picture.filename:
            if allowed_file(profile_picture.filename):
                try:
                    filename = secure_filename(f"{session['username']}_{profile_picture.filename}")
                    filepath = os.path.join(UPLOAD_FOLDER, filename)
                    profile_picture.save(filepath)
                    relative_path = os.path.join('uploads', filename).replace('\\', '/')
                    update_data['profile_picture'] = relative_path
                    logger.info(f"✅ Profile picture saved: {relative_path}")
                except Exception as e:
                    logger.error(f"❌ Profile picture save error: {e}")
                    flash('Failed to upload profile picture!', 'error')
                    return redirect(url_for('edit_profile'))
            else:
                flash('Invalid file type!', 'error')
                return redirect(url_for('edit_profile'))
        
        try:
            users_collection.update_one(
                {'username': session['username']},
                {'$set': update_data}
            )
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('chat'))
        except Exception as e:
            logger.error(f"❌ Profile update error: {e}")
            flash('Failed to update profile!', 'error')
    
    return render_template('edit_profile.html', user=user)

@app.route('/change_password', methods=['POST'])
def change_password():
    """Handle password change"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    
    if not current_password or not new_password:
        return jsonify({'success': False, 'error': 'All fields are required'}), 400
    
    if len(new_password) < 6:
        return jsonify({'success': False, 'error': 'Password must be at least 6 characters'}), 400
    
    try:
        user = users_collection.find_one({'username': session['username']})
        
        if not check_password_hash(user['password'], current_password):
            return jsonify({'success': False, 'error': 'Current password is incorrect'}), 400
        
        users_collection.update_one(
            {'username': session['username']},
            {'$set': {'password': generate_password_hash(new_password)}}
        )
        
        logger.info(f"✅ Password changed: {session['username']}")
        return jsonify({'success': True, 'message': 'Password changed successfully'})
    except Exception as e:
        logger.error(f"❌ Password change error: {e}")
        return jsonify({'success': False, 'error': 'An error occurred'}), 500

@app.route('/upload_attachment', methods=['POST'])
def upload_attachment():
    """Handle single file upload"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400
    
    if file and allowed_file(file.filename):
        try:
            timestamp = datetime.now().timestamp()
            original_name = secure_filename(file.filename)
            filename = f"{session['username']}_{int(timestamp)}_{original_name}"
            filepath = os.path.join(ATTACHMENTS_FOLDER, filename)
            
            file.save(filepath)
            
            file_size = os.path.getsize(filepath)
            file_type = mimetypes.guess_type(filepath)[0] or 'application/octet-stream'
            
            logger.info(f"✅ File uploaded: {filename} ({file_size} bytes)")
            
            return jsonify({
                'success': True,
                'file_url': url_for('static', filename=f'attachments/{filename}'),
                'file_name': file.filename,
                'file_size': file_size,
                'file_type': file_type
            })
        except Exception as e:
            logger.error(f"❌ File upload error: {e}")
            return jsonify({'success': False, 'error': 'Upload failed'}), 500
    
    return jsonify({'success': False, 'error': 'Invalid file type'}), 400

@app.route('/upload_multiple_attachments', methods=['POST'])
def upload_multiple_attachments():
    """Handle multiple file uploads"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    if 'files[]' not in request.files:
        return jsonify({'success': False, 'error': 'No files provided'}), 400
    
    files = request.files.getlist('files[]')
    
    if not files or len(files) == 0:
        return jsonify({'success': False, 'error': 'No files selected'}), 400
    
    if len(files) > 10:
        return jsonify({'success': False, 'error': 'Maximum 10 files allowed'}), 400
    
    uploaded_files = []
    
    for file in files:
        if file.filename == '':
            continue
        
        if file and allowed_file(file.filename):
            try:
                timestamp = datetime.now().timestamp()
                original_name = secure_filename(file.filename)
                filename = f"{session['username']}_{int(timestamp)}_{original_name}"
                filepath = os.path.join(ATTACHMENTS_FOLDER, filename)
                
                file.save(filepath)
                
                file_size = os.path.getsize(filepath)
                file_type = mimetypes.guess_type(filepath)[0] or 'application/octet-stream'
                
                uploaded_files.append({
                    'file_url': url_for('static', filename=f'attachments/{filename}'),
                    'file_name': file.filename,
                    'file_size': file_size,
                    'file_type': file_type
                })
                
                logger.info(f"✅ File uploaded: {filename}")
            except Exception as e:
                logger.error(f"❌ File upload error: {e}")
                continue
    
    if uploaded_files:
        return jsonify({
            'success': True,
            'files': uploaded_files,
            'count': len(uploaded_files)
        })
    
    return jsonify({'success': False, 'error': 'Failed to upload files'}), 500

@app.route('/convert_images_to_pdf', methods=['POST'])
def convert_images_to_pdf():
    """Convert multiple images to PDF"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    if 'images[]' not in request.files:
        return jsonify({'success': False, 'error': 'No images provided'}), 400
    
    images = request.files.getlist('images[]')
    
    if not images or len(images) == 0:
        return jsonify({'success': False, 'error': 'No images selected'}), 400
    
    if len(images) > 20:
        return jsonify({'success': False, 'error': 'Maximum 20 images allowed'}), 400
    
    try:
        timestamp = datetime.now().timestamp()
        pdf_filename = f"{session['username']}_images_{int(timestamp)}.pdf"
        pdf_path = os.path.join(ATTACHMENTS_FOLDER, pdf_filename)
        
        c = canvas.Canvas(pdf_path, pagesize=A4)
        page_width, page_height = A4
        
        for img_file in images:
            if img_file.filename == '':
                continue
            
            temp_img_path = os.path.join(tempfile.gettempdir(), secure_filename(img_file.filename))
            img_file.save(temp_img_path)
            
            try:
                img = Image.open(temp_img_path)
                
                # Convert to RGB
                if img.mode in ('RGBA', 'LA', 'P'):
                    background = Image.new('RGB', img.size, (255, 255, 255))
                    if img.mode == 'P':
                        img = img.convert('RGBA')
                    if img.mode in ('RGBA', 'LA'):
                        background.paste(img, mask=img.split()[-1])
                    else:
                        background.paste(img)
                    img = background
                elif img.mode != 'RGB':
                    img = img.convert('RGB')
                
                # Calculate scaling
                img_width, img_height = img.size
                aspect = img_height / float(img_width)
                
                margin = 50
                available_width = page_width - (2 * margin)
                available_height = page_height - (2 * margin)
                
                if available_width / available_height > img_width / img_height:
                    new_height = available_height
                    new_width = new_height / aspect
                else:
                    new_width = available_width
                    new_height = new_width * aspect
                
                x_offset = (page_width - new_width) / 2
                y_offset = (page_height - new_height) / 2
                
                temp_rgb_path = temp_img_path + '_rgb.jpg'
                img.save(temp_rgb_path, 'JPEG', quality=95)
                
                c.drawImage(temp_rgb_path, x_offset, y_offset, width=new_width, height=new_height)
                c.showPage()
                
                # Cleanup
                if os.path.exists(temp_img_path):
                    os.remove(temp_img_path)
                if os.path.exists(temp_rgb_path):
                    os.remove(temp_rgb_path)
            except Exception as e:
                logger.error(f"❌ Image processing error: {e}")
                if os.path.exists(temp_img_path):
                    os.remove(temp_img_path)
                continue
        
        c.save()
        file_size = os.path.getsize(pdf_path)
        
        logger.info(f"✅ PDF created: {pdf_filename}")
        
        return jsonify({
            'success': True,
            'file_url': url_for('static', filename=f'attachments/{pdf_filename}'),
            'file_name': pdf_filename,
            'file_size': file_size,
            'file_type': 'application/pdf'
        })
    except Exception as e:
        logger.error(f"❌ PDF conversion error: {e}")
        return jsonify({'success': False, 'error': 'Conversion failed'}), 500

# Socket Events
@socketio.on('connect')
def on_connect():
    """Handle client connection"""
    username = session.get('username')
    logger.info(f"🔌 Socket connected: {username or 'Anonymous'}")
    
    if username:
        join_room(username)
        active_users[username] = {
            'room': 'general',
            'online': True,
            'last_seen': get_current_time()
        }
        
        try:
            users_collection.update_one(
                {'username': username},
                {'$set': {'online': True}}
            )
            
            user_list = []
            for u in active_users.keys():
                user_data = users_collection.find_one({'username': u})
                if user_data:
                    user_list.append({
                        'username': u,
                        'online': active_users[u]['online'],
                        'profile_picture': user_data.get('profile_picture', ''),
                        'last_seen': user_data.get('last_seen', '')
                    })
            
            socketio.emit('update_users', {'users': user_list})
        except Exception as e:
            logger.error(f"❌ Connect handler error: {e}")

@socketio.on('join')
def on_join(data):
    """Handle room join"""
    username = session.get('username')
    if not username:
        emit('error', {'msg': 'Not authenticated'})
        return
    
    room = data['room']
    join_room(room)
    join_room(username)
    
    active_users[username] = {
        'room': room,
        'online': True,
        'last_seen': get_current_time()
    }
    
    if username not in unread_counts:
        unread_counts[username] = {}
    
    logger.info(f"✅ {username} joined room: {room}")
    
    try:
        # Update user list
        user_list = []
        for u in active_users.keys():
            user_data = users_collection.find_one({'username': u})
            if user_data:
                user_list.append({
                    'username': u,
                    'online': active_users[u]['online'],
                    'profile_picture': user_data.get('profile_picture', ''),
                    'last_seen': user_data.get('last_seen', '')
                })
        
        socketio.emit('update_users', {'users': user_list})
        
        # Load chat history
        history = list(messages_collection.find({'room': room}).sort('timestamp', 1).limit(100))
        history_with_data = []
        for msg in history:
            history_with_data.append({
                'username': msg['username'],
                'message': msg.get('message', ''),
                'timestamp': msg['timestamp'],
                'room': msg['room'],
                '_id': str(msg['_id']),
                'attachment': msg.get('attachment'),
                'attachments': msg.get('attachments'),
                'reply_to': msg.get('reply_to'),
                'read_by': msg.get('read_by', [])
            })
        
        emit('load_history', {'messages': history_with_data})
        emit('status', {'msg': f'{username} has joined the chat.'}, to=room)
        
        # Mark messages as read
        messages_collection.update_many(
            {'room': room, 'username': {'$ne': username}},
            {'$addToSet': {'read_by': username}}
        )
        
        if room in unread_counts.get(username, {}):
            del unread_counts[username][room]
        emit('update_badge', {'count': 0}, to=username)
    except Exception as e:
        logger.error(f"❌ Join handler error: {e}")

@socketio.on('start_private_chat')
def start_private_chat(data):
    """Handle private chat initialization"""
    username = session.get('username')
    if not username:
        emit('error', {'msg': 'Not authenticated'})
        return
    
    target_user = data['target_user']
    room = ':'.join(sorted([username, target_user]))
    join_room(room)
    join_room(username)
    active_users[username]['room'] = room
    
    logger.info(f"✅ Private chat: {username} <-> {target_user}")
    
    try:
        history = list(messages_collection.find({'room': room}).sort('timestamp', 1).limit(100))
        history_with_data = []
        for msg in history:
            history_with_data.append({
                'username': msg['username'],
                'message': msg.get('message', ''),
                'timestamp': msg['timestamp'],
                'room': msg['room'],
                '_id': str(msg['_id']),
                'attachment': msg.get('attachment'),
                'attachments': msg.get('attachments'),
                'reply_to': msg.get('reply_to'),
                'read_by': msg.get('read_by', [])
            })
        
        target_user_data = users_collection.find_one({'username': target_user})
        emit('load_history', {
            'messages': history_with_data,
            'target_user_profile_picture': target_user_data.get('profile_picture', '') if target_user_data else ''
        })
        emit('status', {'msg': f'Private chat with {target_user} started.'}, to=room)
    except Exception as e:
        logger.error(f"❌ Private chat error: {e}")

@socketio.on('typing_start')
def handle_typing_start(data):
    """Handle typing start event"""
    username = session.get('username')
    if not username:
        return
    
    room = data['room']
    
    if room not in typing_users:
        typing_users[room] = set()
    typing_users[room].add(username)
    
    logger.debug(f"⌨️ {username} typing in {room}")
    socketio.emit('user_typing', {'username': username, 'room': room, 'typing': True}, to=room)

@socketio.on('typing_stop')
def handle_typing_stop(data):
    """Handle typing stop event"""
    username = session.get('username')
    if not username:
        return
    
    room = data['room']
    
    if room in typing_users and username in typing_users[room]:
        typing_users[room].discard(username)
    
    logger.debug(f"⌨️ {username} stopped typing")
    socketio.emit('user_typing', {'username': username, 'room': room, 'typing': False}, to=room)

@socketio.on('message')
def handle_message(data):
    """Handle incoming message"""
    username = session.get('username')
    if not username:
        emit('error', {'msg': 'Not authenticated'})
        return
    
    room = data['room']
    message_text = data.get('message', '')
    current_time = get_current_time()
    
    message = {
        'username': username,
        'message': message_text,
        'timestamp': current_time,
        'room': room,
        'read_by': [username]
    }
    
    if 'attachments' in data and data['attachments']:
        message['attachments'] = data['attachments']
    elif 'attachment' in data:
        message['attachment'] = data['attachment']
    
    try:
        result = messages_collection.insert_one(message)
        message['_id'] = str(result.inserted_id)
        
        logger.info(f"💬 Message: {username} in {room}")
        
        # Stop typing indicator
        if room in typing_users and username in typing_users[room]:
            typing_users[room].discard(username)
            socketio.emit('user_typing', {'username': username, 'room': room, 'typing': False}, to=room)
        
        emit_data = {
            'username': username,
            'message': message['message'],
            'timestamp': current_time,
            'room': room,
            '_id': message['_id'],
            'current_user': username,
            'read_by': [username]
        }
        
        if 'attachments' in message:
            emit_data['attachments'] = message['attachments']
        elif 'attachment' in message:
            emit_data['attachment'] = message['attachment']
        
        socketio.emit('message', emit_data, to=room)
        
        # Send notifications
        if room == 'general':
            for user in active_users:
                if user != username:
                    if user not in unread_counts:
                        unread_counts[user] = {}
                    unread_counts[user][room] = unread_counts.get(user, {}).get(room, 0) + 1
                    socketio.emit('notification', {
                        'message': f'{message_text[:50]}',
                        'room': room,
                        'count': unread_counts[user][room],
                        'sender': username
                    }, to=user)
        else:
            room_users = room.split(':')
            target_user = room_users[0] if room_users[1] == username else room_users[1]
            if target_user in active_users:
                if target_user not in unread_counts:
                    unread_counts[target_user] = {}
                unread_counts[target_user][room] = unread_counts.get(target_user, {}).get(room, 0) + 1
                socketio.emit('notification', {
                    'message': f'{message_text[:50]}',
                    'room': room,
                    'count': unread_counts[target_user][room],
                    'sender': username
                }, to=target_user)
    except Exception as e:
        logger.error(f"❌ Message handler error: {e}")

@socketio.on('delete_message')
def handle_delete_message(data):
    """Handle message deletion"""
    username = session.get('username')
    if not username:
        emit('error', {'msg': 'Not authenticated'})
        return
    
    message_id = data.get('message_id')
    room = data.get('room')
    
    if not message_id or not room:
        emit('error', {'msg': 'Invalid request'})
        return
    
    try:
        message = messages_collection.find_one({'_id': ObjectId(message_id), 'room': room})
        if not message or message['username'] != username:
            emit('error', {'msg': 'Unauthorized'})
            return
        
        messages_collection.delete_one({'_id': ObjectId(message_id)})
        logger.info(f"🗑️ Message deleted: {message_id}")
        socketio.emit('delete_message', {'message_id': message_id}, to=room)
    except Exception as e:
        logger.error(f"❌ Delete message error: {e}")

@socketio.on('edit_message')
def handle_edit_message(data):
    """Handle message editing"""
    username = session.get('username')
    if not username:
        emit('error', {'msg': 'Not authenticated'})
        return
    
    message_id = data.get('message_id')
    room = data.get('room')
    new_message = data.get('new_message', '').strip()
    
    if not message_id or not room or not new_message:
        emit('error', {'msg': 'Invalid request'})
        return
    
    try:
        message = messages_collection.find_one({'_id': ObjectId(message_id), 'room': room})
        if not message or message['username'] != username:
            emit('error', {'msg': 'Unauthorized'})
            return
        
        messages_collection.update_one(
            {'_id': ObjectId(message_id)},
            {'$set': {'message': new_message, 'edited': True, 'edited_at': get_current_time()}}
        )
        
        logger.info(f"✏️ Message edited: {message_id}")
        socketio.emit('edit_message', {
            'message_id': message_id,
            'new_message': new_message,
            'timestamp': get_current_time(),
            'edited': True
        }, to=room)
    except Exception as e:
        logger.error(f"❌ Edit message error: {e}")

@socketio.on('leave')
def on_leave(data):
    """Handle room leave"""
    username = session.get('username')
    if not username:
        return
    
    room = data['room']
    leave_room(room)
    
    logger.info(f"👋 {username} left: {room}")
    emit('status', {'msg': f'{username} has left the chat.'}, to=room)

@socketio.on('disconnect')
def on_disconnect():
    """Handle client disconnect"""
    username = session.get('username')
    
    if username and username in active_users:
        logger.info(f"🔌 Disconnected: {username}")
        
        active_users[username]['online'] = False
        
        try:
            users_collection.update_one(
                {'username': username},
                {'$set': {'online': False, 'last_seen': get_current_time()}}
            )
        except Exception as e:
            logger.error(f"❌ Disconnect handler error: {e}")
        
        if username in unread_counts:
            del unread_counts[username]
        
        # Clean up typing users
        if username in typing_users:
            for room in list(typing_users.keys()):
                if username in typing_users[room]:
                    typing_users[room].discard(username)
        
        socketio.emit('user_offline', {'username': username})

# Error handlers
@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"❌ Internal error: {error}")
    return render_template('500.html'), 500

# Health check endpoint (for deployment platforms)
@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'timestamp': get_current_time()}), 200

if __name__ == '__main__':
    # Get configuration from environment
    port = int(os.getenv('PORT', 5000))
    debug_mode = os.getenv('DEBUG', 'False').lower() == 'true'
    host = os.getenv('HOST', '0.0.0.0')
    
    logger.info(f"🚀 Starting Chatlet server...")
    logger.info(f"📊 Debug mode: {debug_mode}")
    logger.info(f"🌐 Host: {host}:{port}")
    
    # Run with eventlet for better production performance
    socketio.run(
        app,
        debug=debug_mode,
        host=host,
        port=port
    )
