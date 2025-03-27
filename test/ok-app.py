from flask import Flask, request, render_template, redirect, url_for, send_from_directory
import paramiko
import os
import time
import socket
from concurrent.futures import ThreadPoolExecutor
from stegano import lsb

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
ARTIFACTS_FOLDER = 'artifacts'

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ARTIFACTS_FOLDER, exist_ok=True)

def clear_uploads():
    for f in os.listdir(UPLOAD_FOLDER):
        os.remove(os.path.join(UPLOAD_FOLDER, f))

@app.route('/')
def index():
    if 'keep' not in request.args:
        clear_uploads()
    
    servers = []
    if os.path.exists(os.path.join(UPLOAD_FOLDER, 'servers.csv')):
        with open(os.path.join(UPLOAD_FOLDER, 'servers.csv')) as f:
            servers = [line.strip().split(':') for line in f if line.strip()]
    
    return render_template('index.html', servers=servers)

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return "No file selected", 400
    
    file = request.files['file']
    if file.filename == '':
        return "No file selected", 400
    
    # Save image temporarily
    image_path = os.path.join(UPLOAD_FOLDER, 'temp.png')
    file.save(image_path)
    
    # Extract credentials
    try:
        hidden_data = lsb.reveal(image_path)
        if not hidden_data:
            raise ValueError("No hidden data found")
        
        # Save to CSV
        with open(os.path.join(UPLOAD_FOLDER, 'servers.csv'), 'w') as f:
            f.write(hidden_data)
        
        os.remove(image_path)
        return redirect(url_for('index', keep='true'))
    except Exception as e:
        return f"Error extracting credentials: {str(e)}", 400

def execute_ssh(ip, username, password, action):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=10)
        
        # Create artifact file
        artifact = f"{ip}_{action}.log"
        with open(os.path.join(ARTIFACTS_FOLDER, artifact), 'w') as f:
            f.write(f"=== {action.upper()} LOG FOR {ip} ===\n")
            
            # Get basic info
            stdin, stdout, stderr = ssh.exec_command('hostname')
            f.write(f"Hostname: {stdout.read().decode().strip()}\n")
            
            stdin, stdout, stderr = ssh.exec_command('cat /etc/os-release')
            f.write(f"OS Info:\n{stdout.read().decode()}\n")
            
            # Execute action
            if action == 'reboot':
                ssh.exec_command('sudo shutdown -r now')
                status = "✅ Reboot initiated"
            elif action == 'shutdown':
                ssh.exec_command('sudo shutdown -h now')
                status = "✅ Shutdown initiated"
            elif action == 'patch':
                stdin, stdout, stderr = ssh.exec_command('sudo apt update && sudo apt upgrade -y')
                f.write(stdout.read().decode())
                status = "✅ Updates installed"
            elif action == 'check-updates':
                stdin, stdout, stderr = ssh.exec_command('sudo apt update && apt list --upgradable')
                f.write(stdout.read().decode())
                status = "✅ Updates checked"
                
        return (ip, status, 'green', artifact)
        
    except paramiko.AuthenticationException:
        return (ip, "❌ Authentication failed", 'red', None)
    except socket.timeout:
        return (ip, "❌ Connection timed out", 'red', None)
    except Exception as e:
        return (ip, f"❌ Error: {str(e)}", 'red', None)
    finally:
        try:
            ssh.close()
        except:
            pass

@app.route('/operation/<action>')
def operation(action):
    if not os.path.exists(os.path.join(UPLOAD_FOLDER, 'servers.csv')):
        return redirect(url_for('index'))
    
    with open(os.path.join(UPLOAD_FOLDER, 'servers.csv')) as f:
        servers = [line.strip().split(':') for line in f if line.strip()]
    
    results = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for server in servers:
            if len(server) == 3:
                ip, user, pwd = server
                futures.append(executor.submit(execute_ssh, ip, user, pwd, action))
        
        for future in futures:
            results.append(future.result())
    
    return render_template('results.html', results=results, action=action)

@app.route('/download/<filename>')
def download(filename):
    return send_from_directory(ARTIFACTS_FOLDER, filename)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
