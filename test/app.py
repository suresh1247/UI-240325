from flask import Flask, request, render_template, redirect, url_for, send_from_directory
import paramiko
import os
import time
import csv
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from stegano import lsb

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
ARTIFACTS_FOLDER = "artifacts"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ARTIFACTS_FOLDER, exist_ok=True)

def clear_uploads_folder():
    """Clears uploads folder on startup"""
    for file in os.listdir(UPLOAD_FOLDER):
        file_path = os.path.join(UPLOAD_FOLDER, file)
        try:
            os.remove(file_path)
        except Exception as e:
            print(f"Error removing {file_path}: {e}")

def extract_credentials(image_path):
    """Extracts credentials from image using steganography (format: IP,username,password)"""
    try:
        secret_data = lsb.reveal(image_path)
        if not secret_data:
            raise ValueError("No hidden data found in image")
        
        # Parse CSV format from hidden data
        servers = []
        for line in secret_data.split('\n'):
            line = line.strip()
            if line and line.count(',') >= 2:
                parts = line.split(',')
                ip = parts[0].strip()
                username = parts[1].strip()
                password = parts[2].strip()
                servers.append([ip, username, password])
        
        if not servers:
            raise ValueError("No valid server credentials found")
        
        # Save to temporary CSV
        temp_csv = os.path.join(UPLOAD_FOLDER, "inventory.csv")
        with open(temp_csv, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerows(servers)
        
        return temp_csv
    except Exception as e:
        print(f"Credential extraction failed: {str(e)}")
        return None

@app.route('/')
def index():
    """Main page that shows upload form and server list"""
    if not request.args.get("keep"):
        clear_uploads_folder()

    inventory_path = os.path.join(UPLOAD_FOLDER, "inventory.csv")
    uploaded = os.path.exists(inventory_path)
    servers = []
    
    if uploaded:
        with open(inventory_path, "r") as f:
            servers = list(csv.reader(f))

    return render_template("index.html", 
                         uploaded=uploaded,
                         servers=servers,
                         action=request.args.get("action"))

@app.route("/upload", methods=["POST"])
def upload_file():
    """Handles image upload with hidden credentials"""
    if "file" not in request.files:
        return "No file selected", 400

    file = request.files["file"]
    if file.filename == "":
        return "No file selected", 400

    # Save the uploaded image temporarily
    image_path = os.path.join(UPLOAD_FOLDER, "temp_image.png")
    file.save(image_path)
    
    # Extract credentials from image
    csv_path = extract_credentials(image_path)
    os.remove(image_path)  # Clean up image file
    
    if not csv_path:
        return "Failed to extract credentials from image", 400

    return redirect(url_for("index", keep="true"))

def detect_os(ssh):
    """Detects the OS type of the remote server"""
    commands = ["cat /etc/os-release", "lsb_release -a", "uname -a"]
    for cmd in commands:
        stdin, stdout, stderr = ssh.exec_command(cmd)
        output = stdout.read().decode().lower()
        if "ubuntu" in output: return "ubuntu"
        elif "debian" in output: return "debian"
        elif "centos" in output: return "centos"
        elif "red hat" in output: return "rhel"
        elif "suse" in output: return "suse"
    return "unknown"

def run_command(ip, username, password, action):
    """Executes reboot or shutdown command on server"""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=15)
        
        # Collect system info
        artifact_data = f"System Information for {ip}\n{'='*40}\n"
        commands = ["cat /etc/os-release", "date", "ip a", "free -h", "df -h", "uptime"]
        
        for cmd in commands:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            artifact_data += f"\nCommand: {cmd}\n{stdout.read().decode()}"
        
        # Save artifact
        artifact_filename = f"{ip}_artifact.txt"
        with open(os.path.join(ARTIFACTS_FOLDER, artifact_filename), "w") as f:
            f.write(artifact_data)

        # Execute action
        if action == "reboot":
            ssh.exec_command("sudo shutdown -r now")
            time.sleep(180)
            try:
                ssh.connect(ip, username=username, password=password, timeout=5)
                status = "✅ Rebooted Successfully"
                color = "green"
            except:
                status = "❌ Reboot Failed"
                color = "red"
                
        elif action == "shutdown":
            ssh.exec_command("sudo shutdown -h now")
            time.sleep(5)
            try:
                ssh.connect(ip, username=username, password=password, timeout=5)
                status = "❌ Shutdown Failed"
                color = "red"
            except:
                status = "✅ Shutdown Successful"
                color = "green"
        
        # Get uptime if rebooted successfully
        uptime = None
        if action == "reboot" and "Success" in status:
            stdin, stdout, stderr = ssh.exec_command("uptime")
            uptime = stdout.read().decode().strip() or "N/A"
        
        return (ip, status, color, artifact_filename, uptime)

    except paramiko.AuthenticationException:
        return (ip, "❌ Authentication failed", "red", None, None)
    except socket.timeout:
        return (ip, "❌ Connection timed out", "red", None, None)
    except Exception as e:
        return (ip, f"❌ Error: {str(e)}", "red", None, None)

def run_patch_update(ip, username, password, apply_patches=False):
    """Handles patch updates for server"""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=15)
        
        os_type = detect_os(ssh)
        artifact_data = f"Patch Update for {ip}\n{'='*40}\n"
        update_needed = False
        
        # OS-specific commands
        if os_type in ["ubuntu", "debian"]:
            cmds = [
                "export DEBIAN_FRONTEND=noninteractive",
                "sudo apt update -y",
                "sudo apt list --upgradable"
            ]
            if apply_patches:
                cmds.append("sudo apt upgrade -y")
        elif os_type in ["centos", "rhel"]:
            cmds = [
                "sudo yum clean all",
                "sudo yum makecache",
                "sudo yum check-update || true"
            ]
            if apply_patches:
                cmds.append("sudo yum update -y")
        elif os_type in ["suse", "sles"]:
            cmds = [
                "sudo zypper refresh",
                "sudo zypper list-updates"
            ]
            if apply_patches:
                cmds.append("sudo zypper update -y")
        else:
            return (ip, "❌ Unsupported OS", "red", None)
        
        # Execute commands
        for cmd in cmds:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            output = stdout.read().decode()
            artifact_data += f"\nCommand: {cmd}\n{output}"
            
            # Check for updates
            if "upgradable" in output or "update" in output:
                update_needed = True
        
        # Save artifact
        artifact_filename = f"{ip}_patch.txt"
        with open(os.path.join(ARTIFACTS_FOLDER, artifact_filename), "w") as f:
            f.write(artifact_data)
        
        # Determine status
        if update_needed:
            if apply_patches:
                return (ip, "✅ Updates Installed", "green", artifact_filename)
            return (ip, "🔵 Updates Available", "blue", artifact_filename)
        return (ip, "✅ System Up-to-date", "green", artifact_filename)
        
    except Exception as e:
        return (ip, f"❌ Error: {str(e)}", "red", None)

@app.route("/process/<action>")
def process_servers(action):
    """Processes reboot/shutdown actions"""
    inventory_path = os.path.join(UPLOAD_FOLDER, "inventory.csv")
    if not os.path.exists(inventory_path):
        return redirect(url_for('index', action=action))

    with open(inventory_path, "r") as f:
        servers = list(csv.reader(f))

    results = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(run_command, ip, user, pwd, action) 
                 for ip, user, pwd in servers if len(servers) >= 3]
        
        for future in as_completed(futures):
            results.append(future.result())

    # Clean up
    if os.path.exists(inventory_path):
        os.remove(inventory_path)

    return render_template("results.html", results=results, action=action, in_progress=False)

@app.route('/patch', methods=['POST'])
def patch_servers():
    """Applies patches to servers"""
    inventory_path = os.path.join(UPLOAD_FOLDER, "inventory.csv")
    if not os.path.exists(inventory_path):
        return redirect(url_for('index', action='patch'))

    with open(inventory_path, "r") as f:
        servers = list(csv.reader(f))

    results = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(run_patch_update, ip, user, pwd, True)
                 for ip, user, pwd in servers if len(servers) >= 3]
        
        for future in as_completed(futures):
            results.append(future.result())

    if os.path.exists(inventory_path):
        os.remove(inventory_path)

    return render_template("results.html", results=results, action="patch", in_progress=False)

@app.route('/check-updates')
def check_updates():
    """Checks for available updates"""
    inventory_path = os.path.join(UPLOAD_FOLDER, "inventory.csv")
    if not os.path.exists(inventory_path):
        return redirect(url_for('index', action='check-updates'))

    with open(inventory_path, "r") as f:
        servers = list(csv.reader(f))

    results = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(run_patch_update, ip, user, pwd, False)
                 for ip, user, pwd in servers if len(servers) >= 3]
        
        for future in as_completed(futures):
            results.append(future.result())

    if os.path.exists(inventory_path):
        os.remove(inventory_path)

    return render_template("results.html", results=results, action="check-updates", in_progress=False)

@app.route('/download/<filename>')
def download_file(filename):
    """Downloads artifact files"""
    return send_from_directory(ARTIFACTS_FOLDER, filename, as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
