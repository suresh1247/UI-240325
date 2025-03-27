from flask import Flask, request, render_template, redirect, url_for, send_from_directory
import paramiko
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from stegano import lsb
import csv

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
    """Extracts hidden credentials from image using steganography"""
    try:
        secret_data = lsb.reveal(image_path)
        csv_data = [line.split(',') for line in secret_data.split('\n') if line.strip()]
        
        temp_csv = os.path.join(UPLOAD_FOLDER, "temp_inventory.csv")
        with open(temp_csv, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerows(csv_data)
        return temp_csv
    except Exception as e:
        print(f"Error extracting credentials: {e}")
        return None

@app.route('/')
def index():
    """Main page with upload form"""
    if not request.args.get("keep"):
        clear_uploads_folder()

    inventory_path = os.path.join(UPLOAD_FOLDER, "temp_inventory.csv")
    uploaded = os.path.exists(inventory_path)
    servers = []
    
    if uploaded:
        with open(inventory_path, "r") as f:
            reader = csv.reader(f)
            servers = [row for row in reader if len(row) >= 3]

    return render_template("index.html", 
                         uploaded=uploaded, 
                         servers=servers, 
                         action=request.args.get("action"))

@app.route("/upload", methods=["POST"])
def upload_file():
    """Handles image upload with hidden credentials"""
    if "file" not in request.files:
        return "No file part", 400

    file = request.files["file"]
    if file.filename == "":
        return "No selected file", 400

    image_path = os.path.join(UPLOAD_FOLDER, "temp_image.png")
    file.save(image_path)
    csv_path = extract_credentials(image_path)
    os.remove(image_path)

    if not csv_path or not os.path.exists(csv_path):
        return "Failed to extract credentials", 400

    return redirect(url_for("index", keep="true"))

def detect_os(ssh):
    """Detects remote server OS type"""
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
    """Executes reboot/shutdown commands"""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=10)

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
            status = "✅ Rebooted" if ssh.connect(ip, username=username, password=password, timeout=5) else "❌ Failed"
            color = "green" if "✅" in status else "red"
        elif action == "shutdown":
            ssh.exec_command("sudo shutdown -h now")
            time.sleep(5)
            try:
                ssh.connect(ip, username=username, password=password, timeout=5)
                status = "❌ Failed"
                color = "red"
            except:
                status = "✅ Shutdown"
                color = "green"

        ssh.close()
        return (ip, status, color, artifact_filename)

    except Exception as e:
        return (ip, f"❌ Error: {str(e)}", "red", None)

def run_patch_update(ip, username, password, apply_patches=False):
    """Handles patch updates"""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=10)

        os_type = detect_os(ssh)
        artifact_data = f"Patch Update for {ip}\n{'='*40}\n"
        
        if os_type in ["ubuntu", "debian"]:
            cmds = ["sudo apt update -y", "sudo apt list --upgradable"]
            if apply_patches: cmds.append("sudo apt upgrade -y")
        elif os_type in ["centos", "rhel"]:
            cmds = ["sudo yum check-update"]
            if apply_patches: cmds.append("sudo yum update -y")
        elif os_type == "suse":
            cmds = ["sudo zypper refresh", "sudo zypper list-updates"]
            if apply_patches: cmds.append("sudo zypper update -y")
        else:
            return (ip, "❌ Unsupported OS", "red", None)

        update_needed = False
        for cmd in cmds:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            output = stdout.read().decode()
            artifact_data += f"\nCommand: {cmd}\n{output}"
            if "upgradable" in output or "update" in output:
                update_needed = True

        artifact_filename = f"{ip}_patch.txt"
        with open(os.path.join(ARTIFACTS_FOLDER, artifact_filename), "w") as f:
            f.write(artifact_data)

        if update_needed:
            status = "✅ Updates Installed" if apply_patches else "🔵 Updates Available"
            color = "green" if apply_patches else "blue"
        else:
            status = "✅ Up to Date"
            color = "green"
            
        return (ip, status, color, artifact_filename)

    except Exception as e:
        return (ip, f"❌ Error: {str(e)}", "red", None)

@app.route("/process/<action>")
def process_servers(action):
    """Processes reboot/shutdown actions"""
    inventory_path = os.path.join(UPLOAD_FOLDER, "temp_inventory.csv")
    if not os.path.exists(inventory_path):
        return redirect(url_for('index', action=action))

    with open(inventory_path, "r") as f:
        servers = [row for row in csv.reader(f) if len(row) >= 3]

    results = []
    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(run_command, ip, user, pwd, action) for ip, user, pwd in servers]
        for future in as_completed(futures):
            results.append(future.result())

    return render_template("results.html", results=results, action=action)

@app.route('/patch', methods=['POST'])
def patch_servers():
    """Applies patches to servers"""
    inventory_path = os.path.join(UPLOAD_FOLDER, "temp_inventory.csv")
    if not os.path.exists(inventory_path):
        return redirect(url_for('index', action='patch'))

    with open(inventory_path, "r") as f:
        servers = [row for row in csv.reader(f) if len(row) >= 3]

    results = []
    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(run_patch_update, ip, user, pwd, True) for ip, user, pwd in servers]
        for future in as_completed(futures):
            results.append(future.result())

    return render_template("results.html", results=results, action="patch")

@app.route('/check-updates')
def check_updates():
    """Checks for available updates"""
    inventory_path = os.path.join(UPLOAD_FOLDER, "temp_inventory.csv")
    if not os.path.exists(inventory_path):
        return redirect(url_for('index', action='check-updates'))

    with open(inventory_path, "r") as f:
        servers = [row for row in csv.reader(f) if len(row) >= 3]

    results = []
    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(run_patch_update, ip, user, pwd, False) for ip, user, pwd in servers]
        for future in as_completed(futures):
            results.append(future.result())

    return render_template("results.html", results=results, action="check-updates")

@app.route('/download/<filename>')
def download_file(filename):
    """Downloads artifact files"""
    return send_from_directory(ARTIFACTS_FOLDER, filename, as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
