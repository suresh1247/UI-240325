from flask import Flask, request, render_template, redirect, url_for, send_from_directory
import paramiko
import csv
import os
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
ARTIFACTS_FOLDER = "artifacts"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ARTIFACTS_FOLDER, exist_ok=True)

# Lock dictionary to prevent race conditions
lock_status = {}

def clear_uploads_folder():
    """Removes all files in the uploads folder at the start of the application."""
    for file in os.listdir(UPLOAD_FOLDER):
        file_path = os.path.join(UPLOAD_FOLDER, file)
        try:
            os.remove(file_path)
        except Exception as e:
            print(f"Error removing {file_path}: {e}")

@app.route('/')
def index():
    """Runs once when the page loads to clear previous uploads."""
    if not request.args.get("keep"):  # Only clear if not redirected from file upload
        clear_uploads_folder()

    uploaded = os.path.exists(os.path.join(UPLOAD_FOLDER, "inventory.csv"))
    return render_template("index.html", uploaded=uploaded)

@app.route("/upload", methods=["POST"])
def upload_file():
    """Handles file upload and redirects to index with an indicator to keep uploaded file."""
    if "file" not in request.files:
        return "No file part", 400

    file = request.files["file"]
    if file.filename == "":
        return "No selected file", 400

    # Save the uploaded inventory file
    file.save(os.path.join(UPLOAD_FOLDER, "inventory.csv"))

    # Redirect to index without clearing files
    return redirect(url_for("index", keep="true"))

def run_command(ip, username, password, action):
    """Handles Reboot or Shutdown for a server and collects results."""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=10)

        artifact_data = f"System Information for {ip}\n{'='*40}\n"
        commands = ["cat /etc/os-release", "date", "ip a", "free -h", "df -h", "uptime", "netstat -planetu", "uname -r"]

        for cmd in commands:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            artifact_data += f"\nCommand: {cmd}\n{stdout.read().decode()}"

        # Save system info before action
        artifact_filename = f"{ip}_artifact.txt"
        artifact_path = os.path.join(ARTIFACTS_FOLDER, artifact_filename)
        with open(artifact_path, "w") as f:
            f.write(artifact_data)

        # Execute Reboot or Shutdown
        if action == "reboot":
            ssh.exec_command("sudo shutdown -r now")
            time.sleep(180)  # Wait for reboot

        elif action == "shutdown":
            ssh.exec_command("sudo shutdown -h now")
            time.sleep(5)

        # Check if server is still reachable (to verify shutdown success)
        try:
            ssh.connect(ip, username=username, password=password, timeout=5)
            status = "❌ Failed" if action == "shutdown" else "✅ Rebooted Successfully"
            color = "red" if action == "shutdown" else "green"
        except:
            status = "✅ Shutdown Successful" if action == "shutdown" else "❌ Reboot Failed"
            color = "green" if action == "shutdown" else "red"

        # Get uptime if action is reboot
        uptime = None
        if action == "reboot":
            stdin, stdout, stderr = ssh.exec_command("uptime")
            uptime = stdout.read().decode().strip()

        ssh.close()
        return (ip, status, color, artifact_filename, uptime)

    except Exception as e:
        return (ip, f"❌ Error: {str(e)}", "red", None, None)

@app.route("/process/<action>")
def process_servers(action):
    """Processes servers in parallel for Reboot or Shutdown."""
    inventory_path = os.path.join(UPLOAD_FOLDER, "inventory.csv")

    if not os.path.exists(inventory_path):
        return redirect(url_for('index'))  # Redirect to home if file is missing

    results = []
    in_progress = True  # Flag to indicate that the process is in progress

    with open(inventory_path, "r") as csvfile:
        reader = csv.reader(csvfile)
        servers = [row for row in reader if len(row) >= 3]

    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(run_command, ip, username, password, action): (ip, username, password) for ip, username, password in servers}

        for future in as_completed(futures):
            results.append(future.result())

    in_progress = False  # Process completed

    # Delete the inventory file after execution
    if os.path.exists(inventory_path):
        os.remove(inventory_path)

    return render_template("results.html", results=results, action=action, in_progress=in_progress)

def get_os_type(client):
    """Identifies the OS type of the remote server."""
    try:
        stdin, stdout, stderr = client.exec_command("cat /etc/os-release")
        output = stdout.read().decode().lower()
        if "ubuntu" in output or "debian" in output:
            return "ubuntu"
        elif "centos" in output or "red hat" in output:
            return "centos"
        elif "suse" in output or "sles" in output:
            return "suse"
        else:
            return "unknown"
    except:
        return "unknown"

def run_patch_update(ip, username, password, results):
    """Runs patch updates on the remote server and determines the update status."""
    with lock_status[ip]:  # Ensure only one thread runs per IP
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, username=username, password=password)

            os_type = get_os_type(client)

            if os_type == "ubuntu":
                commands = [
                    "sudo apt update -y",
                    "sudo apt list --upgradable",
                    "sudo apt upgrade -y"
                ]
            elif os_type == "centos":
                commands = [
                    "sudo yum check-update",
                    "sudo yum update -y"
                ]
            elif os_type == "suse":
                commands = [
                    "sudo zypper refresh",
                    "sudo zypper list-updates",
                    "sudo zypper update -y"
                ]
            else:
                results[ip] = {"ip": ip, "os": os_type, "status": "FAILED - Unsupported OS"}
                return

            update_needed = False  # Flag to check if updates were available

            for cmd in commands:
                stdin, stdout, stderr = client.exec_command(cmd)
                output = stdout.read().decode()
                error = stderr.read().decode()

                if error:
                    results[ip] = {"ip": ip, "os": os_type, "status": f"FAILED - {error}"}
                    return

                # If command output indicates available updates
                if "upgradable" in output or "updates available" in output or "Updating" in output:
                    update_needed = True

            client.close()

            if update_needed:
                results[ip] = {"ip": ip, "os": os_type, "status": "✅ SUCCESS - Updates Installed"}
            else:
                results[ip] = {"ip": ip, "os": os_type, "status": "✅ SERVER IS UP TO DATE"}

        except Exception as e:
            results[ip] = {"ip": ip, "os": "unknown", "status": f"FAILED - {str(e)}"}

@app.route('/patch', methods=['POST'])
def patch_servers():
    """Handles patch updates for servers."""
    statuses = {}
    threads = []

    inventory_path = os.path.join(UPLOAD_FOLDER, "inventory.csv")

    if not os.path.exists(inventory_path):
        return redirect(url_for('index'))  # Redirect to home if file is missing

    with open(inventory_path, "r") as csvfile:
        reader = csv.reader(csvfile)
        servers = [row for row in reader if len(row) >= 3]

    for ip, username, password in servers:
        if ip in statuses:  # Check if this IP was already processed
            statuses[ip] = {"ip": ip, "os": "N/A", "status": "ALREADY EXISTS"}
            continue

        lock_status[ip] = threading.Lock()  # Create a lock for this IP
        statuses[ip] = {"ip": ip, "os": "Processing", "status": "IN PROGRESS"}

        thread = threading.Thread(target=run_patch_update, args=(ip, username, password, statuses))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    return render_template("results.html", results=[statuses[ip] for ip in statuses], action="patch", in_progress=False)

@app.route('/download/<filename>')
def download_file(filename):
    """Allows users to download artifact files."""
    return send_from_directory(ARTIFACTS_FOLDER, filename, as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
