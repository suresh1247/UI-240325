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
        print(f"Connecting to {ip}...")  # Debug output
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=10)

        artifact_data = f"System Information for {ip}\n{'='*40}\n"
        commands = ["cat /etc/os-release", "date", "ip a", "free -h", "df -h", "uptime", "netstat -planetu", "uname -r"]

        for cmd in commands:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            output = stdout.read().decode()
            error = stderr.read().decode()
            artifact_data += f"\nCommand: {cmd}\n{output}"
            if error:
                print(f"Error executing {cmd} on {ip}: {error}")  # Debug output

        # Save system info before action
        artifact_filename = f"{ip}_artifact.txt"
        artifact_path = os.path.join(ARTIFACTS_FOLDER, artifact_filename)
        with open(artifact_path, "w") as f:
            f.write(artifact_data)
        print(f"Artifact saved: {artifact_path}")  # Debug output

        # Execute Reboot or Shutdown
        if action == "reboot":
            print(f"Rebooting {ip}...")  # Debug output
            ssh.exec_command("sudo shutdown -r now")
            time.sleep(180)  # Wait for reboot

        elif action == "shutdown":
            print(f"Shutting down {ip}...")  # Debug output
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
            uptime_output = stdout.read().decode().strip()
            if uptime_output:
                uptime = uptime_output
            else:
                uptime = "N/A (Command failed)"
            print(f"Uptime for {ip}: {uptime}")  # Debug output

        ssh.close()
        return (ip, status, color, artifact_filename, uptime)

    except Exception as e:
        print(f"Error connecting to {ip}: {str(e)}")  # Debug output
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
            result = future.result()
            print(f"Result for {result[0]}: {result[1]}")  # Debug output
            results.append(result)

    in_progress = False  # Process completed

    # Delete the inventory file after execution
    if os.path.exists(inventory_path):
        os.remove(inventory_path)

    print(f"Results before rendering: {results}")  # Debug output
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

def run_patch_update(ip, username, password):
    """Runs patch updates on the remote server and determines the update status."""
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
            return (ip, "FAILED - Unsupported OS", "red", None, None)

        update_needed = False  # Flag to check if updates were available

        artifact_data = f"Patch Update Information for {ip}\n{'='*40}\n"

        for cmd in commands:
            stdin, stdout, stderr = client.exec_command(cmd)
            output = stdout.read().decode()
            error = stderr.read().decode()
            artifact_data += f"\nCommand: {cmd}\n{output}"

            if error:
                return (ip, f"FAILED - {error}", "red", None, None)

            # If command output indicates available updates
            if "upgradable" in output or "updates available" in output or "Updating" in output:
                update_needed = True

        client.close()

        # Save system info before action
        artifact_filename = f"{ip}_patch_artifact.txt"
        artifact_path = os.path.join(ARTIFACTS_FOLDER, artifact_filename)
        with open(artifact_path, "w") as f:
            f.write(artifact_data)

        if update_needed:
            return (ip, "✅ SUCCESS - Updates Installed", "green", artifact_filename, None)
        else:
            return (ip, "✅ SERVER IS UP TO DATE", "green", artifact_filename, None)

    except Exception as e:
        return (ip, f"FAILED - {str(e)}", "red", None, None)

@app.route('/patch', methods=['POST'])
def patch_servers():
    """Handles patch updates for servers."""
    inventory_path = os.path.join(UPLOAD_FOLDER, "inventory.csv")

    if not os.path.exists(inventory_path):
        return redirect(url_for('index'))  # Redirect to home if file is missing

    results = []
    in_progress = True  # Flag to indicate that the process is in progress

    with open(inventory_path, "r") as csvfile:
        reader = csv.reader(csvfile)
        servers = [row for row in reader if len(row) >= 3]

    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(run_patch_update, ip, username, password): (ip, username, password) for ip, username, password in servers}

        for future in as_completed(futures):
            result = future.result()
            print(f"Result for {result[0]}: {result[1]}")  # Debug output
            results.append(result)

    in_progress = False  # Process completed

    # Delete the inventory file after execution
    if os.path.exists(inventory_path):
        os.remove(inventory_path)

    print(f"Results before rendering: {results}")  # Debug output
    return render_template("results.html", results=results, action="patch", in_progress=in_progress)

@app.route('/download/<filename>')
def download_file(filename):
    """Allows users to download artifact files."""
    return send_from_directory(ARTIFACTS_FOLDER, filename, as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
