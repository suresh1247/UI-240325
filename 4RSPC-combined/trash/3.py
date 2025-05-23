from flask import Flask, request, render_template, redirect, url_for, send_from_directory, jsonify
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

def detect_os(ssh):
    """Detects the OS type of the remote server."""
    commands = ["cat /etc/os-release", "lsb_release -a", "uname -a"]
    for cmd in commands:
        stdin, stdout, stderr = ssh.exec_command(cmd)
        output = stdout.read().decode().lower()
        if "ubuntu" in output:
            return "ubuntu"
        elif "debian" in output:
            return "debian"
        elif "centos" in output:
            return "centos"
        elif "red hat" in output or "redhat" in output:
            return "rhel"
        elif "suse" in output or "sles" in output:
            return "suse"
    return "unknown"

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

        # Fetch running services before reboot and save to a file
        running_services_before = []
        services_file_path = os.path.join(ARTIFACTS_FOLDER, f"{ip}_services.txt")
        if action == "reboot":
            stdin, stdout, stderr = ssh.exec_command("systemctl list-units --type=service --state=running --no-legend | awk '{print $1}'")
            running_services_before = stdout.read().decode().splitlines()
            print(f"Running services before reboot on {ip}: {running_services_before}")  # Debug output

            # Save the list of services to a file
            with open(services_file_path, "w") as f:
                for service in running_services_before:
                    f.write(f"{service}\n")

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

        # Fetch running services after reboot and compare with the saved list
        failed_services = []
        if action == "reboot" and status == "✅ Rebooted Successfully":
            # Read the list of services from the file
            with open(services_file_path, "r") as f:
                running_services_before = f.read().splitlines()

            # Fetch running services after reboot
            stdin, stdout, stderr = ssh.exec_command("systemctl list-units --type=service --state=running --no-legend | awk '{print $1}'")
            running_services_after = stdout.read().decode().splitlines()
            print(f"Running services after reboot on {ip}: {running_services_after}")  # Debug output

            # Compare before and after reboot service lists
            for service in running_services_before:
                if service not in running_services_after:
                    # Try to restart the service
                    stdin, stdout, stderr = ssh.exec_command(f"sudo systemctl restart {service}")
                    error = stderr.read().decode()
                    if error:
                        print(f"Error restarting service {service} on {ip}: {error}")  # Debug output
                        failed_services.append(service)
                    else:
                        # Verify if the service is running after restart
                        stdin, stdout, stderr = ssh.exec_command(f"systemctl is-active {service}")
                        service_state = stdout.read().decode().strip()
                        if service_state != "active":
                            failed_services.append(service)

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
        return (ip, status, color, artifact_filename, uptime, failed_services)

    except Exception as e:
        print(f"Error connecting to {ip}: {str(e)}")  # Debug output
        return (ip, f"❌ Error: {str(e)}", "red", None, None, None)  # Return None for failed_services to indicate an error

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

def run_patch_update(ip, username, password, apply_patches=False):
    """Runs patch updates on the remote server and determines the update status."""
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password)

        os_type = detect_os(client)

        if os_type == "ubuntu" or os_type == "debian":
            commands = [
                "sudo apt update -y",
                "sudo apt list --upgradable"
            ]
            if apply_patches:
                commands.append("sudo apt upgrade -y")
        elif os_type == "centos" or os_type == "rhel":
            # Check if the server is CentOS 8
            stdin, stdout, stderr = client.exec_command("cat /etc/redhat-release")
            centos_version = stdout.read().decode().strip()
            if "release 8" in centos_version:
                # Update CentOS 8 repositories to use vault.centos.org
                repo_update_commands = [
                    "sudo sed -i 's/mirror.centos.org/vault.centos.org/g' /etc/yum.repos.d/CentOS-*.repo",
                    "sudo sed -i 's/#baseurl/baseurl/g' /etc/yum.repos.d/CentOS-*.repo",
                    "sudo sed -i 's/^mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*.repo"
                ]
                for cmd in repo_update_commands:
                    stdin, stdout, stderr = client.exec_command(cmd)
                    error = stderr.read().decode()
                    if error:
                        return (ip, f"FAILED - Error updating repositories: {error}", "red", None, None)

            commands = [
                "sudo yum clean all",
                "sudo yum makecache",
                "sudo yum check-update"
            ]
            if apply_patches:
                commands.append("sudo yum update -y")
        elif os_type == "suse":
            commands = [
                "sudo zypper refresh",
                "sudo zypper list-updates"
            ]
            if apply_patches:
                commands.append("sudo zypper update -y")
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
            if apply_patches:
                return (ip, "✅ SUCCESS - Updates Installed", "green", artifact_filename, None)
            else:
                return (ip, "✅ Updates Available", "blue", artifact_filename, None)
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
        futures = {executor.submit(run_patch_update, ip, username, password, apply_patches=True): (ip, username, password) for ip, username, password in servers}

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

@app.route('/check-updates')
def check_updates():
    """Handles checking for updates on servers."""
    inventory_path = os.path.join(UPLOAD_FOLDER, "inventory.csv")

    if not os.path.exists(inventory_path):
        return redirect(url_for('index'))  # Redirect to home if file is missing

    results = []
    in_progress = True  # Flag to indicate that the process is in progress

    with open(inventory_path, "r") as csvfile:
        reader = csv.reader(csvfile)
        servers = [row for row in reader if len(row) >= 3]

    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(run_patch_update, ip, username, password, apply_patches=False): (ip, username, password) for ip, username, password in servers}

        for future in as_completed(futures):
            result = future.result()
            print(f"Result for {result[0]}: {result[1]}")  # Debug output
            results.append(result)

    in_progress = False  # Process completed

    # Delete the inventory file after execution
    if os.path.exists(inventory_path):
        os.remove(inventory_path)

    print(f"Results before rendering: {results}")  # Debug output
    return render_template("results.html", results=results, action="check-updates", in_progress=in_progress)

@app.route('/download/<filename>')
def download_file(filename):
    """Allows users to download artifact files."""
    return send_from_directory(ARTIFACTS_FOLDER, filename, as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
