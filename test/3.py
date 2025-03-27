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
    for file in os.listdir(UPLOAD_FOLDER):
        file_path = os.path.join(UPLOAD_FOLDER, file)
        try:
            os.remove(file_path)
        except Exception as e:
            print(f"Error removing {file_path}: {e}")

def extract_credentials(image_path):
    try:
        secret_data = lsb.reveal(image_path)
        if not secret_data:
            raise ValueError("No hidden data found")
        
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
    if not request.args.get("keep"):
        clear_uploads_folder()

    inventory_path = os.path.join(UPLOAD_FOLDER, "inventory.csv")
    uploaded = os.path.exists(inventory_path)
    servers = []
    
    if uploaded:
        with open(inventory_path, "r") as f:
            servers = list(csv.reader(f))

    return render_template("index.html", uploaded=uploaded, servers=servers)

@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return "No file selected", 400

    file = request.files["file"]
    if file.filename == "":
        return "No file selected", 400

    image_path = os.path.join(UPLOAD_FOLDER, "temp_image.png")
    file.save(image_path)
    
    csv_path = extract_credentials(image_path)
    os.remove(image_path)
    
    if not csv_path:
        return "Failed to extract credentials", 400

    return redirect(url_for("index"))

def detect_os(ssh):
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

def get_running_services(ssh, ip):
    try:
        stdin, stdout, stderr = ssh.exec_command("systemctl list-units --type=service --state=running --no-legend | awk '{print $1}'")
        services = stdout.read().decode().splitlines()
        print(f"Running services on {ip}: {services}")
        return services
    except Exception as e:
        print(f"Error getting services on {ip}: {str(e)}")
        return None

def run_command(ip, username, password, action):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=15)
        
        artifact_data = f"System Information for {ip}\n{'='*40}\n"
        commands = ["cat /etc/os-release", "date", "ip a", "free -h", "df -h", "uptime"]
        
        for cmd in commands:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            artifact_data += f"\nCommand: {cmd}\n{stdout.read().decode()}"
        
        artifact_filename = f"{ip}_{action}.log"
        artifact_path = os.path.join(ARTIFACTS_FOLDER, artifact_filename)
        with open(artifact_path, "w") as f:
            f.write(artifact_data)

        # Save services before reboot if action is reboot
        services_before = None
        services_file = None
        if action == "reboot":
            services_before = get_running_services(ssh, ip)
            if services_before:
                services_file = os.path.join(ARTIFACTS_FOLDER, f"{ip}_services.txt")
                with open(services_file, "w") as f:
                    f.write("\n".join(services_before))

        # Execute action
        if action == "reboot":
            ssh.exec_command('sudo shutdown -r now')
            time.sleep(180)
            try:
                ssh.connect(ip, username=username, password=password, timeout=15)
                status = "✅ Rebooted Successfully"
                color = "green"
                
                # Check services after reboot
                failed_services = []
                if services_before and services_file:
                    services_after = get_running_services(ssh, ip)
                    if services_after:
                        with open(services_file, "r") as f:
                            services_before = f.read().splitlines()
                        
                        for service in services_before:
                            if service not in services_after:
                                # Try to restart the service
                                stdin, stdout, stderr = ssh.exec_command(f"sudo systemctl restart {service}")
                                error = stderr.read().decode()
                                if error:
                                    failed_services.append(service)
                                else:
                                    # Verify service is running
                                    stdin, stdout, stderr = ssh.exec_command(f"systemctl is-active {service}")
                                    if stdout.read().decode().strip() != "active":
                                        failed_services.append(service)
                
                uptime = None
                stdin, stdout, stderr = ssh.exec_command("uptime")
                uptime = stdout.read().decode().strip() or "N/A"
                
                return (ip, status, color, artifact_filename, uptime, failed_services)
                
            except:
                status = "❌ Reboot Failed"
                color = "red"
                return (ip, status, color, artifact_filename, None, None)
                
        elif action == "shutdown":
            ssh.exec_command('sudo shutdown -h now')
            time.sleep(5)
            try:
                ssh.connect(ip, username=username, password=password, timeout=5)
                status = "❌ Shutdown Failed"
                color = "red"
            except:
                status = "✅ Shutdown Successful"
                color = "green"
            return (ip, status, color, artifact_filename, None, None)

    except paramiko.AuthenticationException:
        return (ip, "❌ Authentication failed", "red", None, None, None)
    except socket.timeout:
        return (ip, "❌ Connection timed out", "red", None, None, None)
    except Exception as e:
        return (ip, f"❌ Error: {str(e)}", "red", None, None, None)

def run_patch_update(ip, username, password, apply_patches=False):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=15)
        
        os_type = detect_os(ssh)
        artifact_data = f"Patch Update for {ip}\n{'='*40}\n"
        update_needed = False
        
        if os_type in ["ubuntu", "debian"]:
            # Update package lists
            stdin, stdout, stderr = ssh.exec_command('sudo apt update')
            artifact_data += f"\nUpdate output:\n{stdout.read().decode()}"
            
            # Check for upgradable packages
            stdin, stdout, stderr = ssh.exec_command('sudo apt list --upgradable 2>/dev/null')
            upgradable = stdout.read().decode()
            artifact_data += f"\nUpgradable packages:\n{upgradable}"
            
            if "upgradable" in upgradable.lower():
                update_needed = True
            
            if apply_patches and update_needed:
                stdin, stdout, stderr = ssh.exec_command('sudo DEBIAN_FRONTEND=noninteractive apt upgrade -y')
                artifact_data += f"\nUpgrade output:\n{stdout.read().decode()}"
                
        elif os_type in ["centos", "rhel"]:
            # Check for updates
            stdin, stdout, stderr = ssh.exec_command('sudo yum check-update')
            output = stdout.read().decode()
            artifact_data += f"\nUpdate check:\n{output}"
            
            # Check if updates are available (different output patterns)
            if "Available Upgrades" in output or "updates available" in output.lower():
                update_needed = True
            
            if apply_patches and update_needed:
                stdin, stdout, stderr = ssh.exec_command('sudo yum update -y')
                artifact_data += f"\nUpgrade output:\n{stdout.read().decode()}"
                
        elif os_type in ["suse", "sles"]:
            # Refresh repositories
            stdin, stdout, stderr = ssh.exec_command('sudo zypper refresh')
            artifact_data += f"\nRefresh output:\n{stdout.read().decode()}"
            
            # Check for updates
            stdin, stdout, stderr = ssh.exec_command('sudo zypper list-updates')
            output = stdout.read().decode()
            artifact_data += f"\nUpdate check:\n{output}"
            
            # Check if updates are available
            if "No updates found" not in output:
                update_needed = True
            
            if apply_patches and update_needed:
                stdin, stdout, stderr = ssh.exec_command('sudo zypper update -y')
                artifact_data += f"\nUpgrade output:\n{stdout.read().decode()}"
        
        else:
            return (ip, "❌ Unsupported OS", "red", None)
        
        artifact_filename = f"{ip}_patch.log"
        with open(os.path.join(ARTIFACTS_FOLDER, artifact_filename), "w") as f:
            f.write(artifact_data)
        
        if update_needed:
            if apply_patches:
                return (ip, "✅ Updates Installed", "green", artifact_filename)
            return (ip, "🔵 Updates Available", "blue", artifact_filename)
        return (ip, "✅ System Up-to-date", "green", artifact_filename)
        
    except Exception as e:
        return (ip, f"❌ Error: {str(e)}", "red", None)

@app.route("/process/<action>")
def process_servers(action):
    if request.args.get('confirmation') != 'YES':
        return redirect(url_for('index'))

    inventory_path = os.path.join(UPLOAD_FOLDER, "inventory.csv")
    if not os.path.exists(inventory_path):
        return redirect(url_for('index'))

    with open(inventory_path, "r") as f:
        servers = list(csv.reader(f))

    results = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(run_command, ip, user, pwd, action) 
                 for ip, user, pwd in servers if len(servers) >= 3]
        
        for future in as_completed(futures):
            results.append(future.result())

    if os.path.exists(inventory_path):
        os.remove(inventory_path)

    return render_template("results.html", results=results, action=action)

@app.route('/patch', methods=['POST'])
def patch_servers():
    if request.args.get('confirmation') != 'YES':
        return redirect(url_for('index'))

    inventory_path = os.path.join(UPLOAD_FOLDER, "inventory.csv")
    if not os.path.exists(inventory_path):
        return redirect(url_for('index'))

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

    return render_template("results.html", results=results, action="patch")

@app.route('/check-updates')
def check_updates():
    inventory_path = os.path.join(UPLOAD_FOLDER, "inventory.csv")
    if not os.path.exists(inventory_path):
        return redirect(url_for('index'))

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

    return render_template("results.html", results=results, action="check-updates")

@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(ARTIFACTS_FOLDER, filename, as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
