from flask import Flask, request, render_template, redirect, url_for, send_from_directory, session
from flask_sqlalchemy import SQLAlchemy
import paramiko
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///servers.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class Server(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(15), nullable=False, unique=True)
    hostname = db.Column(db.String(50))

# Initialize database within app context
with app.app_context():
    db.create_all()

# Rest of your routes and functions remain the same...
ARTIFACTS_FOLDER = "artifacts"
SSH_PRIVATE_KEY_PATH = os.path.expanduser("~/.ssh/id_rsa")
os.makedirs(ARTIFACTS_FOLDER, exist_ok=True)

@app.route('/')
def index():
    servers = Server.query.all()
    return render_template("index.html", servers=servers)

@app.route('/add_server', methods=['POST'])
def add_server():
    ip = request.form.get('ip')
    hostname = request.form.get('hostname')
    
    if not ip:
        return "IP address is required", 400
    
    existing_server = Server.query.filter_by(ip=ip).first()
    if existing_server:
        return "Server with this IP already exists", 400
    
    new_server = Server(ip=ip, hostname=hostname)
    db.session.add(new_server)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/delete_server/<int:server_id>')
def delete_server(server_id):
    server = Server.query.get_or_404(server_id)
    db.session.delete(server)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/handle_action', methods=['POST'])
def handle_action():
    selected_ips = request.form.getlist('server_ips')
    action = request.form.get('action')
    
    if not selected_ips:
        return "No servers selected", 400
    
    session['selected_ips'] = selected_ips
    session['action'] = action
    
    if action in ['reboot', 'shutdown']:
        return redirect(url_for('confirm_action', action=action))
    else:
        return redirect(url_for('process_servers', action=action))

@app.route("/confirm/<action>")
def confirm_action(action):
    if session.get('action') != action or 'selected_ips' not in session:
        return redirect(url_for('index'))
    return render_template("confirm.html", action=action)

def detect_os(ssh):
    # Existing detect_os implementation remains the same
    # ... (keep original detect_os function code)
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
        elif "red hat" in output:
            return "rhel"
        elif "suse" in output:
            return "suse"
    return "unknown"


def run_command(ip, action):
    # Existing run_command implementation remains the same
    # ... (keep original run_command function code)
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username='suresh', key_filename=SSH_PRIVATE_KEY_PATH, timeout=10)

        artifact_data = f"System Information for {ip}\n{'='*40}\n"
        commands = ["cat /etc/os-release", "date", "ip a", "free -h", "df -h", "uptime"]
        for cmd in commands:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            artifact_data += f"\nCommand: {cmd}\n{stdout.read().decode()}"

        artifact_filename = f"{ip}_artifact.txt"
        with open(os.path.join(ARTIFACTS_FOLDER, artifact_filename), "w") as f:
            f.write(artifact_data)

        services_file = os.path.join(ARTIFACTS_FOLDER, f"{ip}_services.txt")
        failed_services = None

        if action == "reboot":
            stdin, stdout, stderr = ssh.exec_command("systemctl list-units --type=service --state=running --no-legend | awk '{print $1}'")
            with open(services_file, "w") as f:
                f.write(stdout.read().decode())

        ssh.exec_command(f"sudo shutdown -{'r' if action == 'reboot' else 'h'} now")
        time.sleep(180 if action == 'reboot' else 5)

        try:
            ssh.connect(ip, username='suresh', key_filename=SSH_PRIVATE_KEY_PATH, timeout=5)
            status = f"❌ {action.capitalize()} Failed" if action == "shutdown" else "✅ Reboot Successful"
            color = "red" if "Failed" in status else "green"
        except:
            status = f"✅ {action.capitalize()} Successful" if action == "shutdown" else "❌ Reboot Failed"
            color = "green" if "Successful" in status else "red"

        if action == "reboot" and "Successful" in status:
            try:
                with open(services_file) as f:
                    before_services = f.read().splitlines()
                stdin, stdout, stderr = ssh.exec_command("systemctl list-units --type=service --state=running --no-legend | awk '{print $1}'")
                after_services = stdout.read().decode().splitlines()
                failed_services = [svc for svc in before_services if svc not in after_services]
            except:
                failed_services = ["Service check failed"]
        elif action == "reboot":
            failed_services = ["---"]

        return (ip, status, color, artifact_filename, failed_services)

    except Exception as e:
        return (ip, f"❌ Error: {str(e)}", "red", None, ["---"])

def run_patch_update(ip, apply_patches=False):
    # Existing run_patch_update implementation remains the same
    # ... (keep original run_patch_update function code)
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username='suresh', key_filename=SSH_PRIVATE_KEY_PATH, timeout=10)

        os_type = detect_os(ssh)
        artifact_data = f"Patch Update Information for {ip}\n{'='*40}\n"
        update_needed = False

        if os_type in ["ubuntu", "debian"]:
            cmds = [
                "export DEBIAN_FRONTEND=noninteractive",
                "sudo apt update -y",
                "sudo apt list --upgradable"
            ]
            check_cmd = "sudo apt list --upgradable"
            if apply_patches:
                cmds.append("sudo apt upgrade -y")
        elif os_type in ["centos", "rhel"]:
            cmds = [
                "sudo yum clean all",
                "sudo yum makecache",
                "sudo yum check-update || true"
            ]
            check_cmd = "sudo yum check-update"
            if apply_patches:
                cmds.append("sudo yum update -y")
        elif os_type == "suse":
            cmds = [
                "sudo zypper refresh",
                "sudo zypper --non-interactive list-updates"
            ]
            check_cmd = "sudo zypper --non-interactive list-updates"
            if apply_patches:
                cmds.append("sudo zypper --non-interactive update -y")
        else:
            return (ip, "❌ Unsupported OS", "red", None)

        stdin, stdout, stderr = ssh.exec_command(check_cmd)
        exit_code = stdout.channel.recv_exit_status()
        output = stdout.read().decode().lower()

        if os_type in ["centos", "rhel"]:
            update_needed = (exit_code == 100)
        elif os_type == "suse":
            update_needed = ("no updates found" not in output)
        else:
            update_needed = ("upgradable" in output)
        for cmd in cmds:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            artifact_data += f"\nCommand: {cmd}\n{stdout.read().decode()}"

        artifact_filename = f"{ip}_patch_artifact.txt"
        with open(os.path.join(ARTIFACTS_FOLDER, artifact_filename), "w") as f:
            f.write(artifact_data)

        if update_needed:
            if apply_patches:
                return (ip, "✅ Updates Installed", "green", artifact_filename)
            return (ip, "⚠️ Updates Available", "blue", artifact_filename)
        return (ip, "✅ System Updated", "green", artifact_filename)

    except Exception as e:
        return (ip, f"❌ Error: {str(e)}", "red", None)
"""
@app.route("/process/<action>", methods=["POST"])
def process_servers(action):
    if action in ["reboot", "shutdown"] and request.form.get("confirmation") != "yes":
        return redirect(url_for('index'))
    
    if 'selected_ips' not in session or session.get('action') != action:
        return redirect(url_for('index'))
    
    servers = session['selected_ips']
    session.pop('selected_ips', None)
    session.pop('action', None)
    
    results = []
    with ThreadPoolExecutor() as executor:
        if action in ["reboot", "shutdown"]:
            futures = [executor.submit(run_command, ip, action) for ip in servers]
        else:
            apply_patches = (action == "apply_patches")
            futures = [executor.submit(run_patch_update, ip, apply_patches) for ip in servers]

        for future in as_completed(futures):
            results.append(future.result())

    return render_template("results.html", results=results, action=action)
"""
# Update the process_servers route decorator to allow both GET and POST
@app.route("/process/<action>", methods=["GET", "POST"])
def process_servers(action):
    # For destructive actions (reboot/shutdown), require POST confirmation
    if action in ["reboot", "shutdown"]:
        if request.method != "POST" or request.form.get("confirmation") != "yes":
            return redirect(url_for('index'))

    # Verify session data exists
    if 'selected_ips' not in session or session.get('action') != action:
        return redirect(url_for('index'))

    # Get servers from session
    servers = session['selected_ips']

    # Clear session data
    session.pop('selected_ips', None)
    session.pop('action', None)

    # Processing logic remains the same
    results = []
    with ThreadPoolExecutor() as executor:
        if action in ["reboot", "shutdown"]:
            futures = [executor.submit(run_command, ip, action) for ip in servers]
        else:
            apply_patches = (action == "apply_patches")
            futures = [executor.submit(run_patch_update, ip, apply_patches) for ip in servers]

        for future in as_completed(futures):
            results.append(future.result())

    return render_template("results.html", results=results, action=action)
@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(ARTIFACTS_FOLDER, filename, as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
