from flask import Flask, request, render_template, redirect, url_for, send_from_directory, session
from flask_sqlalchemy import SQLAlchemy
import paramiko
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import traceback

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///servers.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class Server(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(15), nullable=False, unique=True)
    hostname = db.Column(db.String(50))
    username = db.Column(db.String(50), nullable=False, default='suresh')
    tags = db.Column(db.String(200), default='')  # New tags field

with app.app_context():
    db.create_all()

ARTIFACTS_FOLDER = "artifacts"
SSH_PRIVATE_KEY_PATH = os.path.expanduser("~/.ssh/id_rsa")
os.makedirs(ARTIFACTS_FOLDER, exist_ok=True)

# Helper function to handle app context
def get_server(ip):
    with app.app_context():
        return Server.query.filter_by(ip=ip).first()

@app.route('/')
def index():
    with app.app_context():
        servers = Server.query.all()
    return render_template("index.html", servers=servers)

@app.route('/add_server', methods=['POST'])
def add_server():
    ip = request.form.get('ip')
    hostname = request.form.get('hostname')
    username = request.form.get('username') or 'suresh'
    tags = request.form.get('tags', '').strip()

    if not ip:
        return "IP address is required", 400

    with app.app_context():
        existing_server = Server.query.filter_by(ip=ip).first()
        if existing_server:
            existing_server.hostname = hostname
            existing_server.username = username
            existing_server.tags = tags
        else:
            new_server = Server(
                ip=ip,
                hostname=hostname,
                username=username,
                tags=tags
            )
            db.session.add(new_server)
        db.session.commit()
    return redirect(url_for('index'))

@app.route('/delete_server/<int:server_id>')
def delete_server(server_id):
    with app.app_context():
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
    commands = ["cat /etc/os-release", "lsb_release -a", "uname -a", "free -h", "df -h"]
    for cmd in commands:
        try:
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
        except:
            continue
    return "unknown"

def run_command(ip, action):
    try:
        server = get_server(ip)
        if not server:
            return (ip, "❌ Server not registered", "red", "N/A", None, ["---"])

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=server.username, key_filename=SSH_PRIVATE_KEY_PATH, timeout=15)

        artifact_data = f"System Information for {ip}\n{'='*40}\n"
        services_file = os.path.join(ARTIFACTS_FOLDER, f"{ip}_services.txt")
        failed_services = []
        uptime = "N/A"

        # Collect system diagnostics
        commands = ["cat /etc/os-release", "date", "uptime -p", "free -h", "df -h"]
        for cmd in commands:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            output = stdout.read().decode().strip() or 'N/A'
            artifact_data += f"\nCommand: {cmd}\n{output}\n"

        if action == "reboot":
            # Capture pre-reboot services
            stdin, stdout, stderr = ssh.exec_command(
                "systemctl list-units --type=service --state=running --no-legend | awk '{print $1}'"
            )
            initial_services = [s.strip() for s in stdout.read().decode().splitlines() if s.strip()]
            with open(services_file, "w") as f:
                f.write("\n".join(initial_services))

            # Initiate reboot
            ssh.exec_command("sudo shutdown -r now")
            time.sleep(180)  # Wait for reboot completion

            try:
                # Post-reboot connection
                ssh.connect(ip, username=server.username, key_filename=SSH_PRIVATE_KEY_PATH, timeout=30)

                # Get uptime
                stdin, stdout, stderr = ssh.exec_command("uptime -p || uptime")
                uptime = stdout.read().decode().strip() or "N/A"

                # Get post-reboot services
                stdin, stdout, stderr = ssh.exec_command(
                    "systemctl list-units --type=service --state=running --no-legend | awk '{print $1}'"
                )
                post_services = [s.strip() for s in stdout.read().decode().splitlines() if s.strip()]

                # Find missing services
                missing_services = list(set(initial_services) - set(post_services))
                restart_failed = []

                if missing_services:
                    artifact_data += "\nService Recovery Attempts:\n"
                    # Attempt to restart missing services
                    for service in missing_services:
                        stdin, stdout, stderr = ssh.exec_command(f"sudo systemctl restart {service}")
                        exit_code = stdout.channel.recv_exit_status()
                        artifact_data += f"Restart {service}: {'Success' if exit_code == 0 else 'Failed'}\n"
                        if exit_code != 0:
                            restart_failed.append(service)
                        time.sleep(1)

                    # Verify final service status
                    stdin, stdout, stderr = ssh.exec_command(
                        "systemctl list-units --type=service --state=running --no-legend | awk '{print $1}'"
                    )
                    final_services = [s.strip() for s in stdout.read().decode().splitlines() if s.strip()]
                    still_missing = list(set(missing_services) - set(final_services))

                    failed_services = list(set(still_missing + restart_failed))

                status = "✅ Reboot Successful" if not failed_services else "⚠️ Reboot Completed with Service Issues"
                color = "green" if not failed_services else "orange"

            except Exception as e:
                status = "❌ Reboot Failed"
                color = "red"
                uptime = "N/A"
                failed_services = ["---"]
                artifact_data += f"\nPost-reboot Error: {str(e)}"

            # Save artifact
            artifact_filename = f"{ip}_reboot_artifact.txt"
            with open(os.path.join(ARTIFACTS_FOLDER, artifact_filename), "w") as f:
                f.write(artifact_data)

            return (ip, status, color, uptime, artifact_filename,
                    failed_services if failed_services else [])

        elif action == "shutdown":
            artifact_filename = f"{ip}_shutdown_artifact.txt"
            with open(os.path.join(ARTIFACTS_FOLDER, artifact_filename), "w") as f:
                f.write(artifact_data)

            ssh.exec_command("sudo shutdown -h now")
            time.sleep(2)
            return (ip, "✅ Shutdown Initiated", "green", "N/A", artifact_filename, None)

    except paramiko.ssh_exception.NoValidConnectionsError:
        return (ip, "❌ Connection Failed", "red", "N/A", None, ["---"])
    except Exception as e:
        return (ip, f"❌ Error: {str(e)}", "red", "N/A", None, ["---"])
    finally:
        try:
            ssh.close()
        except:
            pass

def run_patch_update(ip, apply_patches=False):
    # Initialize artifact data first to prevent UnboundLocalError
    artifact_data = f"Patch Update Information for {ip}\n{'='*40}\n"
    artifact_data += f"Start Time: {datetime.now().isoformat()}\n"
    artifact_filename = None

    try:
        # Get server info and validate
        server = get_server(ip)
        if not server:
            artifact_data += "\n❌ Server not registered in database\n"
            artifact_filename = f"{ip}_patch_error.txt"
            return (ip, "❌ Server not registered", "red", artifact_filename)

        artifact_data += f"\nServer Details:\n- IP: {server.ip}\n- Hostname: {server.hostname}\n- Username: {server.username}\n"
        artifact_data += f"- Tags: {server.tags}\n"

        # Establish SSH connection
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            artifact_data += f"\nConnecting with key: {SSH_PRIVATE_KEY_PATH}\n"
            ssh.connect(
                ip, 
                username=server.username,
                key_filename=SSH_PRIVATE_KEY_PATH,
                timeout=15,
                banner_timeout=30
            )
        except paramiko.ssh_exception.NoValidConnectionsError as e:
            artifact_data += f"\n🚨 Connection Failed: {str(e)}\n"
            artifact_filename = f"{ip}_connection_failure.txt"
            return (ip, "❌ Connection Failed", "red", artifact_filename)

        # Detect OS type
        os_type = detect_os(ssh)
        artifact_data += f"\nOS Detection:\n- Detected OS: {os_type}\n"
        
        if os_type not in ["ubuntu", "debian", "centos", "rhel", "suse"]:
            artifact_data += "\n❌ Unsupported operating system\n"
            artifact_filename = f"{ip}_unsupported_os.txt"
            return (ip, "❌ Unsupported OS", "red", artifact_filename)

        # OS-specific commands setup
        cmd_config = {
            "ubuntu": {
                 "update": "sudo DEBIAN_FRONTEND=noninteractive apt-get update -yq",
                 "check": "apt-get -qq --just-print upgrade",  # Simulate upgrades
                 "upgrade": "sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -yq",
                 "check_phrase": "The following packages will be upgraded:"
            },
            "debian": {
                "update": "sudo DEBIAN_FRONTEND=noninteractive apt update -y",
                "check": "apt list --upgradable",
                "upgrade": "sudo DEBIAN_FRONTEND=noninteractive apt upgrade -y",
                "check_phrase": "upgradable"
            },
            "centos": {
                "update": "sudo yum clean all && sudo yum makecache",
                "check": "sudo yum check-update",
                "upgrade": "sudo yum update -y",
                "check_phrase": "updates available"
            },
            "rhel": {
                "update": "sudo yum clean all && sudo yum makecache",
                "check": "sudo yum check-update",
                "upgrade": "sudo yum update -y",
                "check_phrase": "updates available"
            },
            "suse": {
                "update": "sudo zypper --non-interactive refresh",
                "check": "sudo zypper --non-interactive list-updates",
                "upgrade": "sudo zypper --non-interactive update -y",
                "check_phrase": "No updates found"
            }
        }

        cmds = cmd_config[os_type]
        initial_update_needed = False
        update_successful = False

        # Initial update check
        artifact_data += "\n=== Initial Update Check ===\n"
        for cmd in [cmds['update'], cmds['check']]:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            exit_code = stdout.channel.recv_exit_status()
            output = stdout.read().decode().strip()
            errors = stderr.read().decode().strip()

            artifact_data += f"\nCommand: {cmd}\n"
            artifact_data += f"Exit Code: {exit_code}\n"
            artifact_data += f"Output:\n{output}\n"
            artifact_data += f"Errors:\n{errors}\n"

            # Handle CentOS/RHEL specific exit codes
            if os_type in ["centos", "rhel"] and cmd == cmds['check']:
                initial_update_needed = exit_code == 100
            elif cmd == cmds['check']:
                initial_update_needed = cmds['check_phrase'] not in output

        artifact_data += f"\nInitial Update Needed: {initial_update_needed}\n"

        if not apply_patches:
            status = ("⚠️ Updates available" if initial_update_needed 
                     else "✅ System updated")
            color = "blue" if initial_update_needed else "green"
            artifact_filename = f"{ip}_patch_check.txt"
            return (ip, status, color, artifact_filename)

        # Apply patches if needed
        if not initial_update_needed:
            artifact_data += "\nNo updates available to apply\n"
            artifact_filename = f"{ip}_no_updates.txt"
            return (ip, "✅ System already up-to-date", "green", artifact_filename)

        artifact_data += "\n=== Applying Updates ===\n"
        stdin, stdout, stderr = ssh.exec_command(cmds['upgrade'])
        exit_code = stdout.channel.recv_exit_status()
        output = stdout.read().decode().strip()
        errors = stderr.read().decode().strip()

        artifact_data += f"\nCommand: {cmds['upgrade']}\n"
        artifact_data += f"Exit Code: {exit_code}\n"
        artifact_data += f"Output:\n{output}\n"
        artifact_data += f"Errors:\n{errors}\n"

        if exit_code != 0:
            artifact_data += "\n❌ Update installation failed\n"
            artifact_filename = f"{ip}_update_failure.txt"
            return (ip, "❌ Patch installation failed", "red", artifact_filename)

        # Post-update verification
        artifact_data += "\n=== Post-Update Verification ===\n"
        stdin, stdout, stderr = ssh.exec_command(cmds['check'])
        exit_code = stdout.channel.recv_exit_status()
        output = stdout.read().decode().strip()
        errors = stderr.read().decode().strip()

        artifact_data += f"\nCommand: {cmds['check']}\n"
        artifact_data += f"Exit Code: {exit_code}\n"
        artifact_data += f"Output:\n{output}\n"
        artifact_data += f"Errors:\n{errors}\n"

        # Determine final status
        if os_type in ["centos", "rhel"]:
            final_update_needed = exit_code == 100
        else:
            final_update_needed = cmds['check_phrase'] not in output

        if final_update_needed:
            artifact_data += "\n⚠️ Some updates might still be pending\n"
            status_msg = "⚠️ Partial updates installed"
            color = "orange"
        else:
            artifact_data += "\n✅ All updates applied successfully\n"
            status_msg = "✅ Updates installed"
            color = "green"

        artifact_filename = f"{ip}_patch_results.txt"
        return (ip, status_msg, color, artifact_filename)

    except Exception as e:
        error_msg = f"\n!!! Critical Error: {str(e)}\n"
        artifact_data += error_msg
        artifact_data += f"Exception Type: {type(e).__name__}\n"
        artifact_data += f"Traceback: {traceback.format_exc()}\n"
        
        # Ensure we save artifacts even on critical failures
        artifact_filename = f"{ip}_critical_error.txt"
        with open(os.path.join(ARTIFACTS_FOLDER, artifact_filename), "w") as f:
            f.write(artifact_data)
            
        return (ip, f"❌ Critical Error: {str(e)}", "red", artifact_filename)

    finally:
        # Cleanup and write artifact file
        if artifact_filename and not os.path.exists(os.path.join(ARTIFACTS_FOLDER, artifact_filename)):
            with open(os.path.join(ARTIFACTS_FOLDER, artifact_filename), "w") as f:
                f.write(artifact_data)
        
        try:
            ssh.close()
        except:
            pass

def apply_patches_and_reboot(ip):
    try:
        # Step 1: Apply patches (if any)
        patch_result = run_patch_update(ip, apply_patches=True)
        ip_patch, status_patch, color_patch, artifact_patch = patch_result

        if "❌" in status_patch:
            return (ip, status_patch, color_patch, "N/A", artifact_patch, ["---"])

        # Step 2: Always check reboot requirement regardless of patch status
        server = get_server(ip)
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=server.username, 
                   key_filename=SSH_PRIVATE_KEY_PATH, timeout=15)
        
        os_type = detect_os(ssh)
        reboot_required = False
        reboot_reason = ""

        # OS-specific reboot checks
        if os_type in ["ubuntu", "debian"]:
            # Check for existence of reboot-required files
            stdin, stdout, stderr = ssh.exec_command(
                "[ -f /var/run/reboot-required ] && echo 'reboot required' || echo 'ok'"
            )
            reboot_required = "reboot required" in stdout.read().decode()
            reboot_reason = "Kernel update or critical service update pending"
            
        elif os_type in ["centos", "rhel"]:
            # Check if system needs restart for updates
            stdin, stdout, stderr = ssh.exec_command(
                "needs-restarting -r &> /dev/null; echo $?"
            )
            reboot_required = stdout.read().decode().strip() == "1"
            reboot_reason = "Core library or service update requires restart"
            
        elif os_type == "suse":
            # Check for reboot-needed flag
            stdin, stdout, stderr = ssh.exec_command(
                "[ -f /var/run/reboot-needed ] && echo 'reboot required' || echo 'ok'"
            )
            reboot_required = "reboot required" in stdout.read().decode()
            reboot_reason = "System libraries or services require restart"
        
        ssh.close()

        # Step 3: Reboot if required
        if reboot_required:
            reboot_result = run_command(ip, 'reboot')
            ip_reboot, status_reboot, color_reboot, uptime, artifact_reboot, failed_services = reboot_result
            
            # Combine artifacts
            combined_artifact = f"{ip}_full_reboot_log.txt"
            try:
                with open(os.path.join(ARTIFACTS_FOLDER, artifact_patch), 'r') as f1, \
                     open(os.path.join(ARTIFACTS_FOLDER, artifact_reboot), 'r') as f2:
                    combined_content = f"PATCH LOGS:\n{f1.read()}\n\nREBOOT LOGS:\n{f2.read()}"
                
                with open(os.path.join(ARTIFACTS_FOLDER, combined_artifact), 'w') as f:
                    f.write(f"Reboot Reason: {reboot_reason}\n")
                    f.write(combined_content)
                
                os.remove(os.path.join(ARTIFACTS_FOLDER, artifact_patch))
                os.remove(os.path.join(ARTIFACTS_FOLDER, artifact_reboot))
            except Exception as e:
                combined_artifact = artifact_patch or artifact_reboot

            return (ip, 
                   f"{status_patch} + {status_reboot}", 
                   color_reboot if "❌" in status_reboot else color_patch,
                   uptime,
                   combined_artifact,
                   failed_services)
        
        # Step 4: Handle no reboot needed
        return (ip, 
               f"{status_patch} (No reboot required)", 
               color_patch,
               "Not rebooted",
               artifact_patch, 
               ["---"])

    except paramiko.ssh_exception.NoValidConnectionsError:
        return (ip, "❌ Connection Failed", "red", "N/A", None, ["---"])
    except Exception as e:
        return (ip, f"❌ Error: {str(e)}", "red", "N/A", None, ["---"])
# Update the process_servers route
@app.route("/process/<action>", methods=["GET", "POST"])
def process_servers(action):
    if action in ["reboot", "shutdown"]:
        if request.method != "POST" or request.form.get("confirmation") != "yes":
            return redirect(url_for('index'))

    if 'selected_ips' not in session or session.get('action') != action:
        return redirect(url_for('index'))

    servers = session['selected_ips']
    session.pop('selected_ips', None)
    session.pop('action', None)

    results = []
    with ThreadPoolExecutor() as executor:
        if action == "reboot":
            futures = [executor.submit(run_command, ip, 'reboot') for ip in servers]
        elif action == "shutdown":
            futures = [executor.submit(run_command, ip, 'shutdown') for ip in servers]
        elif action == "apply_patches_and_reboot":
            futures = [executor.submit(apply_patches_and_reboot, ip) for ip in servers]
        else:
            apply_patches = (action == "apply_patches")
            futures = [executor.submit(run_patch_update, ip, apply_patches) for ip in servers]

        for future in as_completed(futures):
            res = future.result()
            # Normalize results to 6 elements
            if len(res) == 4:  # Patch results
                results.append((res[0], res[1], res[2], None, res[3], None))
            else:
                results.append(res)

    return render_template("results.html", results=results, action=action)


@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(ARTIFACTS_FOLDER, filename, as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
