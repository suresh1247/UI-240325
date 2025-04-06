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
    username = db.Column(db.String(50), nullable=False, default='suresh')

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
    
    if not ip:
        return "IP address is required", 400
    
    with app.app_context():
        existing_server = Server.query.filter_by(ip=ip).first()
        if existing_server:
            existing_server.hostname = hostname
            existing_server.username = username
        else:
            new_server = Server(ip=ip, hostname=hostname, username=username)
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
"""
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
        failed_services = None
        uptime = "N/A"

        # Collect diagnostic commands for both actions
        commands = ["cat /etc/os-release", "date", "uptime -p", "free -h", "df -h"]
        for cmd in commands:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            artifact_data += f"\nCommand: {cmd}\n{stdout.read().decode().strip() or 'N/A'}\n"
            # Write artifact before shutting down
        if action == "shutdown":
            artifact_filename = f"{ip}_shutdown_artifact.txt"
            with open(os.path.join(ARTIFACTS_FOLDER, artifact_filename), "w") as f:
                f.write(artifact_data)

            ssh.exec_command("sudo shutdown -h now")
            time.sleep(2)
            return (ip, "✅ Shutdown Initiated", "green", "N/A", artifact_filename, None)

        elif action == "reboot":
            # Collect services before reboot
            stdin, stdout, stderr = ssh.exec_command("systemctl list-units --type=service --state=running --no-legend | awk '{print $1}'")
            with open(services_file, "w") as f:
                f.write(stdout.read().decode())

            # Execute reboot
            ssh.exec_command("sudo shutdown -r now")
            time.sleep(180)

            try:
                # Reconnect post-reboot
                ssh.connect(ip, username=server.username, key_filename=SSH_PRIVATE_KEY_PATH, timeout=30)
                stdin, stdout, stderr = ssh.exec_command("uptime -p || uptime")
                uptime = stdout.read().decode().strip() or "N/A"
                status = "✅ Reboot Successful"
                color = "green"

                # Verify services
                with open(services_file) as f:
                    before_services = f.read().splitlines()
                stdin, stdout, stderr = ssh.exec_command("systemctl list-units --type=service --state=running --no-legend | awk '{print $1}'")
                after_services = stdout.read().decode().splitlines()
                failed_services = [svc for svc in before_services if svc not in after_services]

                # Attempt service restarts
                if failed_services:
                    for service in failed_services.copy():
                        ssh.exec_command(f"sudo systemctl restart {service}")
                        time.sleep(3)
                    stdin, stdout, stderr = ssh.exec_command("systemctl list-units --type=service --state=running --no-legend | awk '{print $1}'")
                    final_services = stdout.read().decode().splitlines()
                    failed_services = [svc for svc in failed_services if svc not in final_services]

            except Exception as e:
                status = "❌ Reboot Failed"
                color = "red"
                uptime = "N/A"
                failed_services = ["---"]

            # Save reboot artifact
            artifact_filename = f"{ip}_reboot_artifact.txt"
            with open(os.path.join(ARTIFACTS_FOLDER, artifact_filename), "w") as f:
                f.write(artifact_data)

            return (ip, status, color, uptime, artifact_filename, failed_services or ["---"])

    except paramiko.ssh_exception.NoValidConnectionsError:
        return (ip, "❌ Connection Failed", "red", "N/A", None, ["---"])
    except Exception as e:
        return (ip, f"❌ Error: {str(e)}", "red", "N/A", None, ["---"])
    finally:
        try:
            ssh.close()
        except:
            pass
"""

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
    try:
        server = get_server(ip)
        if not server:
            return (ip, "❌ Server not registered", "red", None)

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=server.username, key_filename=SSH_PRIVATE_KEY_PATH, timeout=15)

        os_type = detect_os(ssh)
        artifact_data = f"Patch Update Information for {ip}\n{'='*40}\n"
        update_needed = False

        if os_type in ["ubuntu", "debian"]:
            cmds = [
                "sudo apt update -y",
                "sudo apt list --upgradable"
            ]
            check_cmd = "sudo apt list --upgradable"
            if apply_patches:
                cmds.append("sudo DEBIAN_FRONTEND=noninteractive apt upgrade -y")
        elif os_type in ["centos", "rhel"]:
            cmds = [
                "sudo yum clean all",
                "sudo yum makecache",
                "sudo yum check-update"
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

        for cmd in cmds:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            artifact_data += f"\nCommand: {cmd}\n{stdout.read().decode()}"

        stdin, stdout, stderr = ssh.exec_command(check_cmd)
        output = stdout.read().decode().lower()
        exit_code = stdout.channel.recv_exit_status()

        if os_type in ["centos", "rhel"]:
            update_needed = (exit_code == 100)
        elif os_type == "suse":
            update_needed = ("no updates found" not in output)
        else:
            update_needed = ("upgradable" in output)

        artifact_filename = f"{ip}_patch_artifact.txt"
        with open(os.path.join(ARTIFACTS_FOLDER, artifact_filename), "w") as f:
            f.write(artifact_data)

        if apply_patches:
            return (ip, "✅ Updates Installed", "green", artifact_filename) if update_needed \
                else (ip, "✅ System Already Update", "green", artifact_filename)
        return (ip, "⚠️ Updates Available", "blue", artifact_filename) if update_needed \
            else (ip, "✅ System Updated", "green", artifact_filename)

    except paramiko.ssh_exception.NoValidConnectionsError:
        return (ip, "❌ Connection Failed", "red", None)
    except Exception as e:
        return (ip, f"❌ Error: {str(e)}", "red", None)
    finally:
        try:
            ssh.close()
        except:
            pass

def apply_patches_and_reboot(ip):
    try:
        patch_result = run_patch_update(ip, apply_patches=True)
        ip_patch, status_patch, color_patch, artifact_patch = patch_result

        if "❌" in status_patch:
            return (ip, status_patch, color_patch, "N/A", artifact_patch, ["---"])

        server = get_server(ip)
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=server.username, key_filename=SSH_PRIVATE_KEY_PATH, timeout=15)
        
        os_type = detect_os(ssh)
        reboot_required = False

        if os_type in ["ubuntu", "debian"]:
            stdin, stdout, stderr = ssh.exec_command("ls /var/run/reboot-required")
            reboot_required = (stdout.channel.recv_exit_status() == 0)
        elif os_type in ["centos", "rhel"]:
            stdin, stdout, stderr = ssh.exec_command("needs-restarting -r")
            reboot_required = (stdout.channel.recv_exit_status() == 1)
        elif os_type == "suse":
            stdin, stdout, stderr = ssh.exec_command("ls /var/run/reboot-needed")
            reboot_required = (stdout.channel.recv_exit_status() == 0)
        
        ssh.close()

        if reboot_required:
            reboot_result = run_command(ip, 'reboot')
            ip_reboot, status_reboot, color_reboot, uptime, artifact_reboot, failed_services = reboot_result
            
            combined_artifact = f"{ip}_patch_reboot_artifact.txt"
            try:
                with open(os.path.join(ARTIFACTS_FOLDER, artifact_patch), 'r') as f1, \
                     open(os.path.join(ARTIFACTS_FOLDER, artifact_reboot), 'r') as f2:
                    combined_content = f"PATCH LOGS:\n{f1.read()}\n\nREBOOT LOGS:\n{f2.read()}"
                
                with open(os.path.join(ARTIFACTS_FOLDER, combined_artifact), 'w') as f:
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
        
        return (ip, 
               f"{status_patch} (No reboot needed)", 
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
