from stegano import lsb

def hide_credentials(image_path, output_path, servers):
    """
    Hides server credentials in an image
    :param image_path: Path to original image
    :param output_path: Path to save image with hidden credentials
    :param servers: List of server credentials as tuples (ip, username, password)
    """
    # Convert credentials to CSV format
    credentials = "\n".join([f"{ip},{user},{pwd}" for ip, user, pwd in servers])
    
    # Hide credentials in image
    secret = lsb.hide(image_path, credentials)
    secret.save(output_path)
    print(f"Credentials hidden in {output_path}")

if __name__ == "__main__":
    # Example usage
    servers = [
        ("192.168.1.1", "admin", "password1"),
        ("192.168.1.2", "admin", "password2"),
        ("192.168.1.3", "admin", "password3")
    ]
    
    hide_credentials("original.png", "hidden_servers.png", servers)
