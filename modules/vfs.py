#!/usr/bin/env python3
"""
Virtual Filesystem Module for Honeypot
Contains fake filesystem structure and file contents.
"""

from typing import Optional

# Virtual Filesystem Structure
VIRTUAL_FS = {
    "/": ["bin", "etc", "home", "root", "var", "tmp", "usr", "opt", "lib", "boot"],
    "/root": ["db_creds.txt", "vpn_keys.pem", ".bash_history", "backup.tar.gz", ".ssh"],
    "/root/.ssh": ["id_rsa", "id_rsa.pub", "authorized_keys", "known_hosts"],
    "/home": ["admin", "deploy", "backup", "user"],
    "/home/admin": [".bashrc", ".profile", "notes.txt", "scripts"],
    "/home/deploy": [".bashrc", ".profile", "deploy.sh"],
    "/home/backup": [".bashrc", ".profile"],
    "/home/user": [".bashrc", ".profile"],
    "/etc": ["passwd", "shadow", "hosts", "ssh", "cron.d"],
    "/var": ["log", "www", "backups"],
    "/var/log": ["auth.log", "syslog", "messages", "secure"],
    "/tmp": ["sess_a1b2c3", ".X11-unix"],
}


def get_virtual_fs_entry(path: str, username: str = "") -> Optional[list]:
    """Get virtual FS entry, with dynamic user home directory support."""
    # Direct lookup
    if path in VIRTUAL_FS:
        return VIRTUAL_FS[path]
    
    # Dynamic user home directory
    if path.startswith("/home/") and path.count("/") == 2:
        # This is a user's home dir like /home/someuser
        return [".bashrc", ".profile", "Documents", "Downloads"]
    
    return None


# Fake File Contents - Honeypot Trap Files
FAKE_FILE_CONTENTS = {
    "/root/db_creds.txt": """# Production Database Credentials
# DO NOT SHARE - CONFIDENTIAL

DB_HOST=192.168.1.50
DB_PORT=3306
DB_NAME=production_main
DB_USER=db_admin
DB_PASS=Pr0d_S3cr3t_2026!

# Backup Database
BACKUP_HOST=192.168.1.51
BACKUP_USER=backup_svc
BACKUP_PASS=B4ckup_P@ss_Secure
""",
    "/root/vpn_keys.pem": """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn0ygzR7PQoXl5vFnqNMPSSzz0Y8RtDkLzL
k5r4fCm7jH6pO/YaVlqwKv1JhA3BT/2nF5eQZkd8qH7GL3nR5O6jC0P8mzC3Vq9k
[SIMULATED KEY DATA - HONEYPOT TRAP]
xK9mL2nO3pQ4rS5tU6vW7xY8zA9bC0dE1fG2hI3jK4lM5nO6pQ7rS8tU9vW0xY1z
-----END RSA PRIVATE KEY-----
""",
    "/root/.bash_history": """mysql -u root -p
ssh admin@192.168.1.100
scp backup.tar.gz deploy@backup-server:/backups/
cat /etc/shadow
sudo passwd root
vim /etc/ssh/sshd_config
systemctl restart sshd
""",
    "/etc/passwd": """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
admin:x:1000:1000:System Admin:/home/admin:/bin/bash
deploy:x:1001:1001:Deploy User:/home/deploy:/bin/bash
backup:x:1002:1002:Backup Service:/home/backup:/bin/bash
""",
    "/etc/shadow": """root:$6$rounds=5000$saltsalt$hashhashhashhashhashhashhash:19000:0:99999:7:::
admin:$6$rounds=5000$adminsalt$adminhashadminhashadminhash:19000:0:99999:7:::
deploy:$6$rounds=5000$deploysalt$deployhashdeployhashdeployhash:19000:0:99999:7:::
""",
    "/home/admin/notes.txt": """TODO:
- Update firewall rules for new office IP
- Rotate database credentials (monthly)
- Check backup integrity
- Review SSH access logs

Server IPs:
- Web Server: 192.168.1.10
- Database: 192.168.1.50
- Backup: 192.168.1.51
- VPN Gateway: 10.0.0.1
""",
    "/root/.ssh/id_rsa": """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAIEA3nD8L2tZ0FGvT1PqY8N3xQ5kR7mJ6sL4hK9vN2oP1wE6yX8sR0t
[SIMULATED PRIVATE KEY - HONEYPOT TRAP]
xK9mL2nO3pQ4rS5tU6vW7xY8zA9bC0dE1fG2hI3jK4lM5nO6pQ7rS8tU9vW0xY1zA2bC3
dE4fG5hI6jK7lM8nO9pQ0rS1tU2vW3xY4zA5bC6dE7fG8hI9jK0lM1nO2pQ3rS4tU5vW6x
-----END OPENSSH PRIVATE KEY-----
""",
    "/root/.ssh/id_rsa.pub": """ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDecPwva1nQUa9PU+pjw3fFDmRHuYnqwviEr283ag/XATrJfyxHS0xLVE1WXVhdZl5oX2pfal9qYGxhbGJsY21jbWNuZG5kb29wb29wcXFxcnJyc3N0dHV1dXZ2dnd3d3h4eHl5eXp6ejAxMjM0NTY3ODkK root@prod-db-server01
""",
    "/root/.ssh/authorized_keys": """ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC7hR7pZ8vK1xL3nM4oP5qR6sT7uV8wX9yZ0aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB4cD5eF6gH7iJ8kL9mN0oP1qR2sT3uV4wX5yZ6aB7cD8eF9g admin@workstation
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDaBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNo deploy@ci-server
""",
    "/root/.ssh/known_hosts": """192.168.1.10 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC7hR7pZ8vK1xL3nM4oP5qR6sT7uV8wX9yZ0aB
192.168.1.50 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDecPwva1nQUa9PU+pjw3fFDmRHuYnqwviE
192.168.1.51 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDaBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFg
backup-server ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC8iS8qZ9wL2yM5pQ6rT8uW9xZ1bC2dE3fG
""",
}
