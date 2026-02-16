#!/usr/bin/env python3

import socket
import threading
import datetime
import json
import xml.etree.ElementTree as ET
import os
import sys
import time
import requests
import tkinter as tk
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from queue import Queue
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.widgets.scrolled import ScrolledText
from ttkbootstrap.widgets.tableview import Tableview

# Import from local modules
from modules.vfs import VIRTUAL_FS, FAKE_FILE_CONTENTS, get_virtual_fs_entry
from modules.commands import FakeShell, resolve_path, execute_shell_command
from modules.export import export_to_xml, export_to_json

# Try to import paramiko for proper SSH
try:
    import paramiko
    from paramiko import RSAKey
    import logging
    
    class _NullHandler(logging.Handler):
        def emit(self, record):
            pass
    
    for logger_name in ["paramiko", "paramiko.transport", "paramiko.sftp"]:
        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.CRITICAL + 100)
        logger.propagate = False
        logger.handlers = [_NullHandler()]
    
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False
    print("[!] paramiko not installed. SSH will use fallback mode (netcat/telnet only)")
    print("    Install with: pip install paramiko")

# ============================================================================
# CONFIGURATION
# ============================================================================

CONFIG = {
    "SSH_PORT": 2222,
    "TELNET_PORT": 2233,
    "FTP_PORT": 2121,
    "SMB_PORT": 4445,
    "FTP_PASV_PORT_START": 5001,
    "FTP_PASV_PORT_END": 5100,
    "SSH_HOST_KEY_FILE": "ssh_host_key",
    "DISCORD_WEBHOOK": "https://discord.com/api/webhooks/1470275818973434000/cEPaosR2ZCzSTD9haNu8dUhdakPEF2bD5bfr0235_2134pGMqOLdEGQm8iOp-5qF_yJ-",
    "LOG_FILE": "honeypot_events.log",
    "HOSTNAME": "prod-db-server01",
}

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class CapturedCredential:
    timestamp: str
    source_ip: str
    source_port: int
    service: str
    username: str
    password: str
    credential_type: str  # 'login' or 'sudo'

@dataclass
class ActiveSession:
    session_id: str
    source_ip: str
    source_port: int
    service: str
    start_time: str
    username: str
    is_elevated: bool = False

@dataclass
class LogEvent:
    timestamp: str
    level: str  # INFO, WARNING, CRITICAL
    service: str
    source_ip: str
    message: str

# ============================================================================
# GLOBAL STATE
# ============================================================================

class HoneypotState:
    def __init__(self):
        self.credentials: List[CapturedCredential] = []
        self.sessions: Dict[str, ActiveSession] = {}
        self.events: List[LogEvent] = []
        self.log_queue: Queue = Queue()
        self.running = True
        self.listeners: List[socket.socket] = []
        self.lock = threading.Lock()

state = HoneypotState()

# ============================================================================
# DISCORD INTEGRATION
# ============================================================================

def send_discord_alert(title: str, description: str, color: int, fields: List[Dict] = None):
    """Send rich embed alert to Discord webhook."""
    try:
        embed = {
            "title": f"🍯 Honey POT Alert: {title}",
            "description": description,
            "color": color,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "footer": {"text": f"Honeypot: {CONFIG['HOSTNAME']}"},
        }
        if fields:
            embed["fields"] = fields
        
        payload = {"embeds": [embed]}
        threading.Thread(
            target=lambda: requests.post(CONFIG["DISCORD_WEBHOOK"], json=payload, timeout=5),
            daemon=True
        ).start()
    except Exception as e:
        log_event("WARNING", "Discord", "N/A", f"Failed to send Discord alert: {e}")

def discord_connection_alert(service: str, ip: str, port: int):
    send_discord_alert(
        "New Connection",
        f"Attacker connected to {service} service",
        0x3498db,  # Blue
        [
            {"name": "Service", "value": service, "inline": True},
            {"name": "Source IP", "value": ip, "inline": True},
            {"name": "Source Port", "value": str(port), "inline": True},
        ]
    )

def discord_login_alert(service: str, ip: str, username: str, password: str):
    send_discord_alert(
        "Login Attempt",
        f"Credentials captured on {service}",
        0xf39c12,  # Orange
        [
            {"name": "Service", "value": service, "inline": True},
            {"name": "Source IP", "value": ip, "inline": True},
            {"name": "Username", "value": f"`{username}`", "inline": True},
            {"name": "Password", "value": f"`{password}`", "inline": True},
        ]
    )

def discord_sudo_alert(ip: str, username: str, password: str, command: str):
    send_discord_alert(
        "🚨 CRITICAL: Sudo Password Captured",
        "Attacker attempted privilege escalation!",
        0xe74c3c,  # Red
        [
            {"name": "Source IP", "value": ip, "inline": True},
            {"name": "Username", "value": f"`{username}`", "inline": True},
            {"name": "Sudo Password", "value": f"`{password}`", "inline": False},
            {"name": "Command", "value": f"`{command}`", "inline": False},
        ]
    )

# ============================================================================
# LOGGING
# ============================================================================

def log_event(level: str, service: str, source_ip: str, message: str):
    """Log an event to the queue for UI display."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    event = LogEvent(timestamp, level, service, source_ip, message)
    with state.lock:
        state.events.append(event)
    state.log_queue.put(event)
    
    # Also write to file
    try:
        with open(CONFIG["LOG_FILE"], "a") as f:
            f.write(f"[{timestamp}] [{level}] [{service}] [{source_ip}] {message}\n")
    except:
        pass

def capture_credential(source_ip: str, source_port: int, service: str, 
                       username: str, password: str, cred_type: str = "login"):
    """Store captured credentials."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cred = CapturedCredential(
        timestamp, source_ip, source_port, service, username, password, cred_type
    )
    with state.lock:
        state.credentials.append(cred)
    
    if cred_type == "sudo":
        log_event("CRITICAL", service, source_ip, 
                  f"SUDO PASSWORD CAPTURED - User: {username}, Pass: {password}")
    else:
        log_event("WARNING", service, source_ip, 
                  f"Login attempt - User: {username}, Pass: {password}")

# ============================================================================
# SERVICE LISTENERS
# ============================================================================

# SSH Host Key Management
def get_ssh_host_key():
    """Get or generate SSH host key."""
    if not HAS_PARAMIKO:
        return None
    
    key_file = CONFIG["SSH_HOST_KEY_FILE"]
    if os.path.exists(key_file):
        try:
            return RSAKey.from_private_key_file(key_file)
        except:
            pass
    
    # Generate new key
    key = RSAKey.generate(2048)
    key.write_private_key_file(key_file)
    return key

# Paramiko SSH Server Interface
if HAS_PARAMIKO:
    class HoneypotSSHServer(paramiko.ServerInterface):
        """SSH server interface for capturing credentials."""
        
        def __init__(self, addr):
            self.addr = addr
            self.username = ""
            self.password = ""
            self.authenticated = False
            self.event = threading.Event()
        
        def check_channel_request(self, kind, chanid):
            if kind == 'session':
                return paramiko.OPEN_SUCCEEDED
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        
        def check_auth_password(self, username, password):
            """Capture password authentication attempts."""
            self.username = username
            self.password = password
            
            # Log and capture the credentials
            log_event("WARNING", "SSH", self.addr[0], 
                     f"Password auth attempt - User: {username}, Pass: {password}")
            capture_credential(self.addr[0], self.addr[1], "SSH", username, password, "login")
            discord_login_alert("SSH", self.addr[0], username, password)
            
            # Always allow authentication to keep attacker engaged
            self.authenticated = True
            return paramiko.AUTH_SUCCESSFUL
        
        def check_auth_publickey(self, username, key):
            """Log public key auth attempts (always fail to force password)."""
            log_event("INFO", "SSH", self.addr[0], 
                     f"Public key auth attempt - User: {username}, Key: {key.get_fingerprint().hex()}")
            return paramiko.AUTH_FAILED
        
        def get_allowed_auths(self, username):
            return 'password'
        
        def check_channel_shell_request(self, channel):
            self.event.set()
            return True
        
        def check_channel_pty_request(self, channel, term, width, height, 
                                       pixelwidth, pixelheight, modes):
            return True
        
        def check_channel_exec_request(self, channel, command):
            log_event("WARNING", "SSH", self.addr[0], f"Exec request: {command.decode()}")
            self.event.set()
            return True

def ssh_handler(conn: socket.socket, addr: tuple):
    """Handle SSH connections with proper protocol support."""
    session_id = f"{addr[0]}:{addr[1]}:{time.time()}"
    
    try:
        log_event("INFO", "SSH", addr[0], f"New connection from port {addr[1]}")
        discord_connection_alert("SSH", addr[0], addr[1])
        
        if not HAS_PARAMIKO:
            # Fallback mode for netcat/telnet connections
            conn.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n")
            try:
                client_banner = conn.recv(256)
                log_event("INFO", "SSH", addr[0], 
                         f"Client banner: {client_banner.decode('utf-8', errors='ignore').strip()}")
            except:
                pass
            
            shell = FakeShell(conn, addr, "SSH", CONFIG, state, log_event,
                              capture_credential, discord_login_alert,
                              discord_sudo_alert, ActiveSession)
            if shell.do_login():
                shell.run_shell()
            return
        
        # Proper SSH with paramiko
        host_key = get_ssh_host_key()
        if not host_key:
            log_event("WARNING", "SSH", addr[0], "No SSH host key available")
            conn.close()
            return
        
        transport = paramiko.Transport(conn)
        transport.add_server_key(host_key)
        transport.set_gss_host(socket.getfqdn(""))
        
        server = HoneypotSSHServer(addr)
        
        try:
            transport.start_server(server=server)
        except paramiko.SSHException as e:
            log_event("INFO", "SSH", addr[0], f"SSH negotiation failed: {e}")
            return
        
        # Wait for authentication
        channel = transport.accept(30)
        if channel is None:
            log_event("INFO", "SSH", addr[0], "No channel opened")
            return
        
        # Register session after successful auth
        session = ActiveSession(
            session_id, addr[0], addr[1], "SSH",
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            server.username
        )
        with state.lock:
            state.sessions[session_id] = session
        
        log_event("WARNING", "SSH", addr[0], f"User '{server.username}' authenticated (FAKE)")
        
        # Wait for shell request
        server.event.wait(10)
        
        # Run fake shell over SSH channel
        ssh_shell_loop(channel, addr, server.username, session_id)
        
    except Exception as e:
        log_event("INFO", "SSH", addr[0], f"Connection error: {e}")
    finally:
        with state.lock:
            if session_id in state.sessions:
                del state.sessions[session_id]
        log_event("INFO", "SSH", addr[0], "Session closed")
        try:
            conn.close()
        except:
            pass

def ssh_shell_loop(channel, addr: tuple, username: str, session_id: str):
    """Run fake shell over SSH channel."""
    is_root = False
    cwd = f"/home/{username}" if username != "root" else "/root"
    created_files = {}  # Track files "created" by attacker
    
    def get_prompt():
        user = "root" if is_root else username
        symbol = "#" if is_root else "$"
        return f"{user}@{CONFIG['HOSTNAME']}:{cwd}{symbol} "
    
    def send(data: str):
        try:
            channel.send(data)
        except:
            pass
    
    def recv_line() -> str:
        buffer = ""
        while True:
            try:
                char = channel.recv(1).decode('utf-8', errors='ignore')
                if not char:
                    return ""
                if char in ('\r', '\n'):
                    send("\r\n")
                    return buffer.strip()
                if char == '\x7f' or char == '\x08':
                    if buffer:
                        buffer = buffer[:-1]
                        send("\b \b")
                elif char == '\x03':
                    send("^C\r\n")
                    return ""
                elif char == '\x04':  # Ctrl+D
                    return "exit"
                elif ord(char) >= 32:
                    buffer += char
                    send(char)
            except:
                return ""
    
    def recv_password() -> str:
        buffer = ""
        while True:
            try:
                char = channel.recv(1).decode('utf-8', errors='ignore')
                if not char:
                    return ""
                if char in ('\r', '\n'):
                    send("\r\n")
                    return buffer.strip()
                if char == '\x7f' or char == '\x08':
                    if buffer:
                        buffer = buffer[:-1]
                elif ord(char) >= 32:
                    buffer += char
            except:
                return ""
    
    # Send banner
    banner = f"Linux {CONFIG['HOSTNAME']} 5.15.0-91-generic #101-Ubuntu SMP x86_64\r\n\r\n"
    banner += f"Last login: {datetime.datetime.now().strftime('%a %b %d %H:%M:%S %Y')} from 192.168.1.100\r\n"
    send(banner)
    
    try:
        while state.running and channel.get_transport() and channel.get_transport().is_active():
            send(get_prompt())
            cmd = recv_line()
            if not cmd:
                continue
            
            log_event("INFO", "SSH", addr[0], f"Command: {cmd}")
            
            parts = cmd.split()
            if not parts:
                continue
            
            command = parts[0]
            args = parts[1:] if len(parts) > 1 else []
            
            # Handle sudo
            if command == "sudo":
                if args:
                    send(f"[sudo] password for {username}: ")
                    sudo_pass = recv_password()
                    if sudo_pass:
                        capture_credential(addr[0], addr[1], "SSH", username, sudo_pass, "sudo")
                        discord_sudo_alert(addr[0], username, sudo_pass, cmd)
                        is_root = True
                        with state.lock:
                            if session_id in state.sessions:
                                state.sessions[session_id].is_elevated = True
                        log_event("CRITICAL", "SSH", addr[0], 
                                 f"SUDO PASSWORD CAPTURED - User: {username}, Pass: {sudo_pass}")
                        # Execute the actual command
                        actual_cmd = " ".join(args)
                        result = execute_shell_command(actual_cmd, cwd, is_root, username, addr, CONFIG, log_event, created_files)
                        if result:
                            send(result)
                continue
            
            # Handle su
            if command == "su":
                target = args[0] if args else "root"
                send("Password: ")
                su_pass = recv_password()
                if su_pass:
                    capture_credential(addr[0], addr[1], "SSH", target, su_pass, "sudo")
                    discord_sudo_alert(addr[0], target, su_pass, "su " + target)
                    if target == "root":
                        is_root = True
                        with state.lock:
                            if session_id in state.sessions:
                                state.sessions[session_id].is_elevated = True
                        log_event("CRITICAL", "SSH", addr[0], 
                                 f"SU PASSWORD CAPTURED - Target: {target}, Pass: {su_pass}")
                continue
            
            if command == "exit" or command == "logout":
                break
            
            # Handle output redirection (>, >>)
            redirect_file = None
            append_mode = False
            actual_cmd = cmd
            if '>>' in cmd:
                parts_redir = cmd.split('>>', 1)
                actual_cmd = parts_redir[0].strip()
                redirect_file = parts_redir[1].strip()
                append_mode = True
            elif '>' in cmd:
                parts_redir = cmd.split('>', 1)
                actual_cmd = parts_redir[0].strip()
                redirect_file = parts_redir[1].strip()
            
            if redirect_file:
                # Resolve the redirect file path
                file_path = resolve_path(redirect_file, cwd, is_root, username)
                # Get content to write (typically from echo)
                redir_parts = actual_cmd.split()
                if redir_parts and redir_parts[0] == 'echo':
                    content = ' '.join(redir_parts[1:])
                    # Remove surrounding quotes
                    if (content.startswith("'") and content.endswith("'")) or \
                       (content.startswith('"') and content.endswith('"')):
                        content = content[1:-1]
                else:
                    content = ""
                
                # Store in created_files
                if append_mode:
                    # Append mode - need to get existing content first
                    if file_path in created_files:
                        created_files[file_path] += "\n" + content
                    elif file_path in FAKE_FILE_CONTENTS:
                        # Appending to an existing system file - copy original first
                        created_files[file_path] = FAKE_FILE_CONTENTS[file_path] + "\n" + content
                    else:
                        created_files[file_path] = content
                else:
                    # Overwrite mode
                    created_files[file_path] = content
                
                log_event("WARNING", "SSH", addr[0], 
                         f"Attacker modified file: {file_path} (append={append_mode})")
                continue  # No output for redirected commands
            
            # Execute other commands
            result = execute_shell_command(cmd, cwd, is_root, username, addr, CONFIG, log_event, created_files)
            
            # Handle cd specially to update cwd
            if command == "cd":
                path = args[0] if args else ("~" if not is_root else "/root")
                new_cwd = resolve_path(path, cwd, is_root, username)
                # Check if directory exists using dynamic lookup
                if get_virtual_fs_entry(new_cwd, username) is not None:
                    cwd = new_cwd
                else:
                    # Allow any /home/username path for dynamic home directories
                    if new_cwd.startswith("/home/") and new_cwd.count("/") == 2:
                        cwd = new_cwd
                    else:
                        send(f"-bash: cd: {path}: No such file or directory\r\n")
                        continue
            
            if result:
                send(result)
    
    except Exception as e:
        log_event("INFO", "SSH", addr[0], f"Shell error: {e}")
    finally:
        try:
            channel.close()
        except:
            pass

def telnet_handler(conn: socket.socket, addr: tuple):
    """Handle Telnet connections."""
    try:
        log_event("INFO", "Telnet", addr[0], f"New connection from port {addr[1]}")
        discord_connection_alert("Telnet", addr[0], addr[1])
        
        # Send telnet negotiation (simplified)
        conn.sendall(b"\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18")  # Will echo, Will SGA, Do Terminal Type
        time.sleep(0.1)
        
        # Drain any negotiation responses
        conn.settimeout(0.5)
        try:
            conn.recv(256)
        except:
            pass
        conn.settimeout(None)
        
        # Send banner
        banner = f"\r\n{CONFIG['HOSTNAME']} - Telnet Server\r\n"
        banner += "Unauthorized access is prohibited.\r\n\r\n"
        conn.sendall(banner.encode())
        
        # Start fake shell
        shell = FakeShell(conn, addr, "Telnet", CONFIG, state, log_event,
                          capture_credential, discord_login_alert,
                          discord_sudo_alert, ActiveSession)
        if shell.do_login():
            shell.run_shell()
    except Exception as e:
        log_event("INFO", "Telnet", addr[0], f"Connection error: {e}")
    finally:
        try:
            conn.close()
        except:
            pass

# FTP Passive Port Manager
class FTPDataPortManager:
    """Manages passive mode data ports for FTP."""
    
    def __init__(self):
        self.lock = threading.Lock()
        self.used_ports = set()
    
    def get_port(self) -> Optional[int]:
        """Get an available passive mode port."""
        with self.lock:
            for port in range(CONFIG["FTP_PASV_PORT_START"], CONFIG["FTP_PASV_PORT_END"]):
                if port not in self.used_ports:
                    self.used_ports.add(port)
                    return port
        return None
    
    def release_port(self, port: int):
        """Release a passive mode port."""
        with self.lock:
            self.used_ports.discard(port)

ftp_port_manager = FTPDataPortManager()

def ftp_create_data_listener(port: int, timeout: float = 30) -> Optional[socket.socket]:
    """Create a data connection listener for passive mode."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', port))
        sock.listen(1)
        sock.settimeout(timeout)
        return sock
    except Exception as e:
        return None

def ftp_send_directory_listing(data_conn: socket.socket, cwd: str):
    """Send directory listing over data connection."""
    try:
        # Generate fake directory listing
        listing = ""
        if cwd in VIRTUAL_FS:
            for item in VIRTUAL_FS[cwd]:
                if "." in item and not item.startswith("."):
                    # File
                    listing += f"-rw-r--r--    1 ftp      ftp          1024 Jan 15 10:30 {item}\r\n"
                else:
                    # Directory
                    listing += f"drwxr-xr-x    2 ftp      ftp          4096 Jan 15 10:30 {item}\r\n"
        else:
            listing = "drwxr-xr-x    2 ftp      ftp          4096 Jan 15 10:30 .\r\n"
            listing += "drwxr-xr-x    2 ftp      ftp          4096 Jan 15 10:30 ..\r\n"
        
        data_conn.sendall(listing.encode())
    except:
        pass
    finally:
        try:
            data_conn.close()
        except:
            pass

def ftp_handler(conn: socket.socket, addr: tuple):
    """Handle FTP connections (medium interaction)."""
    session_id = f"{addr[0]}:{addr[1]}:{time.time()}"
    username = ""
    authenticated = False
    data_listener = None
    data_port = None
    
    try:
        log_event("INFO", "FTP", addr[0], f"New connection from port {addr[1]}")
        discord_connection_alert("FTP", addr[0], addr[1])
        
        # Register session immediately
        session = ActiveSession(
            session_id, addr[0], addr[1], "FTP",
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "anonymous"
        )
        with state.lock:
            state.sessions[session_id] = session
        
        # Get server's own IP for PASV response
        try:
            server_ip = conn.getsockname()[0]
            if server_ip == "0.0.0.0" or server_ip.startswith("127."):
                # Try to get a better IP
                server_ip = socket.gethostbyname(socket.gethostname())
        except:
            server_ip = "127.0.0.1"
        
        # Send FTP banner
        conn.sendall(f"220 {CONFIG['HOSTNAME']} FTP Server (vsFTPd 3.0.5) ready.\r\n".encode())
        
        cwd = "/home/ftp"
        while state.running:
            try:
                data = conn.recv(1024).decode('utf-8', errors='ignore').strip()
                if not data:
                    break
                
                log_event("INFO", "FTP", addr[0], f"Command: {data}")
                parts = data.split(" ", 1)
                cmd = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""
                
                if cmd == "USER":
                    username = arg
                    with state.lock:
                        if session_id in state.sessions:
                            state.sessions[session_id].username = username
                    conn.sendall(f"331 Password required for {username}.\r\n".encode())
                
                elif cmd == "PASS":
                    password = arg
                    capture_credential(addr[0], addr[1], "FTP", username, password)
                    discord_login_alert("FTP", addr[0], username, password)
                    authenticated = True
                    log_event("WARNING", "FTP", addr[0], f"User '{username}' logged in (FAKE)")
                    conn.sendall(f"230 User {username} logged in.\r\n".encode())
                
                elif cmd == "SYST":
                    conn.sendall(b"215 UNIX Type: L8\r\n")
                
                elif cmd == "PWD" or cmd == "XPWD":
                    conn.sendall(f"257 \"{cwd}\" is current directory.\r\n".encode())
                
                elif cmd == "PASV":
                    # Close any existing data listener
                    if data_listener:
                        try:
                            data_listener.close()
                        except:
                            pass
                        if data_port:
                            ftp_port_manager.release_port(data_port)
                    
                    # Get a new passive port
                    data_port = ftp_port_manager.get_port()
                    if not data_port:
                        conn.sendall(b"425 Can't open data connection.\r\n")
                        continue
                    
                    # Create data listener
                    data_listener = ftp_create_data_listener(data_port)
                    if not data_listener:
                        ftp_port_manager.release_port(data_port)
                        data_port = None
                        conn.sendall(b"425 Can't open data connection.\r\n")
                        continue
                    
                    # Format IP for PASV response (comma-separated)
                    ip_parts = server_ip.replace(".", ",")
                    p1 = data_port // 256
                    p2 = data_port % 256
                    conn.sendall(f"227 Entering Passive Mode ({ip_parts},{p1},{p2}).\r\n".encode())
                
                elif cmd == "EPSV":
                    # Close any existing data listener
                    if data_listener:
                        try:
                            data_listener.close()
                        except:
                            pass
                        if data_port:
                            ftp_port_manager.release_port(data_port)
                    
                    # Get a new passive port
                    data_port = ftp_port_manager.get_port()
                    if not data_port:
                        conn.sendall(b"425 Can't open data connection.\r\n")
                        continue
                    
                    # Create data listener
                    data_listener = ftp_create_data_listener(data_port)
                    if not data_listener:
                        ftp_port_manager.release_port(data_port)
                        data_port = None
                        conn.sendall(b"425 Can't open data connection.\r\n")
                        continue
                    
                    conn.sendall(f"229 Entering Extended Passive Mode (|||{data_port}|).\r\n".encode())
                
                elif cmd == "LIST" or cmd == "NLST":
                    if not data_listener:
                        conn.sendall(b"425 Use PASV first.\r\n")
                        continue
                    
                    conn.sendall(b"150 Opening ASCII mode data connection for file list.\r\n")
                    
                    try:
                        # Accept data connection
                        data_conn, data_addr = data_listener.accept()
                        log_event("INFO", "FTP", addr[0], f"Data connection from {data_addr[0]}:{data_addr[1]}")
                        
                        # Send listing
                        ftp_send_directory_listing(data_conn, cwd)
                        
                        conn.sendall(b"226 Transfer complete.\r\n")
                    except socket.timeout:
                        conn.sendall(b"425 Connection timeout.\r\n")
                    except Exception as e:
                        conn.sendall(b"425 Data connection failed.\r\n")
                    finally:
                        # Close and cleanup data listener
                        try:
                            data_listener.close()
                        except:
                            pass
                        if data_port:
                            ftp_port_manager.release_port(data_port)
                        data_listener = None
                        data_port = None
                
                elif cmd == "QUIT":
                    conn.sendall(b"221 Goodbye.\r\n")
                    break
                
                elif cmd == "TYPE":
                    conn.sendall(b"200 Type set to I.\r\n")
                
                elif cmd == "CWD" or cmd == "XCWD":
                    cwd = arg if arg.startswith("/") else f"{cwd}/{arg}"
                    conn.sendall(f"250 CWD command successful. \"{cwd}\" is current directory.\r\n".encode())
                
                elif cmd == "CDUP" or cmd == "XCUP":
                    cwd = "/".join(cwd.rsplit("/", 1)[:-1]) or "/"
                    conn.sendall(b"250 CDUP command successful.\r\n")
                
                elif cmd == "MKD" or cmd == "XMKD":
                    conn.sendall(f"257 \"{arg}\" directory created.\r\n".encode())
                
                elif cmd == "RMD" or cmd == "XRMD":
                    conn.sendall(b"250 Directory removed.\r\n")
                
                elif cmd == "DELE":
                    conn.sendall(b"250 File deleted.\r\n")
                
                elif cmd == "RETR":
                    log_event("WARNING", "FTP", addr[0], f"File download attempt: {arg}")
                    if not data_listener:
                        conn.sendall(b"425 Use PASV first.\r\n")
                        continue
                    
                    # Check if file exists in fake filesystem
                    filepath = resolve_path(arg, cwd, False, "ftp")
                    if filepath in FAKE_FILE_CONTENTS:
                        conn.sendall(b"150 Opening BINARY mode data connection.\r\n")
                        try:
                            data_conn, data_addr = data_listener.accept()
                            data_conn.sendall(FAKE_FILE_CONTENTS[filepath].encode())
                            data_conn.close()
                            conn.sendall(b"226 Transfer complete.\r\n")
                            log_event("CRITICAL", "FTP", addr[0], f"Sensitive file downloaded: {arg}")
                        except:
                            conn.sendall(b"425 Data connection failed.\r\n")
                    else:
                        conn.sendall(b"550 File not found.\r\n")
                    
                    # Cleanup
                    try:
                        data_listener.close()
                    except:
                        pass
                    if data_port:
                        ftp_port_manager.release_port(data_port)
                    data_listener = None
                    data_port = None
                
                elif cmd == "STOR":
                    log_event("WARNING", "FTP", addr[0], f"File upload attempt: {arg}")
                    if not data_listener:
                        conn.sendall(b"425 Use PASV first.\r\n")
                        continue
                    
                    conn.sendall(b"150 Opening BINARY mode data connection.\r\n")
                    try:
                        data_conn, data_addr = data_listener.accept()
                        # Receive and discard the data (but log its size)
                        received_data = b""
                        while True:
                            chunk = data_conn.recv(4096)
                            if not chunk:
                                break
                            received_data += chunk
                        data_conn.close()
                        log_event("CRITICAL", "FTP", addr[0], 
                                 f"File upload received: {arg} ({len(received_data)} bytes)")
                        conn.sendall(b"226 Transfer complete.\r\n")
                    except:
                        conn.sendall(b"425 Data connection failed.\r\n")
                    
                    # Cleanup
                    try:
                        data_listener.close()
                    except:
                        pass
                    if data_port:
                        ftp_port_manager.release_port(data_port)
                    data_listener = None
                    data_port = None
                
                elif cmd == "FEAT":
                    conn.sendall(b"211-Features:\r\n PASV\r\n EPSV\r\n UTF8\r\n211 End\r\n")
                
                elif cmd == "OPTS":
                    conn.sendall(b"200 OK.\r\n")
                
                elif cmd == "SIZE":
                    filepath = resolve_path(arg, cwd, False, "ftp")
                    if filepath in FAKE_FILE_CONTENTS:
                        conn.sendall(f"213 {len(FAKE_FILE_CONTENTS[filepath])}\r\n".encode())
                    else:
                        conn.sendall(b"550 File not found.\r\n")
                
                elif cmd == "MDTM":
                    conn.sendall(b"550 File not found.\r\n")
                
                elif cmd == "NOOP":
                    conn.sendall(b"200 NOOP ok.\r\n")
                
                elif cmd == "HELP":
                    conn.sendall(b"214 Help OK.\r\n")
                
                elif cmd == "STAT":
                    conn.sendall(f"211 FTP server status: {CONFIG['HOSTNAME']}\r\n".encode())
                
                elif cmd == "PORT":
                    # Active mode - we just log it but don't support it
                    log_event("INFO", "FTP", addr[0], f"PORT command (active mode): {arg}")
                    conn.sendall(b"200 PORT command successful.\r\n")
                
                else:
                    conn.sendall(f"502 Command '{cmd}' not implemented.\r\n".encode())
            
            except socket.timeout:
                continue
            except Exception as e:
                break
    
    except Exception as e:
        log_event("INFO", "FTP", addr[0], f"Connection error: {e}")
    finally:
        # Cleanup data listener if still open
        if data_listener:
            try:
                data_listener.close()
            except:
                pass
            if data_port:
                ftp_port_manager.release_port(data_port)
        
        # Remove session
        with state.lock:
            if session_id in state.sessions:
                del state.sessions[session_id]
        log_event("INFO", "FTP", addr[0], "Session closed")
        try:
            conn.close()
        except:
            pass

def smb_handler(conn: socket.socket, addr: tuple):
    """Handle SMB connections with full protocol support."""
    session_id = f"{addr[0]}:{addr[1]}:{time.time()}"
    
    try:
        log_event("CRITICAL", "SMB", addr[0], f"SMB connection from port {addr[1]}")
        discord_connection_alert("SMB/Samba", addr[0], addr[1])
        
        # Register session
        session = ActiveSession(
            session_id, addr[0], addr[1], "SMB",
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "unknown"
        )
        with state.lock:
            state.sessions[session_id] = session
        
        conn.settimeout(30)
        
        # SMB conversation loop
        while True:
            # Read NetBIOS header (4 bytes)
            try:
                nb_header = b''
                while len(nb_header) < 4:
                    chunk = conn.recv(4 - len(nb_header))
                    if not chunk:
                        log_event("INFO", "SMB", addr[0], "Client closed connection (recv header empty)")
                        return
                    nb_header += chunk
            except socket.timeout:
                log_event("INFO", "SMB", addr[0], "Socket timeout reading header")
                return
            except ConnectionError as e:
                log_event("INFO", "SMB", addr[0], f"Connection error reading header: {e}")
                return
            
            # Parse length from NetBIOS header
            msg_len = (nb_header[1] << 16) | (nb_header[2] << 8) | nb_header[3]
            
            if msg_len == 0 or msg_len > 0xFFFF:
                return
            
            # Read SMB message
            smb_data = b''
            while len(smb_data) < msg_len:
                try:
                    chunk = conn.recv(min(msg_len - len(smb_data), 8192))
                    if not chunk:
                        return
                    smb_data += chunk
                except (socket.timeout, ConnectionError):
                    return
            
            if len(smb_data) < 4:
                return
            
            # Check SMB magic
            if smb_data[0:4] == b'\xffSMB':
                # SMBv1 request
                try:
                    response = handle_smb1_message(smb_data, addr, session)
                    if response:
                        conn.sendall(response)
                except Exception as e:
                    log_event("WARNING", "SMB", addr[0], f"SMB1 handler error: {e}")
                    
            elif smb_data[0:4] == b'\xfeSMB':
                # SMBv2/3 request
                try:
                    response = handle_smb2_message(smb_data, addr, session)
                    if response:
                        conn.sendall(response)
                except Exception as e:
                    log_event("WARNING", "SMB", addr[0], f"SMB2 handler error: {e}")
                    import traceback
                    traceback.print_exc()
            else:
                log_event("WARNING", "SMB", addr[0], f"Unknown protocol: {smb_data[0:4].hex()}")
                return
                
    except Exception as e:
        log_event("INFO", "SMB", addr[0], f"SMB error: {e}")
    finally:
        with state.lock:
            if session_id in state.sessions:
                del state.sessions[session_id]
        log_event("INFO", "SMB", addr[0], "Session closed")
        try:
            conn.close()
        except:
            pass


def handle_smb1_message(data: bytes, addr: tuple, session) -> bytes:
    """Handle SMBv1 messages and return response."""
    if len(data) < 32:
        return None
    
    command = data[4]
    log_event("INFO", "SMB", addr[0], f"SMBv1 command: 0x{command:02x}")
    
    if command == 0x72:  # Negotiate
        log_event("WARNING", "SMB", addr[0], "SMBv1 NEGOTIATE - checking for SMB2 dialect")
        
        # Check if client supports SMB2 (look for "SMB 2" in dialects)
        if b'SMB 2' in data or b'SMB2' in data:
            log_event("INFO", "SMB", addr[0], "Client supports SMB2, sending SMB2 negotiate response")
            return smb2_negotiate_response()
        else:
            log_event("INFO", "SMB", addr[0], "SMBv1 only client, sending SMBv1 response")
            return smb1_negotiate_response(data)
            
    elif command == 0x73:  # Session Setup
        log_event("CRITICAL", "SMB", addr[0], "SMBv1 SESSION_SETUP - Auth attempt!")
        extract_ntlm_credentials(data, addr, session)
        return smb1_session_response(data)
        
    elif command == 0x75:  # Tree Connect
        log_event("INFO", "SMB", addr[0], "SMBv1 TREE_CONNECT - Share access")
        return smb1_tree_connect_response(data)
    
    elif command == 0x25:  # Trans (RAP for workgroup listing)
        log_event("INFO", "SMB", addr[0], "SMBv1 TRANS - RAP request (workgroup listing)")
        return smb1_trans_response(data)
    
    elif command == 0x71:  # Tree Disconnect
        log_event("INFO", "SMB", addr[0], "SMBv1 TREE_DISCONNECT")
        return smb1_success_response(data, command)
        
    else:
        return smb1_error_response(data, command, 0xC0000022)


def handle_smb2_message(data: bytes, addr: tuple, session) -> bytes:
    """Handle SMBv2/3 messages and return response, including compound requests."""
    if len(data) < 64:
        return None
    
    # Check for compound request (NextCommand != 0)
    next_command_offset = data[20] | (data[21] << 8) | (data[22] << 16) | (data[23] << 24)
    
    if next_command_offset > 0:
        # Handle compound request - process all commands and combine responses
        return handle_smb2_compound_request(data, addr, session)
    
    # Single command - process normally
    return handle_smb2_single_command(data, addr, session)


def handle_smb2_compound_request(data: bytes, addr: tuple, session) -> bytes:
    """Handle compound SMB2 request with multiple chained commands."""
    log_event("INFO", "SMB", addr[0], "Processing compound SMB2 request")
    responses = []
    offset = 0
    
    while offset < len(data):
        if offset + 64 > len(data):
            break
        
        # Parse NextCommand offset
        next_cmd = data[offset + 20] | (data[offset + 21] << 8) | (data[offset + 22] << 16) | (data[offset + 23] << 24)
        
        # Determine command length
        if next_cmd > 0:
            cmd_len = next_cmd
        else:
            cmd_len = len(data) - offset
        
        # Extract this command's data
        cmd_data = data[offset:offset + cmd_len]
        
        # Process single command - response will include NetBIOS header, strip it
        resp = handle_smb2_single_command(cmd_data, addr, session)
        
        if resp and len(resp) > 4:
            # Strip NetBIOS header (first 4 bytes)
            resp_no_nb = resp[4:]
            responses.append(resp_no_nb)
        
        if next_cmd == 0:
            break
        offset += next_cmd
    
    if not responses:
        return None
    
    log_event("INFO", "SMB", addr[0], f"Compound request: {len(responses)} responses")
    
    # Build compound response
    compound_resp = bytearray()
    for i, resp in enumerate(responses):
        if i < len(responses) - 1:
            # Set NextCommand offset - pad to 8-byte boundary
            padded_len = (len(resp) + 7) & ~7
            resp_bytes = bytearray(resp)
            resp_bytes[20] = padded_len & 0xFF
            resp_bytes[21] = (padded_len >> 8) & 0xFF
            resp_bytes[22] = (padded_len >> 16) & 0xFF
            resp_bytes[23] = (padded_len >> 24) & 0xFF
            compound_resp.extend(resp_bytes)
            # Add padding
            compound_resp.extend(b'\x00' * (padded_len - len(resp)))
        else:
            # Last response - no padding, NextCommand = 0
            resp_bytes = bytearray(resp)
            resp_bytes[20:24] = b'\x00\x00\x00\x00'
            compound_resp.extend(resp_bytes)
    
    # Add NetBIOS header
    nb = bytearray(4)
    nb[0] = 0x00
    length = len(compound_resp)
    nb[1] = (length >> 16) & 0xFF
    nb[2] = (length >> 8) & 0xFF
    nb[3] = length & 0xFF
    
    return bytes(nb + compound_resp)


def handle_smb2_single_command(data: bytes, addr: tuple, session) -> bytes:
    """Handle a single SMBv2/3 command and return response (with NetBIOS header)."""
    if len(data) < 64:
        return None
    
    command = data[12] | (data[13] << 8)
    message_id = data[24:32]
    
    log_event("INFO", "SMB", addr[0], f"SMB2 command: 0x{command:04x}")
    
    if command == 0x0000:  # Negotiate
        log_event("WARNING", "SMB", addr[0], "SMB2 NEGOTIATE")
        return smb2_negotiate_response(message_id)
        
    elif command == 0x0001:  # Session Setup
        log_event("CRITICAL", "SMB", addr[0], "SMB2 SESSION_SETUP - Auth attempt!")
        
        # Check what type of NTLM message this is
        ntlm_type = get_ntlm_type(data)
        
        if ntlm_type == 1:
            # NTLM Type 1 (Negotiate) - send challenge
            log_event("INFO", "SMB", addr[0], "NTLM Type 1 - Sending challenge")
            resp = smb2_session_challenge(data, message_id)
            log_event("INFO", "SMB", addr[0], f"Challenge response: {len(resp)} bytes, status: {resp[12:16].hex()}")
            return resp
        elif ntlm_type == 3:
            # NTLM Type 3 (Auth) - extract credentials, accept login
            log_event("CRITICAL", "SMB", addr[0], "NTLM Type 3 - Extracting credentials!")
            extract_ntlm_credentials(data, addr, session)
            resp = smb2_session_response(data, message_id)
            log_event("INFO", "SMB", addr[0], f"Session response: {len(resp)} bytes, status: {resp[12:16].hex()}")
            return resp
        else:
            # Unknown, just accept
            resp = smb2_session_response(data, message_id)
            log_event("INFO", "SMB", addr[0], f"Session response (no NTLM): {len(resp)} bytes")
            return resp
        
    elif command == 0x0003:  # Tree Connect
        log_event("CRITICAL", "SMB", addr[0], "SMB2 TREE_CONNECT - Share access")
        # Try to extract share name
        try:
            if len(data) > 72:
                offset = data[68] | (data[69] << 8)
                length = data[70] | (data[71] << 8)
                if offset and length:
                    share = data[offset:offset+length].decode('utf-16-le', errors='ignore')
                    log_event("CRITICAL", "SMB", addr[0], f"Requested share: {share}")
        except Exception as e:
            log_event("WARNING", "SMB", addr[0], f"Share parse error: {e}")
        try:
            resp = smb2_tree_connect_response(data, message_id)
            log_event("INFO", "SMB", addr[0], f"Tree connect response: {len(resp)} bytes, status: {resp[12:16].hex()}")
            return resp
        except Exception as e:
            log_event("WARNING", "SMB", addr[0], f"Tree connect response error: {e}")
            import traceback
            traceback.print_exc()
            return smb2_error_response(command, message_id, 0xC0000022)
    
    elif command == 0x0004:  # Tree Disconnect
        log_event("INFO", "SMB", addr[0], "SMB2 TREE_DISCONNECT")
        return smb2_simple_response(data, message_id, 0x0004)
    
    elif command == 0x000b:  # IOCTL - used for share enumeration
        log_event("CRITICAL", "SMB", addr[0], "SMB2 IOCTL - Share enumeration attempt")
        return smb2_ioctl_response(data, message_id)
    
    elif command == 0x0005:  # Create (open file/pipe)
        log_event("CRITICAL", "SMB", addr[0], "SMB2 CREATE - File/pipe access")
        return smb2_create_response(data, message_id, session)
    
    elif command == 0x0006:  # Close
        log_event("INFO", "SMB", addr[0], "SMB2 CLOSE")
        return smb2_close_response(data, message_id)
    
    elif command == 0x0008:  # Read
        log_event("INFO", "SMB", addr[0], "SMB2 READ - Pipe read")
        return smb2_read_response(data, message_id, session)
    
    elif command == 0x0009:  # Write
        log_event("INFO", "SMB", addr[0], "SMB2 WRITE - Pipe write")
        return smb2_write_response(data, message_id, session)
    
    elif command == 0x000e:  # Query Directory
        log_event("CRITICAL", "SMB", addr[0], "SMB2 QUERY_DIRECTORY - Directory listing")
        return smb2_query_directory_response(data, message_id, session)
        
    else:
        log_event("INFO", "SMB", addr[0], f"SMB2 unknown command: 0x{command:04x}")
        return smb2_error_response(command, message_id, 0xC0000022)


def get_ntlm_type(data: bytes) -> int:
    """Get NTLM message type from SMB data."""
    idx = data.find(b'NTLMSSP\x00')
    if idx < 0:
        return 0
    if len(data) < idx + 12:
        return 0
    return data[idx + 8]


def extract_ntlm_credentials(data: bytes, addr: tuple, session):
    """Extract NTLM credentials from SMB auth message."""
    try:
        idx = data.find(b'NTLMSSP\x00')
        if idx < 0:
            return
        
        ntlm = data[idx:]
        if len(ntlm) < 12:
            return
        
        msg_type = ntlm[8]
        
        if msg_type == 1:
            log_event("INFO", "SMB", addr[0], "NTLM Type 1 (Negotiate)")
            
        elif msg_type == 3:
            log_event("CRITICAL", "SMB", addr[0], "NTLM Type 3 (Auth) - Extracting creds")
            
            if len(ntlm) < 52:
                return
            
            # Parse fields
            domain_len = ntlm[28] | (ntlm[29] << 8)
            domain_off = ntlm[32] | (ntlm[33] << 8)
            user_len = ntlm[36] | (ntlm[37] << 8)
            user_off = ntlm[40] | (ntlm[41] << 8)
            host_len = ntlm[44] | (ntlm[45] << 8)
            host_off = ntlm[48] | (ntlm[49] << 8)
            nt_len = ntlm[20] | (ntlm[21] << 8)
            nt_off = ntlm[24] | (ntlm[25] << 8)
            
            domain = ntlm[domain_off:domain_off+domain_len].decode('utf-16-le', errors='ignore') if domain_len else ""
            user = ntlm[user_off:user_off+user_len].decode('utf-16-le', errors='ignore') if user_len else ""
            host = ntlm[host_off:host_off+host_len].decode('utf-16-le', errors='ignore') if host_len else ""
            nt_hash = ntlm[nt_off:nt_off+nt_len].hex() if nt_len else ""
            
            full_user = f"{domain}\\{user}" if domain else user
            
            log_event("CRITICAL", "SMB", addr[0], f"NTLM: {full_user}@{host}")
            
            # Store credential
            cred = CapturedCredential(
                datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                addr[0], addr[1], "SMB",
                full_user,
                f"NTLMv2:{nt_hash[:64]}..." if len(nt_hash) > 64 else f"NTLM:{nt_hash}",
                "ntlm"
            )
            with state.lock:
                state.credentials.append(cred)
            
            discord_login_alert("SMB", addr[0], full_user, "[NTLM HASH]")
            session.username = full_user
            
    except Exception as e:
        log_event("WARNING", "SMB", addr[0], f"NTLM parse error: {e}")


def smb1_negotiate_response(request: bytes) -> bytes:
    """Build SMBv1 negotiate response."""
    # SMB1 header (32 bytes)
    resp = bytearray(32)
    resp[0:4] = b'\xffSMB'  # Magic
    resp[4] = 0x72  # Negotiate
    resp[5:9] = b'\x00\x00\x00\x00'  # SUCCESS
    resp[9] = 0x98  # Flags
    resp[10:12] = b'\x53\xc8'  # Flags2 (Unicode, NT Status, Extended Security)
    
    # Copy TID, PID, UID, MID from request
    if len(request) >= 32:
        resp[24:28] = request[24:28]  # TID + PID
        resp[28:32] = request[28:32]  # UID + MID
    
    # Word count = 17 (0x11)
    params = bytearray(35)
    params[0] = 0x11  # Word count
    params[1:3] = b'\x00\x00'  # Dialect index (NT LM 0.12)
    params[3] = 0x03  # Security mode
    params[4:6] = b'\x02\x00'  # Max MPX
    params[6:8] = b'\x01\x00'  # Max VCs
    params[8:12] = b'\x04\x11\x00\x00'  # Max buffer
    params[12:16] = b'\x00\x00\x01\x00'  # Max raw
    params[16:20] = b'\x00\x00\x00\x00'  # Session key
    params[20:24] = b'\xfd\xe3\x00\x00'  # Capabilities
    params[24:32] = b'\x00' * 8  # System time
    params[32:34] = b'\x00\x00'  # Timezone
    params[34] = 0x00  # Key length
    
    # Byte count (2 bytes) - just GUID for now
    data = bytearray(18)
    data[0:2] = b'\x10\x00'  # Byte count = 16
    data[2:18] = os.urandom(16)  # Server GUID
    
    response = resp + params + data
    
    # NetBIOS
    nb = bytearray(4)
    nb[0] = 0x00
    length = len(response)
    nb[1] = (length >> 16) & 0xFF
    nb[2] = (length >> 8) & 0xFF
    nb[3] = length & 0xFF
    
    return bytes(nb + response)


def smb1_session_response(request: bytes) -> bytes:
    """Build SMBv1 session setup response with NTLM challenge."""
    resp = bytearray(32)
    resp[0:4] = b'\xffSMB'
    resp[4] = 0x73  # Session Setup
    # STATUS_MORE_PROCESSING_REQUIRED
    resp[5:9] = b'\x16\x00\x00\xc0'
    resp[9] = 0x98
    resp[10:12] = b'\x53\xc8'
    
    if len(request) >= 32:
        resp[24:28] = request[24:28]
        resp[28:32] = request[28:32]
    
    # Build NTLM challenge
    challenge = build_ntlm_type2()
    
    # Word count = 4
    params = bytearray(9)
    params[0] = 0x04
    params[1] = 0xff  # AndX command = none
    params[2] = 0x00  # Reserved
    params[3:5] = b'\x00\x00'  # AndX offset
    params[5:7] = b'\x00\x00'  # Action
    params[7:9] = bytes([len(challenge) & 0xFF, (len(challenge) >> 8) & 0xFF])
    
    # Byte count
    bc = len(challenge)
    data = bytearray(2)
    data[0] = bc & 0xFF
    data[1] = (bc >> 8) & 0xFF
    
    response = resp + params + data + challenge
    
    nb = bytearray(4)
    nb[0] = 0x00
    length = len(response)
    nb[1] = (length >> 16) & 0xFF
    nb[2] = (length >> 8) & 0xFF
    nb[3] = length & 0xFF
    
    return bytes(nb + response)


def smb1_error_response(request: bytes, command: int, status: int) -> bytes:
    """Build SMBv1 error response."""
    resp = bytearray(32)
    resp[0:4] = b'\xffSMB'
    resp[4] = command
    resp[5] = status & 0xFF
    resp[6] = (status >> 8) & 0xFF
    resp[7] = (status >> 16) & 0xFF
    resp[8] = (status >> 24) & 0xFF
    resp[9] = 0x88
    resp[10:12] = b'\x03\xc8'
    
    if len(request) >= 32:
        resp[24:28] = request[24:28]
        resp[28:32] = request[28:32]
    
    # Zero word count, zero byte count
    data = bytearray(3)
    data[0] = 0x00
    data[1:3] = b'\x00\x00'
    
    response = resp + data
    
    nb = bytearray(4)
    nb[0] = 0x00
    length = len(response)
    nb[1] = (length >> 16) & 0xFF
    nb[2] = (length >> 8) & 0xFF
    nb[3] = length & 0xFF
    
    return bytes(nb + response)


def smb1_success_response(request: bytes, command: int) -> bytes:
    """Build simple SMBv1 success response."""
    resp = bytearray(32)
    resp[0:4] = b'\xffSMB'
    resp[4] = command
    resp[5:9] = b'\x00\x00\x00\x00'  # STATUS_SUCCESS
    resp[9] = 0x98
    resp[10:12] = b'\x53\xc8'
    
    if len(request) >= 32:
        resp[24:28] = request[24:28]
        resp[28:32] = request[28:32]
    
    data = bytearray(3)
    data[0] = 0x00  # Word count
    data[1:3] = b'\x00\x00'  # Byte count
    
    response = resp + data
    nb = bytearray(4)
    nb[0] = 0x00
    length = len(response)
    nb[1] = (length >> 16) & 0xFF
    nb[2] = (length >> 8) & 0xFF
    nb[3] = length & 0xFF
    return bytes(nb + response)


def smb1_tree_connect_response(request: bytes) -> bytes:
    """Build SMBv1 Tree Connect AndX response for IPC$."""
    resp = bytearray(32)
    resp[0:4] = b'\xffSMB'
    resp[4] = 0x75  # Tree Connect AndX
    resp[5:9] = b'\x00\x00\x00\x00'  # STATUS_SUCCESS
    resp[9] = 0x98
    resp[10:12] = b'\x53\xc8'
    
    if len(request) >= 32:
        resp[24:26] = b'\x01\x00'  # TID = 1
        resp[26:28] = request[26:28]  # PID
        resp[28:32] = request[28:32]  # UID + MID
    
    # Word count = 7 (AndX response)
    params = bytearray(15)
    params[0] = 0x07  # Word count
    params[1] = 0xff  # AndXCommand = NONE
    params[2] = 0x00  # Reserved
    params[3:5] = b'\x00\x00'  # AndXOffset
    params[5:7] = b'\x01\x00'  # OptionalSupport (SMB_SUPPORT_SEARCH_BITS)
    params[7:11] = b'\xff\x01\x00\x00'  # MaximalShareAccessRights
    params[11:15] = b'\xff\x01\x00\x00'  # GuestMaximalShareAccessRights
    
    # Byte count + Service + NativeFileSystem
    service = b'IPC\x00'
    native_fs = b'\x00\x00'  # Empty UTF-16
    byte_count = len(service) + len(native_fs)
    data = bytearray(2 + byte_count)
    data[0] = byte_count & 0xFF
    data[1] = (byte_count >> 8) & 0xFF
    data[2:2+len(service)] = service
    data[2+len(service):] = native_fs
    
    response = resp + params + data
    nb = bytearray(4)
    nb[0] = 0x00
    length = len(response)
    nb[1] = (length >> 16) & 0xFF
    nb[2] = (length >> 8) & 0xFF
    nb[3] = length & 0xFF
    return bytes(nb + response)


def smb1_trans_response(request: bytes) -> bytes:
    """Build SMBv1 TRANS response for RAP NetServerEnum2 - empty workgroup list."""
    resp = bytearray(32)
    resp[0:4] = b'\xffSMB'
    resp[4] = 0x25  # Trans
    resp[5:9] = b'\x00\x00\x00\x00'  # STATUS_SUCCESS
    resp[9] = 0x98
    resp[10:12] = b'\x53\xc8'
    
    if len(request) >= 32:
        resp[24:28] = request[24:28]
        resp[28:32] = request[28:32]
    
    # RAP response data (empty server/domain list)
    # Status (2) + Converter (2) + EntriesReturned (2) + EntriesAvailable (2) = 8 bytes
    rap_data = bytearray(8)
    rap_data[0:2] = b'\x00\x00'  # Win32 error = NERR_Success
    rap_data[2:4] = b'\x00\x00'  # Converter
    rap_data[4:6] = b'\x00\x00'  # Entries returned = 0
    rap_data[6:8] = b'\x00\x00'  # Entries available = 0
    
    # Parameters (Word count = 10)
    params = bytearray(21)
    params[0] = 0x0a  # Word count = 10
    params[1:3] = b'\x08\x00'  # Total param count = 8
    params[3:5] = b'\x00\x00'  # Total data count = 0
    params[5:7] = b'\x00\x00'  # Reserved
    params[7:9] = b'\x08\x00'  # Param count = 8
    params[9:11] = b'\x38\x00'  # Param offset (56 = 32 header + 21 params + 3 byte count section)
    params[11:13] = b'\x00\x00'  # Param displacement
    params[13:15] = b'\x00\x00'  # Data count = 0
    params[15:17] = b'\x40\x00'  # Data offset (64)
    params[17:19] = b'\x00\x00'  # Data displacement
    params[19] = 0x00  # Setup count = 0
    params[20] = 0x00  # Reserved
    
    # Byte count
    byte_data = bytearray(3 + len(rap_data))
    byte_count = 1 + len(rap_data)  # 1 byte padding + RAP data
    byte_data[0] = byte_count & 0xFF
    byte_data[1] = (byte_count >> 8) & 0xFF
    byte_data[2] = 0x00  # Padding
    byte_data[3:] = rap_data
    
    response = resp + params + byte_data
    nb = bytearray(4)
    nb[0] = 0x00
    length = len(response)
    nb[1] = (length >> 16) & 0xFF
    nb[2] = (length >> 8) & 0xFF
    nb[3] = length & 0xFF
    return bytes(nb + response)


def smb2_negotiate_response(message_id: bytes = b'\x00' * 8) -> bytes:
    """Build SMB2 negotiate response with SPNEGO security blob."""
    # Build SPNEGO negTokenInit offering NTLMSSP
    security_blob = build_spnego_negtokeninit()
    
    # Server GUID (use fixed for consistency)
    server_guid = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10'
    
    # SMB2 NEGOTIATE Response body (65 bytes structure + security blob)
    body = bytearray(64)
    body[0:2] = b'\x41\x00'  # Structure size = 65
    body[2:4] = b'\x00\x00'  # Security mode: no signing required
    body[4:6] = b'\x02\x02'  # Dialect: SMB 2.0.2
    body[6:8] = b'\x00\x00'  # Reserved (NegotiateContextCount for 3.1.1)
    body[8:24] = server_guid
    body[24:28] = b'\x07\x00\x00\x00'  # Capabilities
    body[28:32] = b'\x00\x00\x10\x00'  # Max transact (1MB)
    body[32:36] = b'\x00\x00\x10\x00'  # Max read
    body[36:40] = b'\x00\x00\x10\x00'  # Max write
    # SystemTime (8 bytes) - current time as FILETIME
    import time
    filetime = int((time.time() + 11644473600) * 10000000)
    body[40:48] = filetime.to_bytes(8, 'little')
    body[48:56] = filetime.to_bytes(8, 'little')  # ServerStartTime
    
    # Security buffer offset = header (64) + body (64) = 128
    sec_offset = 128
    body[56:58] = sec_offset.to_bytes(2, 'little')
    body[58:60] = len(security_blob).to_bytes(2, 'little')
    body[60:64] = b'\x00\x00\x00\x00'  # Reserved2/NegotiateContextOffset
    
    # SMB2 header (64 bytes)
    hdr = bytearray(64)
    hdr[0:4] = b'\xfeSMB'
    hdr[4:6] = b'\x40\x00'  # Structure size
    hdr[6:8] = b'\x00\x00'  # Credit charge
    hdr[8:12] = b'\x00\x00\x00\x00'  # STATUS_SUCCESS
    hdr[12:14] = b'\x00\x00'  # Command: NEGOTIATE
    hdr[14:16] = b'\xff\x00'  # Credits granted (255 - plenty for any operation)
    hdr[16:20] = b'\x01\x00\x00\x00'  # Flags: Response
    hdr[24:32] = message_id
    # Bytes 48-63 are signature (zeros for no signing)
    
    response = hdr + body + security_blob
    
    # NetBIOS header
    nb = bytearray(4)
    nb[0] = 0x00
    length = len(response)
    nb[1] = (length >> 16) & 0xFF
    nb[2] = (length >> 8) & 0xFF
    nb[3] = length & 0xFF
    
    return bytes(nb + response)


# SPNEGO functions kept for future use if needed
def build_spnego_negtokeninit() -> bytes:
    """Build SPNEGO negTokenInit with NTLMSSP mechanism."""
    # SPNEGO OID: 1.3.6.1.5.5.2
    spnego_oid = bytes([0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02])
    
    # NTLMSSP OID: 1.3.6.1.4.1.311.2.2.10
    ntlmssp_oid = bytes([0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a])
    
    # mechTypes [0] = SEQUENCE of OID
    mech_list = bytearray()
    mech_list.append(0x30)  # SEQUENCE
    mech_list.extend(asn1_length(len(ntlmssp_oid)))
    mech_list.extend(ntlmssp_oid)
    
    mech_types = bytearray()
    mech_types.append(0xa0)  # Context [0]
    mech_types.extend(asn1_length(len(mech_list)))
    mech_types.extend(mech_list)
    
    # negTokenInit SEQUENCE
    neg_token_init_seq = bytearray()
    neg_token_init_seq.append(0x30)  # SEQUENCE
    neg_token_init_seq.extend(asn1_length(len(mech_types)))
    neg_token_init_seq.extend(mech_types)
    
    # Wrap in CONTEXT [0] for APPLICATION tag
    inner = bytearray()
    inner.append(0xa0)  # Context [0]
    inner.extend(asn1_length(len(neg_token_init_seq)))
    inner.extend(neg_token_init_seq)
    
    # Final: APPLICATION [0] with SPNEGO OID
    result = bytearray()
    result.append(0x60)  # APPLICATION [0]
    total_len = len(spnego_oid) + len(inner)
    result.extend(asn1_length(total_len))
    result.extend(spnego_oid)
    result.extend(inner)
    
    return bytes(result)


def smb2_session_challenge(request: bytes, message_id: bytes) -> bytes:
    """Build SMB2 session response with NTLM Type 2 challenge."""
    # Build NTLM Type 2 challenge with target info
    ntlm_challenge = build_ntlm_challenge_message()
    
    # Wrap in proper SPNEGO negTokenTarg
    security_blob = build_spnego_negtokentarg(ntlm_challenge)
    
    # SMB2 header
    hdr = bytearray(64)
    hdr[0:4] = b'\xfeSMB'
    hdr[4:6] = b'\x40\x00'  # Structure size
    hdr[6:8] = b'\x00\x00'  # Credit charge
    # STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016
    hdr[8:12] = b'\x16\x00\x00\xc0'
    hdr[12:14] = b'\x01\x00'  # Session Setup command
    hdr[14:16] = b'\xff\x00'  # Credits granted (255)
    hdr[16:20] = b'\x01\x00\x00\x00'  # Flags: Response
    hdr[24:32] = message_id
    
    # Copy ProcessId from request
    if len(request) >= 36:
        hdr[32:36] = request[32:36]
    
    # Use fixed session ID for honeypot simplicity
    session_id = b'\x01\x00\x00\x00\x00\x00\x00\x00'
    hdr[40:48] = session_id
    
    # Session setup response body
    sec_offset = 64 + 8  # Header + body
    body = bytearray(8)
    body[0:2] = b'\x09\x00'  # Structure size (9)
    body[2:4] = b'\x00\x00'  # Session flags
    body[4:6] = sec_offset.to_bytes(2, 'little')
    body[6:8] = len(security_blob).to_bytes(2, 'little')
    
    response = hdr + body + security_blob
    
    # NetBIOS header
    nb = bytearray(4)
    nb[0] = 0x00
    length = len(response)
    nb[1] = (length >> 16) & 0xFF
    nb[2] = (length >> 8) & 0xFF
    nb[3] = length & 0xFF
    
    return bytes(nb + response)


def build_ntlm_challenge_message() -> bytes:
    """Build NTLM Type 2 (Challenge) message with target info for NTLMv2."""
    # Target name
    target_name = "WORKGROUP".encode('utf-16-le')
    
    # Build AV_PAIR list (target info) - required for NTLMv2
    target_info = bytearray()
    
    # MsvAvNbDomainName (0x0002)
    nb_domain = "WORKGROUP".encode('utf-16-le')
    target_info.extend(b'\x02\x00')
    target_info.extend(bytes([len(nb_domain) & 0xFF, (len(nb_domain) >> 8) & 0xFF]))
    target_info.extend(nb_domain)
    
    # MsvAvNbComputerName (0x0001)
    nb_computer = "FILESERVER".encode('utf-16-le')
    target_info.extend(b'\x01\x00')
    target_info.extend(bytes([len(nb_computer) & 0xFF, (len(nb_computer) >> 8) & 0xFF]))
    target_info.extend(nb_computer)
    
    # MsvAvDnsDomainName (0x0004)
    dns_domain = "workgroup.local".encode('utf-16-le')
    target_info.extend(b'\x04\x00')
    target_info.extend(bytes([len(dns_domain) & 0xFF, (len(dns_domain) >> 8) & 0xFF]))
    target_info.extend(dns_domain)
    
    # MsvAvDnsComputerName (0x0003)
    dns_computer = "fileserver.workgroup.local".encode('utf-16-le')
    target_info.extend(b'\x03\x00')
    target_info.extend(bytes([len(dns_computer) & 0xFF, (len(dns_computer) >> 8) & 0xFF]))
    target_info.extend(dns_computer)
    
    # MsvAvTimestamp (0x0007) - Windows FILETIME
    target_info.extend(b'\x07\x00')
    target_info.extend(b'\x08\x00')
    import time
    filetime = int((time.time() + 11644473600) * 10000000)
    target_info.extend(filetime.to_bytes(8, 'little'))
    
    # MsvAvEOL (0x0000)
    target_info.extend(b'\x00\x00\x00\x00')
    
    # Calculate offsets - header is 56 bytes, payload follows
    header_size = 56
    target_name_offset = header_size
    target_info_offset = target_name_offset + len(target_name)
    
    # Build NTLM Type 2 message
    ntlm = bytearray()
    ntlm.extend(b'NTLMSSP\x00')  # Signature (0-7)
    ntlm.extend(b'\x02\x00\x00\x00')  # Type 2 (8-11)
    
    # Target name fields (12-19)
    ntlm.extend(bytes([len(target_name) & 0xFF, (len(target_name) >> 8) & 0xFF]))
    ntlm.extend(bytes([len(target_name) & 0xFF, (len(target_name) >> 8) & 0xFF]))
    ntlm.extend(bytes([target_name_offset & 0xFF, (target_name_offset >> 8) & 0xFF, 0, 0]))
    
    # Negotiate flags (20-23)
    # UNICODE | REQUEST_TARGET | NTLM | ALWAYS_SIGN | TARGET_INFO | TARGET_TYPE_DOMAIN | EXTENDED_SESSION_SECURITY | NTLM2_KEY
    flags = 0xe2898215
    ntlm.extend(flags.to_bytes(4, 'little'))
    
    # Server challenge (24-31)
    challenge = os.urandom(8)
    ntlm.extend(challenge)
    
    # Reserved (32-39)
    ntlm.extend(b'\x00' * 8)
    
    # Target info fields (40-47)
    ntlm.extend(bytes([len(target_info) & 0xFF, (len(target_info) >> 8) & 0xFF]))
    ntlm.extend(bytes([len(target_info) & 0xFF, (len(target_info) >> 8) & 0xFF]))
    ntlm.extend(bytes([target_info_offset & 0xFF, (target_info_offset >> 8) & 0xFF, 0, 0]))
    
    # Version (48-55) - Windows 6.1
    ntlm.extend(b'\x06\x01\x00\x00\x00\x00\x00\x0f')
    
    # Payload
    ntlm.extend(target_name)
    ntlm.extend(target_info)
    
    return bytes(ntlm)


def smb2_session_response(request: bytes, message_id: bytes) -> bytes:
    """Build SMB2 session response - accept login for honeypot."""
    # For honeypot purposes, we return SUCCESS to keep attacker engaged
    
    hdr = bytearray(64)
    hdr[0:4] = b'\xfeSMB'
    hdr[4:6] = b'\x40\x00'  # Structure size
    hdr[6:8] = b'\x00\x00'  # Credit charge
    # STATUS_SUCCESS = 0x00000000
    hdr[8:12] = b'\x00\x00\x00\x00'
    hdr[12:14] = b'\x01\x00'  # Session Setup command
    hdr[14:16] = b'\xff\x00'  # Credits granted (255)
    hdr[16:20] = b'\x01\x00\x00\x00'  # Flags: Response
    hdr[20:24] = b'\x00\x00\x00\x00'  # Next command
    hdr[24:32] = message_id
    
    # Copy ProcessId from request
    if len(request) >= 36:
        hdr[32:36] = request[32:36]
    
    # Copy Session ID from request (client uses what we gave in challenge)
    if len(request) >= 48:
        hdr[40:48] = request[40:48]
    else:
        hdr[40:48] = b'\x01\x00\x00\x00\x00\x00\x00\x00'
    
    # SPNEGO negTokenResp with accept-completed and supportedMech (NTLMSSP)
    # This is more complete than minimal accept and helps with client compatibility
    spnego_accept = bytes([
        0xa1, 0x15,              # [1] negTokenResp, length 21
        0x30, 0x13,              # SEQUENCE, length 19
        0xa0, 0x03,              # [0] negState, length 3
        0x0a, 0x01, 0x00,        # ENUMERATED, value 0 (accept-completed)
        0xa1, 0x0c,              # [1] supportedMech, length 12
        0x06, 0x0a,              # OID, length 10
        0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a  # NTLMSSP OID (1.3.6.1.4.1.311.2.2.10)
    ])
    
    # Session setup response body
    # SecurityBufferOffset relative to start of SMB2 header
    sec_offset = 64 + 8  # Header (64) + body fixed part (8) = 72
    body = bytearray(8)
    body[0:2] = b'\x09\x00'  # Structure size (9)
    body[2:4] = b'\x01\x00'  # Session flags: SMB2_SESSION_FLAG_IS_GUEST (for compatibility with anonymous)
    body[4:6] = sec_offset.to_bytes(2, 'little')  # SecurityBufferOffset
    body[6:8] = len(spnego_accept).to_bytes(2, 'little')  # SecurityBufferLength
    
    response = hdr + body + spnego_accept
    
    # NetBIOS header
    nb = bytearray(4)
    nb[0] = 0x00
    length = len(response)
    nb[1] = (length >> 16) & 0xFF
    nb[2] = (length >> 8) & 0xFF
    nb[3] = length & 0xFF
    
    return bytes(nb + response)


def smb2_error_response(command: int, message_id: bytes, status: int) -> bytes:
    """Build SMB2 error response."""
    hdr = bytearray(64)
    hdr[0:4] = b'\xfeSMB'
    hdr[4:6] = b'\x40\x00'
    hdr[8] = status & 0xFF
    hdr[9] = (status >> 8) & 0xFF
    hdr[10] = (status >> 16) & 0xFF
    hdr[11] = (status >> 24) & 0xFF
    hdr[12] = command & 0xFF
    hdr[13] = (command >> 8) & 0xFF
    hdr[14:16] = b'\x01\x00'
    hdr[16:20] = b'\x01\x00\x00\x00'
    hdr[24:32] = message_id
    
    body = bytearray(9)
    body[0:2] = b'\x09\x00'
    
    response = hdr + body
    
    nb = bytearray(4)
    nb[0] = 0x00
    length = len(response)
    nb[1] = (length >> 16) & 0xFF
    nb[2] = (length >> 8) & 0xFF
    nb[3] = length & 0xFF
    
    return bytes(nb + response)


def smb2_tree_connect_response(request: bytes, message_id: bytes) -> bytes:
    """Build SMB2 Tree Connect response for IPC$ share."""
    # Detect if IPC$ share - parse from request
    is_ipc = True  # Default to IPC for share listing
    share_name = ""
    try:
        if len(request) > 72:
            # SMB2 TREE_CONNECT request body starts at offset 64
            # PathOffset is at body offset 4-5 (absolute offset 68-69)
            # PathLength is at body offset 6-7 (absolute offset 70-71)
            path_offset = request[68] | (request[69] << 8)
            path_length = request[70] | (request[71] << 8)
            if path_offset and path_length and len(request) >= path_offset + path_length:
                share_name = request[path_offset:path_offset+path_length].decode('utf-16-le', errors='ignore')
                is_ipc = 'IPC$' in share_name.upper()
    except Exception as e:
        pass  # Default to IPC
    
    hdr = bytearray(64)
    hdr[0:4] = b'\xfeSMB'
    hdr[4:6] = b'\x40\x00'  # Structure size
    hdr[6:8] = b'\x00\x00'  # Credit charge
    hdr[8:12] = b'\x00\x00\x00\x00'  # STATUS_SUCCESS
    hdr[12:14] = b'\x03\x00'  # Tree Connect command
    hdr[14:16] = b'\x7f\x00'  # Credits granted (127)
    hdr[16:20] = b'\x01\x00\x00\x00'  # Flags: Response
    hdr[20:24] = b'\x00\x00\x00\x00'  # Next command
    hdr[24:32] = message_id
    
    # Copy Reserved/ProcessId from request
    if len(request) >= 36:
        hdr[32:36] = request[32:36]
    
    # Set Tree ID to 1
    hdr[36:40] = b'\x01\x00\x00\x00'
    
    # Copy session ID from request
    if len(request) >= 48:
        hdr[40:48] = request[40:48]
    
    # Tree Connect response body (16 bytes)
    body = bytearray(16)
    body[0:2] = b'\x10\x00'  # Structure size (16)
    
    if is_ipc:
        body[2] = 0x02  # Share type: PIPE (0x02) for IPC$
        body[3] = 0x00  # Reserved
        body[4:8] = b'\x00\x00\x00\x00'  # Share flags (none - simplest for IPC$)
        body[8:12] = b'\x00\x00\x00\x00'  # Capabilities
        body[12:16] = b'\xff\x01\x1f\x00'  # Maximal access (FILE_ALL_ACCESS = 0x001F01FF)
    else:
        body[2] = 0x01  # Share type: DISK (0x01)
        body[3] = 0x00  # Reserved
        body[4:8] = b'\x00\x00\x00\x00'  # Share flags
        body[8:12] = b'\x00\x00\x00\x00'  # Capabilities
        body[12:16] = b'\xff\x01\x1f\x00'  # Maximal access (FILE_ALL_ACCESS)
    
    response = hdr + body
    
    # NetBIOS header
    nb = bytearray(4)
    nb[0] = 0x00
    length = len(response)
    nb[1] = (length >> 16) & 0xFF
    nb[2] = (length >> 8) & 0xFF
    nb[3] = length & 0xFF
    
    return bytes(nb + response)


def smb2_simple_response(request: bytes, message_id: bytes, command: int) -> bytes:
    """Build simple SMB2 success response."""
    hdr = bytearray(64)
    hdr[0:4] = b'\xfeSMB'
    hdr[4:6] = b'\x40\x00'
    hdr[8:12] = b'\x00\x00\x00\x00'  # STATUS_SUCCESS
    hdr[12] = command & 0xFF
    hdr[13] = (command >> 8) & 0xFF
    hdr[14:16] = b'\x01\x00'
    hdr[16:20] = b'\x01\x00\x00\x00'
    hdr[24:32] = message_id
    if len(request) >= 48:
        hdr[40:48] = request[40:48]
    
    body = bytearray(4)
    body[0:2] = b'\x04\x00'  # Structure size
    
    response = hdr + body
    nb = bytearray(4)
    nb[0] = 0x00
    length = len(response)
    nb[1] = (length >> 16) & 0xFF
    nb[2] = (length >> 8) & 0xFF
    nb[3] = length & 0xFF
    
    return bytes(nb + response)


def smb2_ioctl_response(request: bytes, message_id: bytes) -> bytes:
    """Build SMB2 IOCTL response for FSCTL_PIPE_TRANSACT (DCE/RPC transactions)."""
    ctl_code = 0
    input_data = b''
    file_id = b'\x00' * 16
    
    if len(request) >= 72:
        ctl_code = int.from_bytes(request[68:72], 'little')
    
    if len(request) >= 88:
        file_id = request[72:88]
    
    # Parse input buffer
    if len(request) >= 96:
        input_offset = int.from_bytes(request[88:92], 'little')
        input_count = int.from_bytes(request[92:96], 'little')
        if input_offset > 0 and input_count > 0 and len(request) >= input_offset + input_count:
            input_data = request[input_offset:input_offset + input_count]
    
    # Generate DCE/RPC response based on input
    output_data = b''
    
    if ctl_code == 0x0011C017:  # FSCTL_PIPE_TRANSACT
        # This is a DCE/RPC transaction
        if len(input_data) >= 2:
            dcerpc_type = input_data[2] if len(input_data) > 2 else 0
            call_id = input_data[12:16] if len(input_data) > 15 else b'\x01\x00\x00\x00'
            
            if dcerpc_type == 11:  # DCE/RPC Bind
                output_data = build_dcerpc_bind_ack(call_id)
            elif dcerpc_type == 0:  # DCE/RPC Request (NetShareEnumAll)
                output_data = build_dcerpc_share_enum_response(call_id)
            else:
                output_data = b''
    
    # Build IOCTL response
    hdr = bytearray(64)
    hdr[0:4] = b'\xfeSMB'
    hdr[4:6] = b'\x40\x00'
    hdr[6:8] = b'\x00\x00'  # Credit charge
    hdr[8:12] = b'\x00\x00\x00\x00'  # STATUS_SUCCESS
    hdr[12:14] = b'\x0b\x00'  # IOCTL
    hdr[14:16] = b'\xff\x00'  # Credits granted
    hdr[16:20] = b'\x01\x00\x00\x00'  # Flags: Response
    hdr[20:24] = b'\x00\x00\x00\x00'  # Next command
    hdr[24:32] = message_id
    
    # Copy ProcessId, TreeId, SessionId from request
    if len(request) >= 36:
        hdr[32:36] = request[32:36]  # ProcessId
    if len(request) >= 40:
        hdr[36:40] = request[36:40]  # TreeId
    if len(request) >= 48:
        hdr[40:48] = request[40:48]  # SessionId
    
    # IOCTL response body (48 bytes fixed + output data)
    output_offset = 64 + 48  # Header + body = 112
    body = bytearray(48)
    body[0:2] = b'\x31\x00'  # Structure size (49)
    body[2:4] = b'\x00\x00'  # Reserved
    body[4:8] = ctl_code.to_bytes(4, 'little')  # CtlCode
    body[8:24] = file_id  # FileId
    body[24:28] = b'\x00\x00\x00\x00'  # InputOffset (0 = no input in response)
    body[28:32] = b'\x00\x00\x00\x00'  # InputCount (0)
    body[32:36] = output_offset.to_bytes(4, 'little')  # OutputOffset
    body[36:40] = len(output_data).to_bytes(4, 'little')  # OutputCount
    body[40:44] = b'\x00\x00\x00\x00'  # Flags
    body[44:48] = b'\x00\x00\x00\x00'  # Reserved2
    
    response = hdr + body + output_data
    
    # NetBIOS header
    nb = bytearray(4)
    nb[0] = 0x00
    length = len(response)
    nb[1] = (length >> 16) & 0xFF
    nb[2] = (length >> 8) & 0xFF
    nb[3] = length & 0xFF
    
    return bytes(nb + response)


def smb2_create_response(request: bytes, message_id: bytes, session=None) -> bytes:
    """Build SMB2 CREATE response for file/pipe access with VFS integration."""
    import time
    
    # Parse filename from request
    # SMB2 CREATE request: NameOffset at offset 44-45, NameLength at 46-47 (relative to SMB2 header)
    filename = ""
    is_directory = False
    try:
        if len(request) >= 72:
            name_offset = request[68] | (request[69] << 8)  # Absolute offset 64+4=68
            name_length = request[70] | (request[71] << 8)  # Absolute offset 64+6=70
            if name_offset > 0 and name_length > 0 and len(request) >= name_offset + name_length:
                filename = request[name_offset:name_offset + name_length].decode('utf-16-le', errors='ignore')
            
            # Check CreateOptions for directory flag (offset 64+24=88)
            if len(request) >= 92:
                create_options = request[88] | (request[89] << 8) | (request[90] << 16) | (request[91] << 24)
                is_directory = (create_options & 0x00000001) != 0  # FILE_DIRECTORY_FILE
    except:
        pass
    
    # Normalize path (Windows to Unix style)
    vfs_path = "/" + filename.replace("\\", "/").strip("/")
    if vfs_path == "/":
        vfs_path = "/"
        is_directory = True
    
    # Check if path exists in VFS
    vfs_entry = get_virtual_fs_entry(vfs_path)
    file_content = FAKE_FILE_CONTENTS.get(vfs_path, "")
    
    if vfs_entry is not None:
        is_directory = True
    elif file_content:
        is_directory = False
    
    # Generate FileId (16 bytes)
    file_id = os.urandom(16)
    
    # Store FileId -> path mapping in session
    if session is not None:
        if not hasattr(session, 'file_handles'):
            session.file_handles = {}
        session.file_handles[file_id] = {
            'path': vfs_path,
            'filename': filename,
            'is_directory': is_directory,
            'content': file_content
        }
    
    # Build SMB2 header
    hdr = bytearray(64)
    hdr[0:4] = b'\xfeSMB'
    hdr[4:6] = b'\x40\x00'  # Structure size
    hdr[6:8] = b'\x00\x00'  # Credit charge
    hdr[8:12] = b'\x00\x00\x00\x00'  # STATUS_SUCCESS
    hdr[12:14] = b'\x05\x00'  # CREATE command
    hdr[14:16] = b'\x7f\x00'  # Credits granted
    hdr[16:20] = b'\x01\x00\x00\x00'  # Flags: Response
    hdr[20:24] = b'\x00\x00\x00\x00'  # Next command
    hdr[24:32] = message_id
    
    # Copy TreeId and SessionId from request
    if len(request) >= 40:
        hdr[32:36] = request[32:36]  # Reserved/ProcessId
        hdr[36:40] = request[36:40]  # TreeId
    if len(request) >= 48:
        hdr[40:48] = request[40:48]  # SessionId
    
    # CREATE response body (89 bytes)
    body = bytearray(88)
    body[0:2] = b'\x59\x00'  # Structure size (89)
    body[2] = 0x00  # OplockLevel (none)
    body[3] = 0x00  # Flags
    body[4:8] = b'\x01\x00\x00\x00'  # CreateAction = FILE_OPENED
    
    # FILETIME: 100-nanosecond intervals since Jan 1, 1601
    filetime = int((time.time() + 11644473600) * 10000000)
    filetime_bytes = filetime.to_bytes(8, 'little')
    
    body[8:16] = filetime_bytes   # CreationTime
    body[16:24] = filetime_bytes  # LastAccessTime
    body[24:32] = filetime_bytes  # LastWriteTime
    body[32:40] = filetime_bytes  # ChangeTime
    
    # File size
    file_size = len(file_content) if file_content else 0
    body[40:48] = file_size.to_bytes(8, 'little')  # AllocationSize
    body[48:56] = file_size.to_bytes(8, 'little')  # EndOfFile
    
    # FileAttributes
    if is_directory:
        body[56:60] = (0x10).to_bytes(4, 'little')  # FILE_ATTRIBUTE_DIRECTORY
    else:
        body[56:60] = (0x80).to_bytes(4, 'little')  # FILE_ATTRIBUTE_NORMAL
    
    body[60:64] = b'\x00\x00\x00\x00'  # Reserved2
    body[64:80] = file_id  # FileId (16 bytes)
    body[80:84] = b'\x00\x00\x00\x00'  # CreateContextsOffset
    body[84:88] = b'\x00\x00\x00\x00'  # CreateContextsLength
    
    response = hdr + body
    
    # NetBIOS header
    nb = bytearray(4)
    nb[0] = 0x00
    length = len(response)
    nb[1] = (length >> 16) & 0xFF
    nb[2] = (length >> 8) & 0xFF
    nb[3] = length & 0xFF
    
    return bytes(nb + response)


def smb2_query_directory_response(request: bytes, message_id: bytes, session=None) -> bytes:
    """Build SMB2 QUERY_DIRECTORY response with FileIdBothDirectoryInformation."""
    import time
    
    # Parse FileId from request (offset 64+8 = 72, 16 bytes)
    file_id = request[72:88] if len(request) >= 88 else b'\x00' * 16
    
    # Parse InfoClass from request (offset 64+2 = 66)
    info_class = request[66] if len(request) > 66 else 0x03
    
    # Get directory path from session's file handles
    dir_path = "/"
    if session is not None and hasattr(session, 'file_handles'):
        handle_info = session.file_handles.get(file_id)
        if handle_info:
            dir_path = handle_info.get('path', '/')
    
    # Get directory entries from VFS
    entries = []
    vfs_entry = get_virtual_fs_entry(dir_path)
    if vfs_entry:
        # Add . and ..
        entries.append((".", True, 0))
        entries.append(("..", True, 0))
        
        # Add directory contents
        for item in vfs_entry:
            item_path = dir_path.rstrip("/") + "/" + item
            is_dir = get_virtual_fs_entry(item_path) is not None
            size = len(FAKE_FILE_CONTENTS.get(item_path, ""))
            entries.append((item, is_dir, size))
    
    if not entries:
        # Return STATUS_NO_MORE_FILES
        hdr = bytearray(64)
        hdr[0:4] = b'\xfeSMB'
        hdr[4:6] = b'\x40\x00'
        hdr[8:12] = b'\x03\x01\x00\x80'  # STATUS_NO_MORE_FILES (0x80000003)
        hdr[12:14] = b'\x0e\x00'  # QUERY_DIRECTORY
        hdr[14:16] = b'\x7f\x00'
        hdr[16:20] = b'\x01\x00\x00\x00'
        hdr[24:32] = message_id
        if len(request) >= 40:
            hdr[32:40] = request[32:40]
        if len(request) >= 48:
            hdr[40:48] = request[40:48]
        
        body = bytearray(8)
        body[0:2] = b'\x09\x00'  # Structure size
        
        response = hdr + body
        nb = bytearray(4)
        nb[0] = 0x00
        length = len(response)
        nb[1] = (length >> 16) & 0xFF
        nb[2] = (length >> 8) & 0xFF
        nb[3] = length & 0xFF
        return bytes(nb + response)
    
    filetime = int((time.time() + 11644473600) * 10000000)
    filetime_bytes = filetime.to_bytes(8, 'little')
    
    dir_data = bytearray()
    
    for idx, (name, is_dir, size) in enumerate(entries):
        entry = bytearray()
        
        # Encode filename as UTF-16-LE
        name_bytes = name.encode('utf-16-le')
        name_len = len(name_bytes)
        
        # Calculate entry size (must be 8-byte aligned)
        base_size = 104 + name_len  # FileIdBothDirectoryInformation fixed size + filename
        padded_size = (base_size + 7) & ~7  # Align to 8 bytes
        
        # NextEntryOffset (4 bytes) - set to 0 for last entry, otherwise aligned size
        if idx < len(entries) - 1:
            entry.extend(padded_size.to_bytes(4, 'little'))
        else:
            entry.extend((0).to_bytes(4, 'little'))
        
        entry.extend((idx).to_bytes(4, 'little'))  # FileIndex
        entry.extend(filetime_bytes)  # CreationTime
        entry.extend(filetime_bytes)  # LastAccessTime
        entry.extend(filetime_bytes)  # LastWriteTime
        entry.extend(filetime_bytes)  # ChangeTime
        entry.extend(size.to_bytes(8, 'little'))  # EndOfFile
        entry.extend(size.to_bytes(8, 'little'))  # AllocationSize
        
        # FileAttributes
        if is_dir:
            entry.extend((0x10).to_bytes(4, 'little'))  # FILE_ATTRIBUTE_DIRECTORY
        else:
            entry.extend((0x80).to_bytes(4, 'little'))  # FILE_ATTRIBUTE_NORMAL
        
        entry.extend(name_len.to_bytes(4, 'little'))  # FileNameLength
        entry.extend((0).to_bytes(4, 'little'))  # EaSize
        entry.append(0)  # ShortNameLength
        entry.append(0)  # Reserved1
        entry.extend(b'\x00' * 24)  # ShortName (24 bytes)
        entry.extend(b'\x00\x00')  # Reserved2
        entry.extend(os.urandom(8))  # FileId (8 bytes)
        entry.extend(name_bytes)  # FileName
        
        # Pad to 8-byte boundary
        pad_len = padded_size - len(entry)
        if pad_len > 0:
            entry.extend(b'\x00' * pad_len)
        
        dir_data.extend(entry)
    
    # Build SMB2 header
    hdr = bytearray(64)
    hdr[0:4] = b'\xfeSMB'
    hdr[4:6] = b'\x40\x00'
    hdr[6:8] = b'\x00\x00'
    hdr[8:12] = b'\x00\x00\x00\x00'  # STATUS_SUCCESS
    hdr[12:14] = b'\x0e\x00'  # QUERY_DIRECTORY command
    hdr[14:16] = b'\x7f\x00'  # Credits granted
    hdr[16:20] = b'\x01\x00\x00\x00'  # Flags: Response
    hdr[20:24] = b'\x00\x00\x00\x00'  # Next command
    hdr[24:32] = message_id
    
    if len(request) >= 40:
        hdr[32:36] = request[32:36]  # Reserved/ProcessId
        hdr[36:40] = request[36:40]  # TreeId
    if len(request) >= 48:
        hdr[40:48] = request[40:48]  # SessionId
    
    # QUERY_DIRECTORY response body
    data_offset = 72  # Header (64) + body (8) = 72
    body = bytearray(8)
    body[0:2] = b'\x09\x00'  # Structure size (9)
    body[2:4] = data_offset.to_bytes(2, 'little')  # OutputBufferOffset
    body[4:8] = len(dir_data).to_bytes(4, 'little')  # OutputBufferLength
    
    response = hdr + body + dir_data
    
    # NetBIOS header
    nb = bytearray(4)
    nb[0] = 0x00
    length = len(response)
    nb[1] = (length >> 16) & 0xFF
    nb[2] = (length >> 8) & 0xFF
    nb[3] = length & 0xFF
    
    return bytes(nb + response)


def smb2_read_response(request: bytes, message_id: bytes, session) -> bytes:
    """Build SMB2 READ response with VFS file content or DCE/RPC data."""
    read_data = b''
    
    # Parse FileId from request (offset 64+16 = 80, 16 bytes)
    file_id = request[80:96] if len(request) >= 96 else b'\x00' * 16
    
    # Parse ReadLength from request (offset 64+4 = 68, 4 bytes)
    read_length = 0
    if len(request) >= 72:
        read_length = int.from_bytes(request[68:72], 'little')
    
    # Parse Offset from request (offset 64+8 = 72, 8 bytes)
    read_offset = 0
    if len(request) >= 80:
        read_offset = int.from_bytes(request[72:80], 'little')
    
    # First check for DCE/RPC pending response (for pipe operations)
    if hasattr(session, 'dcerpc_state') and session.dcerpc_state.get('pending'):
        call_id = session.dcerpc_state.get('call_id', b'\x01\x00\x00\x00')
        
        if session.dcerpc_state['pending'] == 'bind_ack':
            read_data = build_dcerpc_bind_ack(call_id)
            session.dcerpc_state['pending'] = None
        elif session.dcerpc_state['pending'] == 'share_enum':
            read_data = build_dcerpc_share_enum_response(call_id)
            session.dcerpc_state['pending'] = None
    else:
        # Look up file content from session's file handles
        if hasattr(session, 'file_handles'):
            handle_info = session.file_handles.get(file_id)
            if handle_info:
                content = handle_info.get('content', '')
                if content:
                    # Convert to bytes if string
                    if isinstance(content, str):
                        content = content.encode('utf-8')
                    
                    # Apply offset and length
                    if read_offset < len(content):
                        end_pos = min(read_offset + read_length, len(content)) if read_length > 0 else len(content)
                        read_data = content[read_offset:end_pos]
    
    # If no data found, return empty
    if not read_data:
        read_data = b''
    
    # Build SMB2 header
    hdr = bytearray(64)
    hdr[0:4] = b'\xfeSMB'
    hdr[4:6] = b'\x40\x00'  # Structure size
    hdr[6:8] = b'\x00\x00'  # Credit charge
    hdr[8:12] = b'\x00\x00\x00\x00'  # STATUS_SUCCESS
    hdr[12:14] = b'\x08\x00'  # READ command
    hdr[14:16] = b'\x7f\x00'  # Credits granted
    hdr[16:20] = b'\x01\x00\x00\x00'  # Flags: Response
    hdr[20:24] = b'\x00\x00\x00\x00'  # Next command
    hdr[24:32] = message_id
    
    if len(request) >= 40:
        hdr[32:36] = request[32:36]  # Reserved/ProcessId
        hdr[36:40] = request[36:40]  # TreeId
    if len(request) >= 48:
        hdr[40:48] = request[40:48]  # SessionId
    
    # Read response body (16 bytes + 1 byte padding = 17 declared)
    data_offset = 80  # Header (64) + body (16) = 80
    body = bytearray(16)
    body[0:2] = b'\x11\x00'  # Structure size (17)
    body[2] = data_offset & 0xFF  # DataOffset
    body[3] = 0x00  # Reserved
    body[4:8] = len(read_data).to_bytes(4, 'little')  # DataLength
    body[8:12] = b'\x00\x00\x00\x00'  # DataRemaining
    body[12:16] = b'\x00\x00\x00\x00'  # Reserved2
    
    response = hdr + body + read_data
    
    # NetBIOS header
    nb = bytearray(4)
    nb[0] = 0x00
    length = len(response)
    nb[1] = (length >> 16) & 0xFF
    nb[2] = (length >> 8) & 0xFF
    nb[3] = length & 0xFF
    
    return bytes(nb + response)


def smb2_close_response(request: bytes, message_id: bytes) -> bytes:
    """Build SMB2 CLOSE response."""
    hdr = bytearray(64)
    hdr[0:4] = b'\xfeSMB'
    hdr[4:6] = b'\x40\x00'
    hdr[8:12] = b'\x00\x00\x00\x00'
    hdr[12:14] = b'\x06\x00'  # CLOSE
    hdr[14:16] = b'\x01\x00'
    hdr[16:20] = b'\x01\x00\x00\x00'
    hdr[24:32] = message_id
    if len(request) >= 48:
        hdr[40:48] = request[40:48]
    
    body = bytearray(60)
    body[0:2] = b'\x3c\x00'  # Structure size (60)
    body[2:4] = b'\x00\x00'  # Flags
    
    response = hdr + body
    nb = bytearray(4)
    nb[0] = 0x00
    length = len(response)
    nb[1] = (length >> 16) & 0xFF
    nb[2] = (length >> 8) & 0xFF
    nb[3] = length & 0xFF
    
    return bytes(nb + response)


def smb2_write_response(request: bytes, message_id: bytes, session) -> bytes:
    """Build SMB2 WRITE response and process DCE/RPC requests."""
    # Extract write data to check for DCE/RPC
    try:
        # SMB2 Write request: offset 64 (header) + 48 (write body before data)
        if len(request) > 68:
            data_offset = request[68] | (request[69] << 8)
            data_length = request[70] | (request[71] << 8) | (request[72] << 16) | (request[73] << 24)
            write_data = request[data_offset:data_offset + data_length] if data_offset else b''
            
            # Check for DCE/RPC Bind request (packet type 11)
            if len(write_data) > 2 and write_data[2] == 11:  # Bind
                # Store that we need to send bind_ack on next read
                if not hasattr(session, 'dcerpc_state'):
                    session.dcerpc_state = {}
                session.dcerpc_state['pending'] = 'bind_ack'
                session.dcerpc_state['call_id'] = write_data[12:16] if len(write_data) > 15 else b'\x01\x00\x00\x00'
            elif len(write_data) > 2 and write_data[2] == 0:  # Request
                # DCE/RPC Request - likely NetShareEnumAll
                if not hasattr(session, 'dcerpc_state'):
                    session.dcerpc_state = {}
                session.dcerpc_state['pending'] = 'share_enum'
                session.dcerpc_state['call_id'] = write_data[12:16] if len(write_data) > 15 else b'\x01\x00\x00\x00'
    except:
        pass
    
    # Build write response
    hdr = bytearray(64)
    hdr[0:4] = b'\xfeSMB'
    hdr[4:6] = b'\x40\x00'
    hdr[8:12] = b'\x00\x00\x00\x00'  # STATUS_SUCCESS
    hdr[12:14] = b'\x09\x00'  # WRITE
    hdr[14:16] = b'\x01\x00'
    hdr[16:20] = b'\x01\x00\x00\x00'
    hdr[24:32] = message_id
    if len(request) >= 48:
        hdr[40:48] = request[40:48]
    if len(request) >= 40:
        hdr[36:40] = request[36:40]
    
    # Write response body
    body = bytearray(16)
    body[0:2] = b'\x11\x00'  # Structure size (17)
    body[2:4] = b'\x00\x00'  # Reserved
    # Count - echo back what was written
    try:
        count = request[70] | (request[71] << 8) | (request[72] << 16) | (request[73] << 24)
        body[4:8] = bytes([count & 0xFF, (count >> 8) & 0xFF, (count >> 16) & 0xFF, (count >> 24) & 0xFF])
    except:
        body[4:8] = b'\x00\x00\x00\x00'
    body[8:12] = b'\x00\x00\x00\x00'  # Remaining
    body[12:16] = b'\x00\x00\x00\x00'  # WriteChannelInfoOffset/Length
    
    response = hdr + body
    nb = bytearray(4)
    nb[0] = 0x00
    length = len(response)
    nb[1] = (length >> 16) & 0xFF
    nb[2] = (length >> 8) & 0xFF
    nb[3] = length & 0xFF
    
    return bytes(nb + response)


def build_dcerpc_bind_ack(call_id: bytes) -> bytes:
    """Build DCE/RPC Bind Ack response for SRVSVC."""
    # NDR Transfer Syntax UUID: 8a885d04-1ceb-11c9-9fe8-08002b104860 version 2.0
    transfer_syntax = bytes([
        0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
        0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
        0x02, 0x00, 0x00, 0x00  # Version 2.0
    ])
    
    # Secondary address (pipe name)
    sec_addr = b'\\PIPE\\srvsvc\x00'
    sec_addr_len = len(sec_addr)
    # Pad to align to 4-byte boundary
    pad_len = (4 - ((2 + sec_addr_len) % 4)) % 4
    
    # Build bind_ack body
    body = bytearray()
    body.extend(b'\xb8\x10')  # Max xmit frag = 4280
    body.extend(b'\xb8\x10')  # Max recv frag = 4280
    body.extend(b'\x01\x00\x00\x00')  # Assoc group = 1
    body.extend(bytes([sec_addr_len & 0xFF, (sec_addr_len >> 8) & 0xFF]))  # Secondary addr len
    body.extend(sec_addr)  # Secondary address
    body.extend(b'\x00' * pad_len)  # Padding
    
    # Result list - 1 context, accepted
    body.extend(b'\x01\x00\x00\x00')  # Num results = 1 (with reserved/alignment)
    body.extend(b'\x00\x00')  # Result: acceptance (0)
    body.extend(b'\x00\x00')  # Reason: not specified
    body.extend(transfer_syntax)  # Transfer syntax (20 bytes)
    
    # Build DCE/RPC header (16 bytes)
    frag_length = 16 + len(body)
    header = bytearray(16)
    header[0] = 0x05  # Version 5
    header[1] = 0x00  # Version minor
    header[2] = 0x0c  # Packet type: bind_ack (12)
    header[3] = 0x03  # Flags: PFC_FIRST_FRAG | PFC_LAST_FRAG
    header[4:8] = b'\x10\x00\x00\x00'  # Data representation (little-endian, ASCII, IEEE float)
    header[8:10] = frag_length.to_bytes(2, 'little')  # Fragment length
    header[10:12] = b'\x00\x00'  # Auth length
    header[12:16] = call_id  # Call ID
    
    return bytes(header + body)


def build_dcerpc_share_enum_response(call_id: bytes) -> bytes:
    """Build DCE/RPC response with fake share list for NetShareEnumAll (opnum 15)."""
    # Fake shares to display
    shares = [
        ("ADMIN$", "Remote Admin", 0x80000000),  # STYPE_DISKTREE_HIDDEN
        ("C$", "Default share", 0x80000000),     # STYPE_DISKTREE_HIDDEN
        ("IPC$", "Remote IPC", 0x80000003),      # STYPE_IPC_HIDDEN
        ("Documents", "Shared Documents", 0x00000000),  # STYPE_DISKTREE
        ("Backup", "Backup Files", 0x00000000),  # STYPE_DISKTREE
    ]
    
    ndr = bytearray()

    ndr.extend(b'\x01\x00\x00\x00')
    
    # InfoStruct.ShareInfo.Level1 switch (DWORD) = 1
    ndr.extend(b'\x01\x00\x00\x00')
    
    # Referent ID for Level1 container pointer
    ndr.extend(b'\x00\x00\x02\x00')
    
    # SHARE_INFO_1_CONTAINER
    # EntriesRead (DWORD)
    ndr.extend(len(shares).to_bytes(4, 'little'))
    
    # Referent ID for Buffer pointer
    ndr.extend(b'\x04\x00\x02\x00')
    
    # Max count for conformant array
    ndr.extend(len(shares).to_bytes(4, 'little'))
    
    # Array of SHARE_INFO_1 structures (fixed parts)
    referent_id = 0x00020008
    for name, comment, stype in shares:
        # shi1_netname referent ID
        ndr.extend(referent_id.to_bytes(4, 'little'))
        referent_id += 4
        # shi1_type
        ndr.extend(stype.to_bytes(4, 'little'))
        # shi1_remark referent ID
        ndr.extend(referent_id.to_bytes(4, 'little'))
        referent_id += 4
    
    # Now the conformant varying strings for each share
    for name, comment, stype in shares:
        # Share name (conformant varying string)
        name_chars = len(name) + 1  # Include null terminator char count
        ndr.extend(name_chars.to_bytes(4, 'little'))  # MaxCount
        ndr.extend(b'\x00\x00\x00\x00')  # Offset
        ndr.extend(name_chars.to_bytes(4, 'little'))  # ActualCount
        name_utf16 = name.encode('utf-16-le') + b'\x00\x00'
        ndr.extend(name_utf16)
        # Pad to 4-byte boundary
        pad = (4 - (len(name_utf16) % 4)) % 4
        if pad:
            ndr.extend(b'\x00' * pad)
        
        # Comment (conformant varying string)
        comment_chars = len(comment) + 1
        ndr.extend(comment_chars.to_bytes(4, 'little'))  # MaxCount
        ndr.extend(b'\x00\x00\x00\x00')  # Offset
        ndr.extend(comment_chars.to_bytes(4, 'little'))  # ActualCount
        comment_utf16 = comment.encode('utf-16-le') + b'\x00\x00'
        ndr.extend(comment_utf16)
        # Pad to 4-byte boundary
        pad = (4 - (len(comment_utf16) % 4)) % 4
        if pad:
            ndr.extend(b'\x00' * pad)
    
    # TotalEntries (DWORD)
    ndr.extend(len(shares).to_bytes(4, 'little'))
    
    # ResumeHandle pointer (NULL = 0)
    ndr.extend(b'\x00\x00\x00\x00')
    
    # Return code (WERROR = WERR_OK = 0)
    ndr.extend(b'\x00\x00\x00\x00')
    
    # Build DCE/RPC response header (24 bytes)
    frag_length = 24 + len(ndr)
    header = bytearray(24)
    header[0] = 0x05  # Version 5
    header[1] = 0x00  # Version minor
    header[2] = 0x02  # Packet type: response (2)
    header[3] = 0x03  # Flags: PFC_FIRST_FRAG | PFC_LAST_FRAG
    header[4:8] = b'\x10\x00\x00\x00'  # Data representation (little-endian)
    header[8:10] = frag_length.to_bytes(2, 'little')  # Fragment length
    header[10:12] = b'\x00\x00'  # Auth length
    header[12:16] = call_id  # Call ID
    header[16:20] = len(ndr).to_bytes(4, 'little')  # Alloc hint
    header[20:22] = b'\x00\x00'  # Context ID
    header[22] = 0x00  # Cancel count
    header[23] = 0x00  # Reserved
    
    return bytes(header + ndr)


def build_ntlm_type2() -> bytes:
    """Build NTLM Type 2 (Challenge) message with target info for NTLMv2."""
    # Target name (NetBIOS domain name)
    target_name = "WORKGROUP".encode('utf-16-le')
    dns_domain = "workgroup".encode('utf-16-le')
    dns_computer = "honeypot".encode('utf-16-le')
    nb_computer = "HONEYPOT".encode('utf-16-le')
    
    # Build AV_PAIR list (target info)
    target_info = bytearray()
    
    # MsvAvNbDomainName (0x0002)
    target_info.extend(b'\x02\x00')  # AvId
    target_info.extend(bytes([len(target_name) & 0xFF, (len(target_name) >> 8) & 0xFF]))  # AvLen
    target_info.extend(target_name)
    
    # MsvAvNbComputerName (0x0001)
    target_info.extend(b'\x01\x00')
    target_info.extend(bytes([len(nb_computer) & 0xFF, (len(nb_computer) >> 8) & 0xFF]))
    target_info.extend(nb_computer)
    
    # MsvAvDnsDomainName (0x0004)
    target_info.extend(b'\x04\x00')
    target_info.extend(bytes([len(dns_domain) & 0xFF, (len(dns_domain) >> 8) & 0xFF]))
    target_info.extend(dns_domain)
    
    # MsvAvDnsComputerName (0x0003)
    target_info.extend(b'\x03\x00')
    target_info.extend(bytes([len(dns_computer) & 0xFF, (len(dns_computer) >> 8) & 0xFF]))
    target_info.extend(dns_computer)
    
    # MsvAvTimestamp (0x0007) - 8 bytes, Windows FILETIME
    target_info.extend(b'\x07\x00')
    target_info.extend(b'\x08\x00')  # Length = 8
    # Current time as Windows FILETIME (100ns intervals since 1601)
    import time
    filetime = int((time.time() + 11644473600) * 10000000)
    target_info.extend(filetime.to_bytes(8, 'little'))
    
    # MsvAvEOL (0x0000)
    target_info.extend(b'\x00\x00\x00\x00')
    
    # Calculate offsets
    # NTLM Type 2 header is 56 bytes (without version)
    # With version it's 56 + 8 = 64 bytes
    # Target name follows header
    # Target info follows target name
    
    base_offset = 56  # Offset where payload starts (after fixed header)
    target_name_offset = base_offset
    target_info_offset = target_name_offset + len(target_name)
    
    # Build NTLM Type 2 message
    ntlm = bytearray()
    ntlm.extend(b'NTLMSSP\x00')  # Signature (0-7)
    ntlm.extend(b'\x02\x00\x00\x00')  # Type 2 (8-11)
    
    # Target name fields (12-19)
    ntlm.extend(bytes([len(target_name) & 0xFF, (len(target_name) >> 8) & 0xFF]))  # Len
    ntlm.extend(bytes([len(target_name) & 0xFF, (len(target_name) >> 8) & 0xFF]))  # MaxLen
    ntlm.extend(bytes([target_name_offset & 0xFF, (target_name_offset >> 8) & 0xFF, 0, 0]))  # Offset
    
    flags = 0xe28a8a15  
    ntlm.extend(flags.to_bytes(4, 'little'))
    
    # Server challenge (24-31)
    challenge = os.urandom(8)
    ntlm.extend(challenge)
    
    # Reserved (32-39)
    ntlm.extend(b'\x00' * 8)
    
    # Target info fields (40-47)
    ntlm.extend(bytes([len(target_info) & 0xFF, (len(target_info) >> 8) & 0xFF]))  # Len
    ntlm.extend(bytes([len(target_info) & 0xFF, (len(target_info) >> 8) & 0xFF]))  # MaxLen
    ntlm.extend(bytes([target_info_offset & 0xFF, (target_info_offset >> 8) & 0xFF, 0, 0]))  # Offset
    
    # Version (48-55) - Windows 6.1 (Windows 7/2008 R2)
    ntlm.extend(b'\x06\x01\x00\x00')  # Major.Minor = 6.1
    ntlm.extend(b'\x00\x00\x00\x0f')  # Build + Revision (NTLMSSP_REVISION_W2K3)
    
    # Payload: target name + target info
    ntlm.extend(target_name)
    ntlm.extend(target_info)
    
    # Wrap in SPNEGO negTokenTarg
    return build_spnego_negtokentarg(bytes(ntlm))


def build_spnego_negtokentarg(ntlm_token: bytes) -> bytes:
    """Wrap NTLM token in SPNEGO negTokenTarg structure (RFC 4178)."""

    # NTLMSSP OID: 1.3.6.1.4.1.311.2.2.10
    ntlmssp_oid = bytes([0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a])
    
    # Build negState [0] = accept-incomplete (1)
    neg_state = bytearray([0xa0, 0x03, 0x0a, 0x01, 0x01])
    
    # Build supportedMech [1] = NTLMSSP OID
    supported_mech = bytearray([0xa1])
    supported_mech.extend(asn1_length(len(ntlmssp_oid)))
    supported_mech.extend(ntlmssp_oid)
    
    # Build responseToken [2] = OCTET STRING containing NTLM token
    response_token_inner = bytearray([0x04])  # OCTET STRING tag
    response_token_inner.extend(asn1_length(len(ntlm_token)))
    response_token_inner.extend(ntlm_token)
    
    response_token = bytearray([0xa2])  # Context tag [2]
    response_token.extend(asn1_length(len(response_token_inner)))
    response_token.extend(response_token_inner)
    
    # Combine into inner SEQUENCE content
    inner_content = bytes(neg_state) + bytes(supported_mech) + bytes(response_token)
    
    # Build the SEQUENCE
    sequence = bytearray([0x30])  # SEQUENCE tag
    sequence.extend(asn1_length(len(inner_content)))
    sequence.extend(inner_content)
    
    # Wrap in negTokenTarg context [1]
    result = bytearray([0xa1])  # Context tag [1] for negTokenTarg
    result.extend(asn1_length(len(sequence)))
    result.extend(sequence)
    
    return bytes(result)


def asn1_length(length: int) -> bytes:
    """Encode ASN.1 length."""
    if length < 0x80:
        return bytes([length])
    elif length <= 0xFF:
        return bytes([0x81, length])
    elif length <= 0xFFFF:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    else:
        return bytes([0x83, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])


# -- NOTE: Old duplicate SMB code removed --


def start_listener(port: int, handler, service_name: str):
    """Start a TCP listener on given port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', port))
        sock.listen(5)
        sock.settimeout(1.0)
        
        with state.lock:
            state.listeners.append(sock)
        
        log_event("INFO", service_name, "0.0.0.0", f"Listening on port {port}")
        
        while state.running:
            try:
                conn, addr = sock.accept()
                conn.settimeout(60)
                threading.Thread(target=handler, args=(conn, addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception as e:
                if state.running:
                    log_event("WARNING", service_name, "0.0.0.0", f"Accept error: {e}")
    except Exception as e:
        log_event("CRITICAL", service_name, "0.0.0.0", f"Failed to start: {e}")
    finally:
        try:
            sock.close()
        except:
            pass

# ============================================================================
# GUI APPLICATION
# ============================================================================

class HoneypotGUI:
    """Beautiful modern UI for Honey POT honeypot."""
    
    # Vibrant cyberpunk color scheme
    COLORS = {
        "bg_main": "#0a0e14",          # Deep dark background
        "bg_sidebar": "#0d1420",        # Slightly lighter sidebar
        "bg_card": "#141c28",           # Card background
        "bg_card_hover": "#1a2535",     # Card hover state
        "border_dark": "#1e2a3a",       # Subtle borders
        "border_glow": "#00d4ff",       # Glowing border accent
        "accent_cyan": "#00ffff",       # Bright cyan
        "accent_green": "#00ff88",      # Neon green
        "accent_orange": "#ff9f43",     # Vibrant orange
        "accent_red": "#ff5555",        # Bright red
        "accent_blue": "#0099ff",       # Electric blue
        "accent_purple": "#bd93f9",     # Soft purple
        "accent_pink": "#ff79c6",       # Hot pink
        "accent_yellow": "#ffeb3b",     # Bright yellow
        "text_primary": "#ffffff",      # Pure white
        "text_secondary": "#a0b4c8",    # Light blue-gray
        "text_muted": "#5c7080",        # Muted blue-gray
        "gradient_start": "#0099ff",    # Gradient blue
        "gradient_end": "#00ffff",      # Gradient cyan
    }
    
    def __init__(self):
        self.root = ttk.Window(themename="cyborg")
        self.root.title("Honey POT - Blue Team Honeypot Command Center")
        self.root.geometry("1600x950")
        self.root.minsize(1400, 800)
        
        # Animation state
        self.pulse_state = 0
        self.threat_level = 0
        
        self.create_ui()
        self.start_services()
        self.update_loop()
        self.animate_pulse()
        
    def create_ui(self):
        """Create the modern UI layout."""
        # Configure root window background
        self.root.configure(bg=self.COLORS["bg_main"])
        
        # Main container with dark background
        self.main_frame = tk.Frame(self.root, bg=self.COLORS["bg_main"])
        self.main_frame.pack(fill=BOTH, expand=YES)
        
        # Left sidebar
        self.create_sidebar()
        
        # Main content area
        self.content_frame = tk.Frame(self.main_frame, bg=self.COLORS["bg_main"])
        self.content_frame.pack(side=LEFT, fill=BOTH, expand=YES, padx=15, pady=15)
        
        # Top header with title and status
        self.create_header()
        
        # Stats cards row
        self.create_stats_cards()
        
        # Main tabbed content
        self.create_main_content()
    
    def create_sidebar(self):
        """Create the sleek sidebar navigation with cyberpunk styling."""
        # Sidebar with gradient effect using canvas
        sidebar_container = tk.Frame(self.main_frame, bg=self.COLORS["bg_sidebar"], width=280)
        sidebar_container.pack(side=LEFT, fill=Y)
        sidebar_container.pack_propagate(False)
        
        # Add glowing left border
        glow_border = tk.Frame(sidebar_container, bg=self.COLORS["accent_cyan"], width=3)
        glow_border.pack(side=LEFT, fill=Y)
        
        sidebar = tk.Frame(sidebar_container, bg=self.COLORS["bg_sidebar"])
        sidebar.pack(side=LEFT, fill=BOTH, expand=YES)
        
        # ═══════════════ LOGO SECTION ═══════════════
        logo_frame = tk.Frame(sidebar, bg=self.COLORS["bg_sidebar"])
        logo_frame.pack(fill=X, pady=20, padx=15)
        
        # Logo with glow effect using a canvas
        logo_canvas = tk.Canvas(logo_frame, width=90, height=90, 
                               bg=self.COLORS["bg_sidebar"], highlightthickness=0)
        logo_canvas.pack()
        
        # Draw glowing circle behind honey emoji
        logo_canvas.create_oval(5, 5, 85, 85, fill="#2a1f00", outline=self.COLORS["accent_orange"], width=2)
        logo_canvas.create_text(45, 45, text="🍯", font=("Segoe UI Emoji", 38))
        
        title_label = tk.Label(logo_frame, text="HONEY POT",
                               font=("Segoe UI", 20, "bold"),
                               fg=self.COLORS["accent_orange"],
                               bg=self.COLORS["bg_sidebar"])
        title_label.pack(pady=(10, 0))
        
        subtitle = tk.Label(logo_frame, text="▸ Command Center ◂",
                            font=("Segoe UI", 10),
                            fg=self.COLORS["accent_cyan"],
                            bg=self.COLORS["bg_sidebar"])
        subtitle.pack()
        
        # ═══════════════ STATUS PANEL ═══════════════
        self.create_sidebar_panel(sidebar, "SYSTEM STATUS", [
            self.create_status_indicator
        ])
        
        # ═══════════════ SERVICES PANEL ═══════════════
        services_panel = tk.Frame(sidebar, bg=self.COLORS["bg_card"], 
                                 highlightbackground=self.COLORS["border_dark"],
                                 highlightthickness=1)
        services_panel.pack(fill=X, padx=15, pady=8)
        
        # Panel header
        header = tk.Frame(services_panel, bg=self.COLORS["bg_card"])
        header.pack(fill=X, padx=12, pady=(10, 5))
        tk.Label(header, text="◆ ACTIVE SERVICES", font=("Segoe UI", 9, "bold"),
                fg=self.COLORS["accent_cyan"], bg=self.COLORS["bg_card"]).pack(anchor=W)
        
        self.service_indicators = {}
        services = [
            ("SSH", CONFIG["SSH_PORT"], "🔐", self.COLORS["accent_green"]),
            ("Telnet", CONFIG["TELNET_PORT"], "📟", self.COLORS["accent_cyan"]),
            ("FTP", CONFIG["FTP_PORT"], "📁", self.COLORS["accent_blue"]),
            ("SMB", CONFIG["SMB_PORT"], "🔗", self.COLORS["accent_orange"]),
        ]
        
        for name, port, icon, color in services:
            svc_frame = tk.Frame(services_panel, bg=self.COLORS["bg_card"])
            svc_frame.pack(fill=X, padx=12, pady=3)
            
            # Left side with icon and name
            left = tk.Frame(svc_frame, bg=self.COLORS["bg_card"])
            left.pack(side=LEFT)
            
            tk.Label(left, text=icon, font=("Segoe UI Emoji", 11),
                    bg=self.COLORS["bg_card"]).pack(side=LEFT)
            tk.Label(left, text=f" {name}", font=("Segoe UI", 10),
                    fg=self.COLORS["text_primary"],
                    bg=self.COLORS["bg_card"]).pack(side=LEFT)
            
            # Right side with status dot and port
            right = tk.Frame(svc_frame, bg=self.COLORS["bg_card"])
            right.pack(side=RIGHT)
            
            indicator = tk.Label(right, text="●", font=("Segoe UI", 10),
                                fg=color, bg=self.COLORS["bg_card"])
            indicator.pack(side=LEFT)
            self.service_indicators[name] = indicator
            
            tk.Label(right, text=f":{port}", font=("Consolas", 9),
                    fg=self.COLORS["text_muted"],
                    bg=self.COLORS["bg_card"]).pack(side=LEFT, padx=(3, 0))
        
        # Bottom padding
        tk.Frame(services_panel, height=8, bg=self.COLORS["bg_card"]).pack()
        
        # ═══════════════ THREAT LEVEL PANEL ═══════════════
        threat_panel = tk.Frame(sidebar, bg=self.COLORS["bg_card"],
                               highlightbackground=self.COLORS["border_dark"],
                               highlightthickness=1)
        threat_panel.pack(fill=X, padx=15, pady=8)
        
        # Panel header
        header = tk.Frame(threat_panel, bg=self.COLORS["bg_card"])
        header.pack(fill=X, padx=12, pady=(10, 5))
        tk.Label(header, text="◆ THREAT LEVEL", font=("Segoe UI", 9, "bold"),
                fg=self.COLORS["accent_red"], bg=self.COLORS["bg_card"]).pack(anchor=W)
        
        # Threat meter canvas with gradient
        meter_frame = tk.Frame(threat_panel, bg=self.COLORS["bg_card"])
        meter_frame.pack(fill=X, padx=12, pady=5)
        
        self.threat_canvas = tk.Canvas(meter_frame, height=24, 
                                       bg=self.COLORS["bg_main"],
                                       highlightthickness=1,
                                       highlightbackground=self.COLORS["border_dark"])
        self.threat_canvas.pack(fill=X)
        
        # Threat level text
        self.threat_label = tk.Label(threat_panel, text="LOW (0%)",
                                     fg=self.COLORS["accent_green"],
                                     bg=self.COLORS["bg_card"],
                                     font=("Segoe UI", 11, "bold"))
        self.threat_label.pack(pady=(5, 10))
        
        # Draw initial threat meter
        self.update_threat_meter()
        
        # ═══════════════ ACTION BUTTONS ═══════════════
        bottom_frame = tk.Frame(sidebar, bg=self.COLORS["bg_sidebar"])
        bottom_frame.pack(side=BOTTOM, fill=X, padx=15, pady=20)
        
        # Export button with glow effect
        export_btn = ttk.Button(bottom_frame, text="📊 Export Report",
                               bootstyle="info",
                               command=self.export_report)
        export_btn.pack(fill=X, pady=3)
        
        # Clear logs button
        clear_btn = ttk.Button(bottom_frame, text="🗑️ Clear Logs",
                              bootstyle="secondary",
                              command=self.clear_logs)
        clear_btn.pack(fill=X, pady=3)
        
        # Shutdown button - prominent red
        shutdown_btn = ttk.Button(bottom_frame, text="⚠️ Shutdown",
                                 bootstyle="danger",
                                 command=self.shutdown)
        shutdown_btn.pack(fill=X, pady=(10, 0))
    
    def create_sidebar_panel(self, parent, title, content_creators):
        """Create a styled sidebar panel with title and content."""
        panel = tk.Frame(parent, bg=self.COLORS["bg_card"],
                        highlightbackground=self.COLORS["border_dark"],
                        highlightthickness=1)
        panel.pack(fill=X, padx=15, pady=8)
        
        # Panel header with accent
        header = tk.Frame(panel, bg=self.COLORS["bg_card"])
        header.pack(fill=X, padx=12, pady=(10, 5))
        
        tk.Label(header, text=f"◆ {title}", font=("Segoe UI", 9, "bold"),
                fg=self.COLORS["accent_cyan"], bg=self.COLORS["bg_card"]).pack(anchor=W)
        
        # Content area
        content = tk.Frame(panel, bg=self.COLORS["bg_card"])
        content.pack(fill=X, padx=12, pady=(0, 10))
        
        for creator in content_creators:
            creator(content)
        
        return panel
    
    def create_status_indicator(self, parent):
        """Create the animated status indicator."""
        status_row = tk.Frame(parent, bg=self.COLORS["bg_card"])
        status_row.pack(fill=X, pady=5)
        
        # Pulsing dot
        self.status_dot = tk.Label(status_row, text="●", 
                                   fg=self.COLORS["accent_green"],
                                   font=("Segoe UI", 16),
                                   bg=self.COLORS["bg_card"])
        self.status_dot.pack(side=LEFT)
        
        self.status_text = tk.Label(status_row, text="ALL SYSTEMS ACTIVE",
                                    fg=self.COLORS["accent_green"],
                                    font=("Segoe UI", 10, "bold"),
                                    bg=self.COLORS["bg_card"])
        self.status_text.pack(side=LEFT, padx=8)
    
    def create_header(self):
        """Create the top header with title and quick stats."""
        header = tk.Frame(self.content_frame, bg=self.COLORS["bg_main"])
        header.pack(fill=X, pady=(0, 15))
        
        # Left side - Title with gradient text effect
        title_frame = tk.Frame(header, bg=self.COLORS["bg_main"])
        title_frame.pack(side=LEFT)
        
        tk.Label(title_frame, text="Dashboard",
                font=("Segoe UI", 24, "bold"),
                fg=self.COLORS["text_primary"],
                bg=self.COLORS["bg_main"]).pack(anchor=W)
        tk.Label(title_frame, text="Real-time honeypot monitoring and threat intelligence",
                font=("Segoe UI", 10),
                fg=self.COLORS["text_secondary"],
                bg=self.COLORS["bg_main"]).pack(anchor=W)
        
        # Right side - Time display with accent
        status_frame = tk.Frame(header, bg=self.COLORS["bg_main"])
        status_frame.pack(side=RIGHT)
        
        # Time display with cyan accent
        self.time_label = tk.Label(status_frame, 
                                   text=datetime.datetime.now().strftime("%H:%M:%S"),
                                   font=("Consolas", 28, "bold"),
                                   fg=self.COLORS["accent_cyan"],
                                   bg=self.COLORS["bg_main"])
        self.time_label.pack(anchor=E)
        
        self.date_label = tk.Label(status_frame,
                                   text=datetime.datetime.now().strftime("%B %d, %Y"),
                                   font=("Segoe UI", 11),
                                   fg=self.COLORS["text_secondary"],
                                   bg=self.COLORS["bg_main"])
        self.date_label.pack(anchor=E)
    
    def create_stats_cards(self):
        """Create the statistics cards row with glowing effects."""
        cards_frame = tk.Frame(self.content_frame, bg=self.COLORS["bg_main"])
        cards_frame.pack(fill=X, pady=(0, 15))
        
        # Configure grid columns to expand equally
        for i in range(4):
            cards_frame.columnconfigure(i, weight=1)
        
        self.stat_cards = {}
        
        # Card data: (title, icon, initial_value, color_key)
        cards_data = [
            ("Total Events", "📊", "0", "accent_blue"),
            ("Credentials", "🔐", "0", "accent_red"),
            ("Active Sessions", "👥", "0", "accent_green"),
            ("Attacks Today", "⚔️", "0", "accent_orange"),
        ]
        
        for i, (title, icon, value, color) in enumerate(cards_data):
            card = self.create_stat_card(cards_frame, title, icon, value, 
                                        self.COLORS[color])
            card.grid(row=0, column=i, sticky="nsew", padx=8)
            self.stat_cards[title] = card
    
    def create_stat_card(self, parent, title, icon, value, accent_color):
        """Create a single statistic card with glowing border effect."""
        # Outer border frame with accent color
        card_outer = tk.Frame(parent, bg=accent_color, padx=2, pady=2)
        card_outer.columnconfigure(0, weight=1)
        card_outer.rowconfigure(0, weight=1)
        
        # Inner card with dark background
        card = tk.Frame(card_outer, bg=self.COLORS["bg_card"], padx=15, pady=15)
        card.grid(row=0, column=0, sticky="nsew")
        
        # Header row with icon
        header = tk.Frame(card, bg=self.COLORS["bg_card"])
        header.pack(fill=X)
        
        tk.Label(header, text=icon, font=("Segoe UI Emoji", 18),
                bg=self.COLORS["bg_card"]).pack(side=LEFT)
        
        tk.Label(header, text=title, font=("Segoe UI", 11),
                fg=self.COLORS["text_secondary"],
                bg=self.COLORS["bg_card"]).pack(side=LEFT, padx=8)
        
        # Value with accent color - large and prominent
        value_label = tk.Label(card, text=value, 
                              fg=accent_color,
                              bg=self.COLORS["bg_card"],
                              font=("Segoe UI", 38, "bold"))
        value_label.pack(anchor=W, pady=(12, 5))
        
        # Store reference for updates
        card_outer.value_label = value_label
        
        # Live indicator with pulsing dot
        trend_frame = tk.Frame(card, bg=self.COLORS["bg_card"])
        trend_frame.pack(anchor=W)
        
        tk.Label(trend_frame, text="●", font=("Segoe UI", 8),
                fg=self.COLORS["accent_green"],
                bg=self.COLORS["bg_card"]).pack(side=LEFT)
        tk.Label(trend_frame, text=" LIVE", font=("Segoe UI", 9, "bold"),
                fg=self.COLORS["accent_green"],
                bg=self.COLORS["bg_card"]).pack(side=LEFT)
        
        return card_outer
    
    def create_main_content(self):
        """Create the main tabbed content area."""
        # Initialize service log widgets dictionaries
        self.service_logs = {}
        self.service_tables = {}
        
        # Create notebook with modern styling
        self.notebook = ttk.Notebook(self.content_frame, bootstyle="info")
        self.notebook.pack(fill=BOTH, expand=YES)
        
        # Create tabs
        self.create_monitoring_tab()
        self.create_credentials_tab()
        self.create_sessions_tab()
        self.create_ssh_tab()
        self.create_telnet_tab()
        self.create_ftp_tab()
        self.create_smb_tab()
    
    def create_monitoring_tab(self):
        """Create the main monitoring tab with real-time logs."""
        tab = tk.Frame(self.notebook, bg=self.COLORS["bg_main"])
        self.notebook.add(tab, text="  📊 Live Monitor  ")
        
        # Split into two columns
        tab.columnconfigure(0, weight=3)
        tab.columnconfigure(1, weight=1)
        tab.rowconfigure(0, weight=1)
        
        # Left - Log area with border
        log_container = tk.Frame(tab, bg=self.COLORS["bg_card"],
                                highlightbackground=self.COLORS["accent_cyan"],
                                highlightthickness=1)
        log_container.grid(row=0, column=0, sticky="nsew", padx=(10, 10), pady=10)
        
        # Log header with styled background
        log_header = tk.Frame(log_container, bg=self.COLORS["bg_card"])
        log_header.pack(fill=X, padx=12, pady=12)
        
        # Live indicator with pulsing red dot
        header_left = tk.Frame(log_header, bg=self.COLORS["bg_card"])
        header_left.pack(side=LEFT)
        
        self.log_pulse = tk.Label(header_left, text="●", font=("Segoe UI", 12),
                                  fg=self.COLORS["accent_red"],
                                  bg=self.COLORS["bg_card"])
        self.log_pulse.pack(side=LEFT)
        
        tk.Label(header_left, text=" Live Event Stream",
                font=("Segoe UI", 13, "bold"),
                fg=self.COLORS["text_primary"],
                bg=self.COLORS["bg_card"]).pack(side=LEFT)
        
        self.log_count_label = tk.Label(log_header, text="0 events",
                                        font=("Consolas", 10),
                                        fg=self.COLORS["accent_cyan"],
                                        bg=self.COLORS["bg_card"])
        self.log_count_label.pack(side=RIGHT)
        
        # Log text with custom styling
        log_frame = tk.Frame(log_container, bg=self.COLORS["bg_main"])
        log_frame.pack(fill=BOTH, expand=YES, padx=10, pady=(0, 10))
        
        self.log_text = ScrolledText(log_frame, height=25, autohide=True,
                                     bootstyle="dark")
        self.log_text.pack(fill=BOTH, expand=YES)
        
        # Configure text widget styling - darker with cyan accents
        self.log_text.text.configure(
            font=("Consolas", 10),
            background=self.COLORS["bg_main"],
            foreground=self.COLORS["text_primary"],
            insertbackground=self.COLORS["accent_cyan"],
            selectbackground=self.COLORS["accent_blue"],
            padx=12,
            pady=12,
            relief="flat",
            borderwidth=0,
        )
        
        # Configure tags for vibrant colors
        self.log_text.text.tag_configure("INFO", foreground=self.COLORS["accent_green"])
        self.log_text.text.tag_configure("WARNING", foreground=self.COLORS["accent_yellow"])
        self.log_text.text.tag_configure("CRITICAL", foreground=self.COLORS["accent_red"], 
                                         font=("Consolas", 10, "bold"))
        self.log_text.text.tag_configure("timestamp", foreground=self.COLORS["text_muted"])
        self.log_text.text.tag_configure("service", foreground=self.COLORS["accent_blue"])
        self.log_text.text.tag_configure("ip", foreground=self.COLORS["accent_purple"])
        
        # Right - Quick stats panel with border
        activity_frame = tk.Frame(tab, bg=self.COLORS["bg_card"],
                                 highlightbackground=self.COLORS["accent_orange"],
                                 highlightthickness=1)
        activity_frame.grid(row=0, column=1, sticky="nsew", padx=(0, 10), pady=10)
        
        # Panel header
        stats_header = tk.Frame(activity_frame, bg=self.COLORS["bg_card"])
        stats_header.pack(fill=X, padx=12, pady=12)
        
        tk.Label(stats_header, text="📈 Quick Stats",
                font=("Segoe UI", 12, "bold"),
                fg=self.COLORS["accent_orange"],
                bg=self.COLORS["bg_card"]).pack(anchor=W)
        
        # Mini stats with better styling
        self.mini_stats = {}
        mini_stats_data = [
            ("SSH Attempts", "🔐", "0", self.COLORS["accent_green"]),
            ("Telnet Attempts", "📟", "0", self.COLORS["accent_cyan"]),
            ("FTP Attempts", "📁", "0", self.COLORS["accent_blue"]),
            ("Passwords Captured", "🔑", "0", self.COLORS["accent_red"]),
        ]
        
        for label, icon, value, color in mini_stats_data:
            stat_row = tk.Frame(activity_frame, bg=self.COLORS["bg_card"])
            stat_row.pack(fill=X, padx=12, pady=6)
            
            tk.Label(stat_row, text=f"{icon} {label}",
                    fg=self.COLORS["text_secondary"],
                    bg=self.COLORS["bg_card"],
                    font=("Segoe UI", 10)).pack(side=LEFT)
            
            val_label = tk.Label(stat_row, text=value,
                                fg=color,
                                bg=self.COLORS["bg_card"],
                                font=("Segoe UI", 12, "bold"))
            val_label.pack(side=RIGHT)
            self.mini_stats[label] = val_label
    
    def create_credentials_tab(self):
        """Create the captured credentials tab with cyberpunk styling."""
        tab = tk.Frame(self.notebook, bg=self.COLORS["bg_main"])
        self.notebook.add(tab, text="  🔐 Credentials  ")
        
        # Header with glowing accent
        header = tk.Frame(tab, bg=self.COLORS["bg_main"])
        header.pack(fill=X, padx=15, pady=15)
        
        tk.Label(header, text="🔐 Captured Credentials",
                font=("Segoe UI", 16, "bold"),
                fg=self.COLORS["accent_red"],
                bg=self.COLORS["bg_main"]).pack(side=LEFT)
        
        self.creds_count = tk.Label(header, text="0 captured",
                                    fg=self.COLORS["accent_cyan"],
                                    bg=self.COLORS["bg_main"],
                                    font=("Consolas", 12, "bold"))
        self.creds_count.pack(side=RIGHT)
        
        # Create frame for table with border
        table_container = tk.Frame(tab, bg=self.COLORS["accent_red"], padx=1, pady=1)
        table_container.pack(fill=BOTH, expand=YES, padx=15, pady=(0, 15))
        
        table_frame = tk.Frame(table_container, bg=self.COLORS["bg_card"])
        table_frame.pack(fill=BOTH, expand=YES)
        
        # Column definitions
        columns = [
            {"text": "⏰ Timestamp", "stretch": False, "width": 160},
            {"text": "🌐 Source IP", "stretch": False, "width": 130},
            {"text": "📡 Port", "stretch": False, "width": 70},
            {"text": "🔌 Service", "stretch": False, "width": 90},
            {"text": "👤 Username", "stretch": True, "width": 140},
            {"text": "🔑 Password", "stretch": True, "width": 180},
            {"text": "📋 Type", "stretch": False, "width": 90},
        ]
        
        self.creds_table = Tableview(
            table_frame,
            coldata=columns,
            rowdata=[],
            paginated=True,
            searchable=True,
            bootstyle="danger",
            pagesize=15,
            height=20,
        )
        self.creds_table.pack(fill=BOTH, expand=YES, padx=5, pady=5)
    
    def create_sessions_tab(self):
        """Create the active sessions tab with cyberpunk styling."""
        tab = tk.Frame(self.notebook, bg=self.COLORS["bg_main"])
        self.notebook.add(tab, text="  👥 Sessions  ")
        
        # Header
        header = tk.Frame(tab, bg=self.COLORS["bg_main"])
        header.pack(fill=X, padx=15, pady=15)
        
        tk.Label(header, text="👥 Active Sessions",
                font=("Segoe UI", 16, "bold"),
                fg=self.COLORS["accent_green"],
                bg=self.COLORS["bg_main"]).pack(side=LEFT)
        
        self.sessions_count = tk.Label(header, text="0 active",
                                       fg=self.COLORS["accent_cyan"],
                                       bg=self.COLORS["bg_main"],
                                       font=("Consolas", 12, "bold"))
        self.sessions_count.pack(side=RIGHT)
        
        # Create frame for table with border
        table_container = tk.Frame(tab, bg=self.COLORS["accent_green"], padx=1, pady=1)
        table_container.pack(fill=BOTH, expand=YES, padx=15, pady=(0, 15))
        
        table_frame = tk.Frame(table_container, bg=self.COLORS["bg_card"])
        table_frame.pack(fill=BOTH, expand=YES)
        
        columns = [
            {"text": "🆔 Session ID", "stretch": False, "width": 220},
            {"text": "🌐 Source IP", "stretch": False, "width": 130},
            {"text": "📡 Port", "stretch": False, "width": 70},
            {"text": "🔌 Service", "stretch": False, "width": 90},
            {"text": "⏰ Start Time", "stretch": False, "width": 160},
            {"text": "👤 Username", "stretch": True, "width": 130},
            {"text": "👑 Elevated", "stretch": False, "width": 90},
        ]
        
        self.sessions_table = Tableview(
            table_frame,
            coldata=columns,
            rowdata=[],
            paginated=False,
            searchable=False,
            bootstyle="success",
            height=20,
        )
        self.sessions_table.pack(fill=BOTH, expand=YES, padx=5, pady=5)
    
    def create_service_tab(self, service_name: str, icon: str, color: str, description: str):
        """Create a service-specific tab with cyberpunk styling."""
        tab = tk.Frame(self.notebook, bg=self.COLORS["bg_main"])
        self.notebook.add(tab, text=f"  {icon} {service_name}  ")
        
        # Map color strings to actual colors
        color_map = {
            "success": self.COLORS["accent_green"],
            "info": self.COLORS["accent_cyan"],
            "primary": self.COLORS["accent_blue"],
            "warning": self.COLORS["accent_orange"],
            "secondary": self.COLORS["accent_purple"],
        }
        accent = color_map.get(color, self.COLORS["accent_cyan"])
        
        # Top info card with colored border
        info_container = tk.Frame(tab, bg=accent, padx=2, pady=2)
        info_container.pack(fill=X, padx=15, pady=15)
        
        info_card = tk.Frame(info_container, bg=self.COLORS["bg_card"], padx=20, pady=15)
        info_card.pack(fill=X)
        
        # Left side - icon and title
        info_left = tk.Frame(info_card, bg=self.COLORS["bg_card"])
        info_left.pack(side=LEFT)
        
        tk.Label(info_left, text=icon, font=("Segoe UI Emoji", 28),
                bg=self.COLORS["bg_card"]).pack(side=LEFT)
        
        title_frame = tk.Frame(info_left, bg=self.COLORS["bg_card"])
        title_frame.pack(side=LEFT, padx=15)
        
        tk.Label(title_frame, text=f"{service_name} Service",
                font=("Segoe UI", 18, "bold"),
                fg=accent,
                bg=self.COLORS["bg_card"]).pack(anchor=W)
        tk.Label(title_frame, text=description,
                font=("Segoe UI", 10),
                fg=self.COLORS["text_secondary"],
                bg=self.COLORS["bg_card"]).pack(anchor=W)
        
        # Stats row with pill-style badges
        stats_frame = tk.Frame(info_card, bg=self.COLORS["bg_card"])
        stats_frame.pack(side=RIGHT)
        
        self.service_tables[f"{service_name}_connections"] = self.create_stat_pill(
            stats_frame, "Connections", "0", self.COLORS["accent_blue"])
        
        self.service_tables[f"{service_name}_creds"] = self.create_stat_pill(
            stats_frame, "Credentials", "0", self.COLORS["accent_red"])
        
        self.service_tables[f"{service_name}_active"] = self.create_stat_pill(
            stats_frame, "Active", "0", self.COLORS["accent_green"])
        
        # Main content area
        content_frame = tk.Frame(tab, bg=self.COLORS["bg_main"])
        content_frame.pack(fill=BOTH, expand=YES, padx=15, pady=(0, 15))
        
        # Log frame with colored border
        log_outer = tk.Frame(content_frame, bg=accent, padx=1, pady=1)
        log_outer.pack(fill=BOTH, expand=YES, pady=(0, 10))
        
        log_container = tk.Frame(log_outer, bg=self.COLORS["bg_card"])
        log_container.pack(fill=BOTH, expand=YES)
        
        log_header = tk.Frame(log_container, bg=self.COLORS["bg_card"])
        log_header.pack(fill=X, padx=12, pady=10)
        
        tk.Label(log_header, text=f"📋 {service_name} Event Log",
                font=("Segoe UI", 12, "bold"),
                fg=accent,
                bg=self.COLORS["bg_card"]).pack(anchor=W)
        
        log_text = ScrolledText(log_container, height=12, autohide=True,
                               bootstyle="dark")
        log_text.pack(fill=BOTH, expand=YES, padx=10, pady=(0, 10))
        
        log_text.text.configure(
            font=("Consolas", 10),
            background=self.COLORS["bg_main"],
            foreground=self.COLORS["text_primary"],
            padx=12,
            pady=12,
        )
        
        # Configure tags with vibrant colors
        log_text.text.tag_configure("INFO", foreground=self.COLORS["accent_green"])
        log_text.text.tag_configure("WARNING", foreground=self.COLORS["accent_yellow"])
        log_text.text.tag_configure("CRITICAL", foreground=self.COLORS["accent_red"],
                                   font=("Consolas", 10, "bold"))
        log_text.text.tag_configure("timestamp", foreground=self.COLORS["text_muted"])
        
        self.service_logs[service_name] = log_text
        
        # Credentials frame with colored border
        creds_outer = tk.Frame(content_frame, bg=self.COLORS["accent_red"], padx=1, pady=1)
        creds_outer.pack(fill=X)
        
        creds_container = tk.Frame(creds_outer, bg=self.COLORS["bg_card"])
        creds_container.pack(fill=BOTH, expand=YES)
        
        creds_header = tk.Frame(creds_container, bg=self.COLORS["bg_card"])
        creds_header.pack(fill=X, padx=12, pady=10)
        
        tk.Label(creds_header, text=f"🔑 {service_name} Captured Credentials",
                font=("Segoe UI", 12, "bold"),
                fg=self.COLORS["accent_red"],
                bg=self.COLORS["bg_card"]).pack(anchor=W)
        
        columns = [
            {"text": "⏰ Timestamp", "stretch": False, "width": 150},
            {"text": "🌐 Source IP", "stretch": False, "width": 120},
            {"text": "👤 Username", "stretch": True, "width": 150},
            {"text": "🔑 Password", "stretch": True, "width": 200},
            {"text": "📋 Type", "stretch": False, "width": 80},
        ]
        
        creds_table = Tableview(
            creds_container,
            coldata=columns,
            rowdata=[],
            paginated=True,
            searchable=True,
            bootstyle="danger",
            pagesize=8,
            height=6,
        )
        creds_table.pack(fill=BOTH, expand=YES, padx=10, pady=(0, 10))
        
        self.service_tables[f"{service_name}_table"] = creds_table
    
    def create_stat_pill(self, parent, label, value, color):
        """Create a glowing pill-style stat badge."""
        pill = tk.Frame(parent, bg=self.COLORS["bg_card"])
        pill.pack(side=LEFT, padx=8)
        
        # Colored border around pill
        pill_inner = tk.Frame(pill, bg=color, padx=1, pady=1)
        pill_inner.pack()
        
        content = tk.Frame(pill_inner, bg=self.COLORS["bg_main"], padx=10, pady=5)
        content.pack()
        
        tk.Label(content, text=label,
                font=("Segoe UI", 9),
                fg=self.COLORS["text_muted"],
                bg=self.COLORS["bg_main"]).pack()
        
        val_label = tk.Label(content, text=value,
                            font=("Segoe UI", 14, "bold"),
                            fg=color,
                            bg=self.COLORS["bg_main"])
        val_label.pack()
        
        return val_label
    
    def create_ssh_tab(self):
        """Create SSH service tab."""
        self.create_service_tab("SSH", "🔐", "success",
            f"High Interaction Shell • Port {CONFIG['SSH_PORT']}")
    
    def create_telnet_tab(self):
        """Create Telnet service tab."""
        self.create_service_tab("Telnet", "📟", "success",
            f"High Interaction Shell • Port {CONFIG['TELNET_PORT']}")
    
    def create_ftp_tab(self):
        """Create FTP service tab."""
        self.create_service_tab("FTP", "📁", "info",
            f"Medium Interaction • Port {CONFIG['FTP_PORT']}")
    
    def create_smb_tab(self):
        """Create SMB service tab."""
        self.create_service_tab("SMB", "🔗", "warning",
            f"Tripwire Mode • Port {CONFIG['SMB_PORT']}")
    
    def update_threat_meter(self):
        """Update the threat level meter visualization based on actual threat indicators."""
        self.threat_canvas.delete("all")
        width = self.threat_canvas.winfo_width() or 200
        height = 20
        
        # Background with gradient effect
        self.threat_canvas.create_rectangle(0, 0, width, height,
                                           fill=self.COLORS["bg_main"], outline="")
        
        # Calculate threat level based on ACTUAL threat indicators
        threat = 0
        with state.lock:
            # Credential captures are serious threats (+15 each)
            cred_count = len(state.credentials)
            threat += cred_count * 15
            
            # Sudo/privilege escalation attempts are critical (+25 each)
            sudo_count = sum(1 for c in state.credentials if c.credential_type == "sudo")
            threat += sudo_count * 25
            
            # Active sessions indicate ongoing attack (+10 each)
            session_count = len(state.sessions)
            threat += session_count * 10
            
            # Elevated sessions are very dangerous (+20 each)
            elevated_count = sum(1 for s in state.sessions.values() if s.is_elevated)
            threat += elevated_count * 20
            
            # Sensitive file access attempts (+5 each)
            sensitive_access = sum(1 for e in state.events 
                                  if "sensitive file" in e.message.lower() or
                                     "accessed" in e.message.lower())
            threat += sensitive_access * 5
            
            # File creation by attacker (+8 each)
            file_creation = sum(1 for e in state.events 
                               if "created file" in e.message.lower())
            threat += file_creation * 8
        
        # Cap at 100
        threat = min(100, threat)
        self.threat_level = threat
        
        # Determine color and label based on threat level
        if threat == 0:
            color = self.COLORS["accent_green"]
            glow_color = "#004422"
            level_text = "NONE"
        elif threat < 20:
            color = self.COLORS["accent_green"]
            glow_color = "#004422"
            level_text = "LOW"
        elif threat < 50:
            color = self.COLORS["accent_orange"]
            glow_color = "#442200"
            level_text = "MEDIUM"
        elif threat < 80:
            color = self.COLORS["accent_red"]
            glow_color = "#440000"
            level_text = "HIGH"
        else:
            color = "#ff0000"
            glow_color = "#660000"
            level_text = "CRITICAL"
        
        # Draw filled portion with glow effect
        fill_width = int((threat / 100) * width)
        if fill_width > 0:
            # Glow layer
            self.threat_canvas.create_rectangle(0, 0, fill_width, height,
                                               fill=glow_color, outline="")
            # Main bar
            self.threat_canvas.create_rectangle(0, 3, fill_width, height - 3,
                                               fill=color, outline="")
        
        # Draw segment lines for visual effect
        for i in range(0, width, 20):
            self.threat_canvas.create_line(i, 0, i, height, 
                                          fill=self.COLORS["border_dark"], width=1)
        
        # Update label with threat score
        self.threat_label.configure(text=f"{level_text} ({threat}%)", fg=color)
    
    def animate_pulse(self):
        """Animate the status indicators with glow effects."""
        self.pulse_state = (self.pulse_state + 1) % 10
        
        # Pulse the status dot - bright/dim cycle
        if self.pulse_state < 5:
            status_color = self.COLORS["accent_green"]
            log_color = self.COLORS["accent_red"]
        else:
            status_color = "#006633"  # Darker green
            log_color = "#660022"     # Darker red
        
        self.status_dot.configure(fg=status_color)
        
        # Pulse the log indicator if it exists
        if hasattr(self, 'log_pulse'):
            self.log_pulse.configure(fg=log_color)
        
        # Update time with cyan glow
        self.time_label.configure(
            text=datetime.datetime.now().strftime("%H:%M:%S"))
        
        # Continue animation
        if state.running:
            self.root.after(200, self.animate_pulse)
    
    def start_services(self):
        """Start all honeypot services in separate threads."""
        services = [
            (CONFIG["SSH_PORT"], ssh_handler, "SSH"),
            (CONFIG["TELNET_PORT"], telnet_handler, "Telnet"),
            (CONFIG["FTP_PORT"], ftp_handler, "FTP"),
            (CONFIG["SMB_PORT"], smb_handler, "SMB"),
        ]
        
        for port, handler, name in services:
            t = threading.Thread(target=start_listener, args=(port, handler, name), daemon=True)
            t.start()
        
        log_event("INFO", "System", "localhost", "🍯 Honey POT initialized - All services started")
    
    def update_loop(self):
        """Update the UI with new events."""
        try:
            # Process log queue
            while not state.log_queue.empty():
                event = state.log_queue.get_nowait()
                self.append_log(event)
            
            # Update stat cards
            with state.lock:
                events_count = len(state.events)
                creds_count = len(state.credentials)
                sessions_count = len(state.sessions)
            
            self.stat_cards["Total Events"].value_label.configure(text=str(events_count))
            self.stat_cards["Credentials"].value_label.configure(text=str(creds_count))
            self.stat_cards["Active Sessions"].value_label.configure(text=str(sessions_count))
            
            # Count attacks today
            today = datetime.datetime.now().date()
            with state.lock:
                today_count = sum(1 for e in state.events 
                                 if "connection" in e.message.lower())
            self.stat_cards["Attacks Today"].value_label.configure(text=str(today_count))
            
            # Update log count
            self.log_count_label.configure(text=f"{events_count} events")
            
            # Update credentials tab count
            self.creds_count.configure(text=f"{creds_count} captured")
            
            # Update sessions tab count
            self.sessions_count.configure(text=f"{sessions_count} active")
            
            # Update mini stats - count only actual connection events
            with state.lock:
                ssh_count = sum(1 for e in state.events if e.service == "SSH" and "New connection" in e.message)
                telnet_count = sum(1 for e in state.events if e.service == "Telnet" and "New connection" in e.message)
                ftp_count = sum(1 for e in state.events if e.service == "FTP" and "New connection" in e.message)
            
            self.mini_stats["SSH Attempts"].configure(text=str(ssh_count))
            self.mini_stats["Telnet Attempts"].configure(text=str(telnet_count))
            self.mini_stats["FTP Attempts"].configure(text=str(ftp_count))
            self.mini_stats["Passwords Captured"].configure(text=str(creds_count))
            
            # Update tables
            self.update_credentials_table()
            self.update_sessions_table()
            self.update_service_tabs()
            
            # Update threat meter
            self.update_threat_meter()
            
        except Exception as e:
            pass
        
        if state.running:
            self.root.after(500, self.update_loop)
    
    def append_log(self, event: LogEvent):
        """Append a log event to the log display with better formatting."""
        # Main log
        self.log_text.text.insert(END, f"[{event.timestamp}] ", "timestamp")
        self.log_text.text.insert(END, f"[{event.service:8}] ", "service")
        self.log_text.text.insert(END, f"[{event.source_ip:15}] ", "ip")
        self.log_text.text.insert(END, f"{event.message}\n", event.level)
        self.log_text.text.see(END)
        
        # Service-specific log
        if event.service in self.service_logs:
            log_widget = self.service_logs[event.service]
            log_widget.text.insert(END, f"[{event.timestamp}] ", "timestamp")
            log_widget.text.insert(END, f"[{event.source_ip}] ", "timestamp")
            log_widget.text.insert(END, f"{event.message}\n", event.level)
            log_widget.text.see(END)
    
    def update_service_tabs(self):
        """Update service-specific statistics and tables."""
        services = ["SSH", "Telnet", "FTP", "SMB", "RDP"]
        
        with state.lock:
            for service in services:
                # Count connections
                conn_count = sum(1 for e in state.events
                               if e.service == service and "connection" in e.message.lower())
                
                # Count credentials
                cred_count = sum(1 for c in state.credentials if c.service == service)
                
                # Count active sessions
                active_count = sum(1 for s in state.sessions.values() if s.service == service)
                
                # Update labels
                if f"{service}_connections" in self.service_tables:
                    self.service_tables[f"{service}_connections"].configure(text=str(conn_count))
                if f"{service}_creds" in self.service_tables:
                    self.service_tables[f"{service}_creds"].configure(text=str(cred_count))
                if f"{service}_active" in self.service_tables:
                    self.service_tables[f"{service}_active"].configure(text=str(active_count))
                
                # Update service credentials table
                if f"{service}_table" in self.service_tables:
                    table = self.service_tables[f"{service}_table"]
                    rows = [(c.timestamp, c.source_ip, c.username, c.password, c.credential_type.upper())
                           for c in state.credentials if c.service == service]
                    
                    current_len = len(table.tablerows)
                    if len(rows) != current_len:
                        table.delete_rows()
                        if rows:
                            table.insert_rows(END, rows)
                        table.load_table_data()
    
    def update_credentials_table(self):
        """Update the credentials table."""
        with state.lock:
            rows = [(c.timestamp, c.source_ip, c.source_port, c.service,
                    c.username, c.password, c.credential_type.upper())
                   for c in state.credentials]
        
        current_len = len(self.creds_table.tablerows)
        if len(rows) != current_len:
            self.creds_table.delete_rows()
            if rows:
                self.creds_table.insert_rows(END, rows)
            self.creds_table.load_table_data()
    
    def update_sessions_table(self):
        """Update the sessions table."""
        with state.lock:
            rows = [(s.session_id[:30] + "...", s.source_ip, s.source_port,
                    s.service, s.start_time, s.username,
                    "👑 ROOT" if s.is_elevated else "—")
                   for s in state.sessions.values()]
        
        self.sessions_table.delete_rows()
        if rows:
            self.sessions_table.insert_rows(END, rows)
        self.sessions_table.load_table_data()
    
    def export_report(self):
        """Export the honeypot report with format and filename options."""
        from tkinter import messagebox, simpledialog, filedialog
        
        # Create export dialog window
        export_window = tk.Toplevel(self.root)
        export_window.title("Export Report")
        export_window.geometry("450x350")
        export_window.configure(bg=self.COLORS["bg_main"])
        export_window.resizable(False, False)
        export_window.transient(self.root)
        export_window.grab_set()
        
        # Center the window
        export_window.update_idletasks()
        x = (export_window.winfo_screenwidth() // 2) - (450 // 2)
        y = (export_window.winfo_screenheight() // 2) - (350 // 2)
        export_window.geometry(f"450x350+{x}+{y}")
        
        # Title
        title_frame = tk.Frame(export_window, bg=self.COLORS["bg_main"])
        title_frame.pack(fill=X, padx=20, pady=15)
        
        tk.Label(title_frame, text="📊 Export Report",
                font=("Segoe UI", 16, "bold"),
                fg=self.COLORS["accent_cyan"],
                bg=self.COLORS["bg_main"]).pack(anchor=W)
        
        tk.Label(title_frame, text="Choose format and filename for your report",
                font=("Segoe UI", 10),
                fg=self.COLORS["text_secondary"],
                bg=self.COLORS["bg_main"]).pack(anchor=W)
        
        # Format selection
        format_frame = tk.Frame(export_window, bg=self.COLORS["bg_card"],
                               highlightbackground=self.COLORS["border_dark"],
                               highlightthickness=1)
        format_frame.pack(fill=X, padx=20, pady=10)
        
        tk.Label(format_frame, text="Export Format:",
                font=("Segoe UI", 10, "bold"),
                fg=self.COLORS["text_primary"],
                bg=self.COLORS["bg_card"]).pack(anchor=W, padx=15, pady=(10, 5))
        
        format_var = tk.StringVar(value="json")
        
        formats_row = tk.Frame(format_frame, bg=self.COLORS["bg_card"])
        formats_row.pack(fill=X, padx=15, pady=(0, 10))
        
        # JSON option
        json_rb = ttk.Radiobutton(formats_row, text="JSON (.json)", 
                                  variable=format_var, value="json",
                                  bootstyle="info")
        json_rb.pack(side=LEFT, padx=(0, 20))
        
        # XML option
        xml_rb = ttk.Radiobutton(formats_row, text="XML + XSLT (.xml)",
                                 variable=format_var, value="xml",
                                 bootstyle="warning")
        xml_rb.pack(side=LEFT)
        
        # Filename entry
        filename_frame = tk.Frame(export_window, bg=self.COLORS["bg_card"],
                                 highlightbackground=self.COLORS["border_dark"],
                                 highlightthickness=1)
        filename_frame.pack(fill=X, padx=20, pady=10)
        
        tk.Label(filename_frame, text="Filename (without extension):",
                font=("Segoe UI", 10, "bold"),
                fg=self.COLORS["text_primary"],
                bg=self.COLORS["bg_card"]).pack(anchor=W, padx=15, pady=(10, 5))
        
        filename_var = tk.StringVar(value="honeypot_report")
        filename_entry = ttk.Entry(filename_frame, textvariable=filename_var,
                                   font=("Consolas", 11), width=40)
        filename_entry.pack(padx=15, pady=(0, 10), fill=X)
        
        # Buttons
        btn_frame = tk.Frame(export_window, bg=self.COLORS["bg_main"])
        btn_frame.pack(fill=X, padx=20, pady=15)
        
        def do_export():
            try:
                base_name = filename_var.get().strip()
                if not base_name:
                    base_name = "honeypot_report"
                
                # Sanitize filename
                base_name = "".join(c for c in base_name if c.isalnum() or c in "_-")
                
                export_format = format_var.get()
                
                if export_format == "json":
                    # Ask user where to save
                    filename = filedialog.asksaveasfilename(
                        defaultextension=".json",
                        filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                        initialfile=f"{base_name}.json",
                        title="Save JSON Report"
                    )
                    if not filename:  # User cancelled
                        return
                    export_to_json(filename, CONFIG, state)
                    log_event("INFO", "System", "localhost", f"📊 JSON report exported to {filename}")
                    export_window.destroy()
                    messagebox.showinfo("Export Complete",
                        f"Report exported successfully!\n\n"
                        f"📄 JSON: {filename}\n\n"
                        f"You can open this file in any text editor or JSON viewer.")
                else:
                    # Ask user where to save
                    filename = filedialog.asksaveasfilename(
                        defaultextension=".xml",
                        filetypes=[("XML files", "*.xml"), ("All files", "*.*")],
                        initialfile=f"{base_name}.xml",
                        title="Save XML Report"
                    )
                    if not filename:  # User cancelled
                        return
                    xml_file, xslt_file = export_to_xml(filename, CONFIG, state)
                    log_event("INFO", "System", "localhost", f"📊 XML report exported to {xml_file}")
                    export_window.destroy()
                    messagebox.showinfo("Export Complete",
                        f"Report exported successfully!\n\n"
                        f"📄 XML: {xml_file}\n"
                        f"🎨 XSLT: {xslt_file}\n\n"
                        f"Open the XML file in a browser to view the styled report.")
                        
            except Exception as e:
                log_event("CRITICAL", "System", "localhost", f"Export failed: {e}")
                messagebox.showerror("Export Failed", f"Could not export report:\n{e}")
        
        def cancel_export():
            export_window.destroy()
        
        # Cancel button
        cancel_btn = ttk.Button(btn_frame, text="Cancel",
                               bootstyle="secondary",
                               command=cancel_export)
        cancel_btn.pack(side=LEFT)
        
        # Export button
        export_btn = ttk.Button(btn_frame, text="📊 Export",
                               bootstyle="success",
                               command=do_export)
        export_btn.pack(side=RIGHT)
        
        # Bind Enter key to export
        export_window.bind('<Return>', lambda e: do_export())
        filename_entry.focus_set()
    
    def clear_logs(self):
        """Clear the log display."""
        self.log_text.text.delete(1.0, END)
        for log_widget in self.service_logs.values():
            log_widget.text.delete(1.0, END)
        log_event("INFO", "System", "localhost", "🗑️ Log display cleared")
    
    def shutdown(self):
        """Shutdown the honeypot gracefully."""
        from tkinter import messagebox
        if messagebox.askyesno("Confirm Shutdown",
                              "⚠️ Are you sure you want to shutdown Honey POT?\n\n"
                              "All active sessions will be terminated."):
            log_event("INFO", "System", "localhost", "🛑 Honey POT shutdown initiated")
            state.running = False
            
            for sock in state.listeners:
                try:
                    sock.close()
                except:
                    pass
            
            self.root.after(500, self.root.destroy)
    
    def run(self):
        """Start the application."""
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            self.shutdown()

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                    🍯 HONEY POT                              ║
    ║           Production-Grade Blue Team Honeypot                 ║
    ║                                                               ║
    ║  Services Starting:                                           ║
    ║    • SSH      : 2222  (High Interaction)                      ║
    ║    • Telnet   : 2233  (High Interaction)                      ║
    ║    • FTP      : 2121  (Medium Interaction)                    ║
    ║    • SMB      : 4445  (fileList)                              ║
    ║                                                               ║
    ║                                                               ║
    ║  [!] Run with sudo/root for ports < 1024                      ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    app = HoneypotGUI()
    app.run()

if __name__ == "__main__":
    main()
