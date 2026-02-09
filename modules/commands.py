#!/usr/bin/env python3
"""
FakeShell Command Handler for Honey Trap Honeypot
Simulates a Linux bash shell with full command support.
"""

import socket
import datetime
import time
from .vfs import VIRTUAL_FS, FAKE_FILE_CONTENTS, get_virtual_fs_entry


class FakeShell:
    """Simulates a Linux bash shell with sudo support."""
    
    def __init__(self, conn: socket.socket, addr: tuple, service: str,
                 config: dict, state, log_event_func, capture_credential_func,
                 discord_login_func, discord_sudo_func, ActiveSession):
        self.conn = conn
        self.addr = addr
        self.service = service
        self.config = config
        self.state = state
        self.log_event = log_event_func
        self.capture_credential = capture_credential_func
        self.discord_login_alert = discord_login_func
        self.discord_sudo_alert = discord_sudo_func
        self.ActiveSession = ActiveSession
        
        self.username = ""
        self.password = ""
        self.is_root = False
        self.cwd = "/home/admin"
        self.session_id = f"{addr[0]}:{addr[1]}:{time.time()}"
        self.authenticated = False
        self.created_files = {}  # Track files "created" by attacker
        
    def get_prompt(self) -> str:
        """Generate the shell prompt."""
        user = "root" if self.is_root else self.username
        symbol = "#" if self.is_root else "$"
        return f"{user}@{self.config['HOSTNAME']}:{self.cwd}{symbol} "
    
    def send(self, data: str):
        """Send data to the client."""
        try:
            self.conn.sendall(data.encode('utf-8'))
        except:
            pass
    
    def recv(self, size: int = 1024) -> str:
        """Receive data from the client."""
        try:
            data = self.conn.recv(size)
            return data.decode('utf-8', errors='ignore').strip()
        except:
            return ""
    
    def recv_line(self) -> str:
        """Receive a line of input (handles character-by-character for telnet)."""
        buffer = ""
        while True:
            try:
                char = self.conn.recv(1).decode('utf-8', errors='ignore')
                if not char:
                    return ""
                if char in ('\r', '\n'):
                    self.send("\r\n")
                    return buffer.strip()
                if char == '\x7f' or char == '\x08':  # Backspace
                    if buffer:
                        buffer = buffer[:-1]
                        self.send("\b \b")
                elif char == '\x03':  # Ctrl+C
                    self.send("^C\r\n")
                    return ""
                elif ord(char) >= 32:  # Printable
                    buffer += char
                    self.send(char)
            except:
                return ""
    
    def recv_password(self) -> str:
        """Receive password (no echo)."""
        buffer = ""
        while True:
            try:
                char = self.conn.recv(1).decode('utf-8', errors='ignore')
                if not char:
                    return ""
                if char in ('\r', '\n'):
                    self.send("\r\n")
                    return buffer.strip()
                if char == '\x7f' or char == '\x08':
                    if buffer:
                        buffer = buffer[:-1]
                elif ord(char) >= 32:
                    buffer += char
            except:
                return ""
    
    def do_login(self) -> bool:
        """Handle login sequence."""
        # Send banner
        banner = f"\r\nLinux {self.config['HOSTNAME']} 5.15.0-91-generic #101-Ubuntu SMP x86_64\r\n"
        banner += f"\r\nLast login: {datetime.datetime.now().strftime('%a %b %d %H:%M:%S %Y')} from 192.168.1.100\r\n\r\n"
        
        self.send(f"{self.config['HOSTNAME']} login: ")
        self.username = self.recv_line()
        if not self.username:
            return False
        
        self.send("Password: ")
        self.password = self.recv_password()
        if not self.password:
            return False
        
        # Log the attempt
        self.capture_credential(self.addr[0], self.addr[1], self.service, 
                               self.username, self.password, "login")
        self.discord_login_alert(self.service, self.addr[0], self.username, self.password)
        
        # Always "succeed" to keep attacker engaged
        time.sleep(0.5)  # Simulate auth delay
        self.send(banner)
        self.authenticated = True
        
        # Register session
        session = self.ActiveSession(
            self.session_id, self.addr[0], self.addr[1], self.service,
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            self.username
        )
        with self.state.lock:
            self.state.sessions[self.session_id] = session
        
        self.log_event("WARNING", self.service, self.addr[0], 
                       f"User '{self.username}' logged in successfully (FAKE)")
        
        return True
    
    def handle_sudo(self, command: str) -> str:
        """Handle sudo command - THE TRAP."""
        self.send(f"[sudo] password for {self.username}: ")
        sudo_pass = self.recv_password()
        
        if sudo_pass:
            # CRITICAL: Capture sudo password
            self.capture_credential(self.addr[0], self.addr[1], self.service,
                                   self.username, sudo_pass, "sudo")
            self.discord_sudo_alert(self.addr[0], self.username, sudo_pass, command)
            
            # Elevate the session
            self.is_root = True
            with self.state.lock:
                if self.session_id in self.state.sessions:
                    self.state.sessions[self.session_id].is_elevated = True
            
            self.log_event("CRITICAL", self.service, self.addr[0],
                          f"Privilege escalation! User '{self.username}' elevated to root")
            
            # Execute the command as root
            actual_cmd = command[5:].strip() if command.startswith("sudo ") else command
            return self.execute_command(actual_cmd)
        
        return "sudo: 3 incorrect password attempts\r\n"
    
    def resolve_path(self, path: str) -> str:
        """Resolve relative path to absolute."""
        if path.startswith("/"):
            return path
        if path == "~":
            return f"/home/{self.username}" if not self.is_root else "/root"
        if path.startswith("~/"):
            base = f"/home/{self.username}" if not self.is_root else "/root"
            return base + path[1:]
        if path == "..":
            parts = self.cwd.rsplit("/", 1)
            return parts[0] if parts[0] else "/"
        if path == ".":
            return self.cwd
        return f"{self.cwd}/{path}".replace("//", "/")
    
    def execute_command(self, cmd: str) -> str:
        """Execute a fake shell command."""
        cmd = cmd.strip()
        if not cmd:
            return ""
        
        self.log_event("INFO", self.service, self.addr[0], f"Command: {cmd}")
        
        # Handle output redirection (>, >>)
        append_mode = False
        redirect_file = None
        if '>>' in cmd:
            parts_redir = cmd.split('>>', 1)
            cmd = parts_redir[0].strip()
            redirect_file = parts_redir[1].strip()
            append_mode = True
        elif '>' in cmd:
            parts_redir = cmd.split('>', 1)
            cmd = parts_redir[0].strip()
            redirect_file = parts_redir[1].strip()
        
        if redirect_file:
            # Resolve the redirect file path
            file_path = self.resolve_path(redirect_file)
            # Get content to write (typically from echo)
            parts = cmd.split()
            if parts and parts[0] == 'echo':
                content = ' '.join(parts[1:])
                # Remove surrounding quotes
                if (content.startswith("'") and content.endswith("'")) or \
                   (content.startswith('"') and content.endswith('"')):
                    content = content[1:-1]
            else:
                # For other commands, simulate empty output
                content = ""
            
            # Store in created_files
            if append_mode:
                # Append mode - get existing content first
                if file_path in self.created_files:
                    self.created_files[file_path] += "\n" + content
                elif file_path in FAKE_FILE_CONTENTS:
                    # Appending to an existing system file - copy original first
                    self.created_files[file_path] = FAKE_FILE_CONTENTS[file_path] + "\n" + content
                else:
                    self.created_files[file_path] = content
            else:
                # Overwrite mode
                self.created_files[file_path] = content
            
            self.log_event("WARNING", self.service, self.addr[0], 
                          f"Attacker modified file: {file_path} (append={append_mode})")
            return ""  # No output for redirected commands
        
        parts = cmd.split()
        if not parts:
            return ""
        command = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        
        # Handle sudo
        if command == "sudo":
            if args:
                return self.handle_sudo(cmd)
            return "usage: sudo <command>\r\n"
        
        # Command handlers
        if command == "ls":
            return self.cmd_ls(args)
        elif command == "cd":
            return self.cmd_cd(args)
        elif command == "pwd":
            return f"{self.cwd}\r\n"
        elif command == "cat":
            return self.cmd_cat(args)
        elif command == "whoami":
            return f"{'root' if self.is_root else self.username}\r\n"
        elif command == "id":
            if self.is_root:
                return "uid=0(root) gid=0(root) groups=0(root)\r\n"
            return f"uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username}),27(sudo)\r\n"
        elif command == "uname":
            if "-a" in args:
                return f"Linux {self.config['HOSTNAME']} 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\r\n"
            return "Linux\r\n"
        elif command == "hostname":
            return f"{self.config['HOSTNAME']}\r\n"
        elif command == "ifconfig" or command == "ip":
            return self.cmd_ifconfig()
        elif command == "ps":
            return self.cmd_ps()
        elif command == "netstat":
            return self.cmd_netstat()
        elif command == "wget" or command == "curl":
            return f"{command}: command not found (network disabled)\r\n"
        elif command == "exit" or command == "logout":
            return "EXIT"
        elif command == "su":
            return self.cmd_su(args)
        elif command == "history":
            return self.cmd_history()
        elif command == "echo":
            return " ".join(args) + "\r\n"
        elif command == "clear":
            return "\033[2J\033[H"
        elif command == "touch":
            if args:
                for target in args:
                    path = self.resolve_path(target)
                    if path not in self.created_files:
                        self.created_files[path] = ""
                        self.log_event("INFO", self.service, self.addr[0], f"touch: {path}")
            return ""
        elif command == "mkdir":
            if args:
                for target in args:
                    if not target.startswith("-"):
                        path = self.resolve_path(target)
                        self.created_files[path + "/"] = "__DIR__"
                        self.log_event("INFO", self.service, self.addr[0], f"mkdir: {path}")
            return ""
        elif command == "rm":
            if args:
                for target in args:
                    if not target.startswith("-"):
                        path = self.resolve_path(target)
                        if path in self.created_files:
                            del self.created_files[path]
                        elif path + "/" in self.created_files:
                            del self.created_files[path + "/"]
                        self.log_event("WARNING", self.service, self.addr[0], f"rm: {path}")
            return ""
        elif command == "help":
            return "Available commands: ls, cd, pwd, cat, whoami, id, uname, hostname, ps, netstat, history, touch, mkdir, rm, exit\r\n"
        else:
            return f"-bash: {command}: command not found\r\n"
    
    def cmd_ls(self, args: list) -> str:
        """Handle ls command."""
        # Separate options from paths
        options = [a for a in args if a.startswith("-")]
        paths = [a for a in args if not a.startswith("-")]
        
        target = paths[0] if paths else "."
        path = self.resolve_path(target)
        
        items = get_virtual_fs_entry(path, self.username)
        if items is not None:
            items = list(items)  # Make a copy
            
            # Add any created files in this directory
            for created_path in self.created_files:
                parent = "/".join(created_path.rsplit("/", 1)[:-1]) or "/"
                filename = created_path.rsplit("/", 1)[-1]
                if parent == path and filename not in items:
                    items.append(filename)
            
            # Check for long listing options
            long_list = any(opt in options for opt in ["-l", "-la", "-al", "-ll", "-a"]) or \
                       "-la" in args or "-al" in args or "-l" in args or "-a" in args
            if long_list:
                output = "total 48\r\n"
                output += "drwxr-xr-x  4 root root 4096 Jan 15 10:30 .\r\n"
                output += "drwxr-xr-x 24 root root 4096 Jan 15 09:00 ..\r\n"
                for item in items:
                    full_path = f"{path}/{item}" if path != "/" else f"/{item}"
                    # Determine if this is a file or directory
                    is_file = False
                    size = "4096"
                    
                    if full_path in self.created_files:
                        is_file = True
                        size = str(len(self.created_files[full_path]))
                    elif full_path in FAKE_FILE_CONTENTS:
                        is_file = True
                        size = str(len(FAKE_FILE_CONTENTS[full_path]))
                    elif full_path in VIRTUAL_FS:
                        # It's a directory (exists as a key in VFS)
                        is_file = False
                    elif "." in item and not item.startswith("."):
                        # Has extension, likely a file
                        is_file = True
                        size = "1024"
                    # else: no extension, no content - assume directory
                    
                    perms = "-rw-r--r--" if is_file else "drwxr-xr-x"
                    output += f"{perms}  1 root root {size:>5} Jan 15 10:30 {item}\r\n"
                return output
            return "  ".join(items) + "\r\n"
        
        # Not a directory - check if it's a file
        parent = "/".join(path.rsplit("/", 1)[:-1]) or "/"
        filename = path.rsplit("/", 1)[-1] if "/" in path else path
        parent_items = get_virtual_fs_entry(parent, self.username)
        if parent_items and filename in parent_items:
            # It's a file - check for long listing
            long_list = any(opt in options for opt in ["-l", "-la", "-al", "-ll"])
            if long_list:
                if path in FAKE_FILE_CONTENTS:
                    size = len(FAKE_FILE_CONTENTS[path])
                elif path in self.created_files:
                    size = len(self.created_files[path])
                else:
                    size = 1024
                return f"-rw-r--r-- 1 root root {size:>5} Jan 15 10:30 {filename}\r\n"
            return f"{filename}\r\n"
        
        return f"ls: cannot access '{target}': No such file or directory\r\n"
    
    def cmd_cd(self, args: list) -> str:
        """Handle cd command."""
        if not args:
            self.cwd = "/root" if self.is_root else f"/home/{self.username}"
            return ""
        
        path = self.resolve_path(args[0])
        
        # Check using dynamic lookup
        if get_virtual_fs_entry(path, self.username) is not None:
            self.cwd = path
            return ""
        
        # Allow any /home/username path for dynamic home directories
        if path.startswith("/home/") and path.count("/") == 2:
            self.cwd = path
            return ""
        
        return f"-bash: cd: {args[0]}: No such file or directory\r\n"
    
    def cmd_cat(self, args: list) -> str:
        """Handle cat command."""
        if not args:
            return "cat: missing operand\r\n"
        
        # Filter out options
        paths = [a for a in args if not a.startswith("-")]
        if not paths:
            return "cat: missing operand\r\n"
        
        target = paths[0]
        path = self.resolve_path(target)
        
        # Check if it's a file created by attacker
        if path in self.created_files:
            content = self.created_files[path].replace("\n", "\r\n")
            if not content.endswith("\r\n"):
                content += "\r\n"
            return content
        
        # Check if it's a sensitive file
        if path in FAKE_FILE_CONTENTS:
            self.log_event("WARNING", self.service, self.addr[0], 
                          f"Attacker accessed sensitive file: {path}")
            # Convert \n to \r\n for proper terminal display
            content = FAKE_FILE_CONTENTS[path].replace("\n", "\r\n")
            if not content.endswith("\r\n"):
                content += "\r\n"
            return content
        
        # Check if file exists in virtual FS
        parent = "/".join(path.rsplit("/", 1)[:-1]) or "/"
        filename = path.rsplit("/", 1)[-1]
        parent_items = get_virtual_fs_entry(parent, self.username)
        if parent_items and filename in parent_items:
            return f"[Binary file or empty content]\r\n"
        
        return f"cat: {target}: No such file or directory\r\n"
    
    def cmd_ifconfig(self) -> str:
        """Handle ifconfig/ip command."""
        return """eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::1  prefixlen 64  scopeid 0x20<link>
        ether 00:0c:29:ab:cd:ef  txqueuelen 1000  (Ethernet)
        RX packets 150234  bytes 98234567 (98.2 MB)
        TX packets 89012  bytes 45678901 (45.6 MB)

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
\r\n"""
    
    def cmd_ps(self) -> str:
        """Handle ps command."""
        return """  PID TTY          TIME CMD
    1 ?        00:00:03 systemd
  234 ?        00:00:01 sshd
  456 ?        00:00:00 cron
  789 ?        00:00:02 mysqld
  890 ?        00:00:01 apache2
 1234 pts/0    00:00:00 bash
 1567 pts/0    00:00:00 ps
\r\n"""
    
    def cmd_netstat(self) -> str:
        """Handle netstat command."""
        return """Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN
tcp        0      0 192.168.1.100:22        """ + f"{self.addr[0]}:{self.addr[1]}".ljust(24) + """ESTABLISHED
\r\n"""
    
    def cmd_su(self, args: list) -> str:
        """Handle su command."""
        target = args[0] if args else "root"
        self.send("Password: ")
        password = self.recv_password()
        
        if password:
            self.capture_credential(self.addr[0], self.addr[1], self.service,
                                   target, password, "sudo")
            if target == "root":
                self.is_root = True
                with self.state.lock:
                    if self.session_id in self.state.sessions:
                        self.state.sessions[self.session_id].is_elevated = True
                self.log_event("CRITICAL", self.service, self.addr[0],
                              f"su to root successful (FAKE) - captured password")
                self.discord_sudo_alert(self.addr[0], target, password, "su root")
            return ""
        return "su: Authentication failure\r\n"
    
    def cmd_history(self) -> str:
        """Handle history command."""
        return """    1  ls -la
    2  cd /root
    3  cat db_creds.txt
    4  mysql -u root -p
    5  history
\r\n"""
    
    def run_shell(self):
        """Main shell loop."""
        try:
            while self.state.running:
                self.send(self.get_prompt())
                cmd = self.recv_line()
                
                if not cmd:
                    continue
                
                result = self.execute_command(cmd)
                if result == "EXIT":
                    break
                if result:
                    self.send(result)
        except Exception as e:
            self.log_event("INFO", self.service, self.addr[0], f"Session error: {e}")
        finally:
            with self.state.lock:
                if self.session_id in self.state.sessions:
                    del self.state.sessions[self.session_id]
            self.log_event("INFO", self.service, self.addr[0], "Session closed")


def resolve_path(path: str, cwd: str, is_root: bool, username: str) -> str:
    """Resolve relative path to absolute."""
    if path.startswith("/"):
        return path
    if path == "~":
        return f"/home/{username}" if not is_root else "/root"
    if path.startswith("~/"):
        base = f"/home/{username}" if not is_root else "/root"
        return base + path[1:]
    if path == "..":
        parts = cwd.rsplit("/", 1)
        return parts[0] if parts[0] else "/"
    if path == ".":
        return cwd
    return f"{cwd}/{path}".replace("//", "/")


def execute_shell_command(cmd: str, cwd: str, is_root: bool, username: str, 
                          addr: tuple, config: dict, log_event_func, 
                          created_files: dict = None) -> str:
    """Execute a fake shell command and return output.
    
    Args:
        cmd: Command string to execute
        cwd: Current working directory
        is_root: Whether user is root
        username: Current username
        addr: Connection address tuple (ip, port)
        config: Configuration dictionary with HOSTNAME etc.
        log_event_func: Function to log events
        created_files: Dictionary of files created by attacker
    """
    if created_files is None:
        created_files = {}
    
    parts = cmd.split()
    if not parts:
        return ""
    
    command = parts[0]
    args = parts[1:] if len(parts) > 1 else []
    
    # Separate options from paths
    options = [a for a in args if a.startswith("-")]
    paths = [a for a in args if not a.startswith("-")]
    
    if command == "ls":
        # Get path - use first non-option arg or cwd
        target_path = paths[0] if paths else "."
        path = resolve_path(target_path, cwd, is_root, username)
        
        # Check if path exists in virtual FS (using dynamic lookup)
        items = get_virtual_fs_entry(path, username)
        if items is not None:
            items = list(items)  # Make a copy
            
            # Add any created files in this directory
            for created_path in created_files:
                parent = "/".join(created_path.rsplit("/", 1)[:-1]) or "/"
                filename = created_path.rsplit("/", 1)[-1]
                if parent == path and filename not in items:
                    items.append(filename)
            
            # Check for long listing options
            long_list = any(opt in options for opt in ["-l", "-la", "-al", "-ll", "-a"])
            if long_list or "-la" in args or "-al" in args or "-l" in args or "-a" in args:
                output = "total 48\r\n"
                output += "drwxr-xr-x  4 root root 4096 Jan 15 10:30 .\r\n"
                output += "drwxr-xr-x 24 root root 4096 Jan 15 09:00 ..\r\n"
                for item in items:
                    full_path = f"{path}/{item}" if path != "/" else f"/{item}"
                    # Determine if this is a file or directory
                    is_file = False
                    size = "4096"
                    
                    if full_path in created_files:
                        is_file = True
                        size = str(len(created_files[full_path]))
                    elif full_path in FAKE_FILE_CONTENTS:
                        is_file = True
                        size = str(len(FAKE_FILE_CONTENTS[full_path]))
                    elif full_path in VIRTUAL_FS:
                        is_file = False
                    elif "." in item and not item.startswith("."):
                        is_file = True
                        size = "1024"
                    
                    perms = "-rw-r--r--" if is_file else "drwxr-xr-x"
                    output += f"{perms}  1 root root {size:>5} Jan 15 10:30 {item}\r\n"
                return output
            return "  ".join(items) + "\r\n"
        else:
            # Try parent directory to see if it's a file
            parent = "/".join(path.rsplit("/", 1)[:-1]) or "/"
            filename = path.rsplit("/", 1)[-1] if "/" in path else path
            parent_items = get_virtual_fs_entry(parent, username)
            if parent_items and filename in parent_items:
                long_list = any(opt in options for opt in ["-l", "-la", "-al", "-ll"])
                if long_list:
                    if path in FAKE_FILE_CONTENTS:
                        size = len(FAKE_FILE_CONTENTS[path])
                    else:
                        size = 1024
                    return f"-rw-r--r-- 1 root root {size:>5} Jan 15 10:30 {filename}\r\n"
                return f"{filename}\r\n"
            return f"ls: cannot access '{target_path}': No such file or directory\r\n"
    
    elif command == "cd":
        return ""  # Handled by caller
    
    elif command == "pwd":
        return f"{cwd}\r\n"
    
    elif command == "cat":
        if not paths:
            return "cat: missing operand\r\n"
        target = paths[0]
        path = resolve_path(target, cwd, is_root, username)
        
        if path in created_files:
            content = created_files[path].replace("\n", "\r\n")
            if not content.endswith("\r\n"):
                content += "\r\n"
            return content
        
        if path in FAKE_FILE_CONTENTS:
            log_event_func("WARNING", "SSH", addr[0], f"Accessed sensitive file: {path}")
            content = FAKE_FILE_CONTENTS[path].replace("\n", "\r\n")
            if not content.endswith("\r\n"):
                content += "\r\n"
            return content
        return f"cat: {target}: No such file or directory\r\n"
    
    elif command == "whoami":
        return f"{'root' if is_root else username}\r\n"
    
    elif command == "id":
        if is_root:
            return "uid=0(root) gid=0(root) groups=0(root)\r\n"
        return f"uid=1000({username}) gid=1000({username}) groups=1000({username}),27(sudo)\r\n"
    
    elif command == "uname":
        if "-a" in options or "-a" in args:
            return f"Linux {config['HOSTNAME']} 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\r\n"
        return "Linux\r\n"
    
    elif command == "hostname":
        return f"{config['HOSTNAME']}\r\n"
    
    elif command == "ps":
        return "  PID TTY          TIME CMD\r\n    1 ?        00:00:03 systemd\r\n  234 ?        00:00:01 sshd\r\n  456 ?        00:00:00 cron\r\n  789 ?        00:00:02 mysqld\r\n 1234 pts/0    00:00:00 bash\r\n"
    
    elif command == "echo":
        return " ".join(args) + "\r\n"
    
    elif command == "clear":
        return "\033[2J\033[H"
    
    elif command == "history":
        return "    1  ls -la\r\n    2  cd /root\r\n    3  cat db_creds.txt\r\n    4  history\r\n"
    
    elif command == "ifconfig":
        return "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255\r\n        ether 00:0c:29:ab:cd:ef  txqueuelen 1000  (Ethernet)\r\n\r\nlo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\r\n        inet 127.0.0.1  netmask 255.0.0.0\r\n"
    
    elif command == "ip":
        if paths and paths[0] == "a":
            return "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\r\n    inet 127.0.0.1/8 scope host lo\r\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\r\n    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0\r\n"
        return "Usage: ip [ OPTIONS ] OBJECT { COMMAND }\r\n"
    
    elif command == "netstat":
        return "Active Internet connections (only servers)\r\nProto Recv-Q Send-Q Local Address           Foreign Address         State\r\ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\r\ntcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN\r\ntcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\r\n"
    
    elif command == "w" or command == "who":
        return f"{username}  pts/0        {datetime.datetime.now().strftime('%H:%M')}   (192.168.1.100)\r\n"
    
    elif command == "uptime":
        return " 11:30:00 up 45 days,  3:22,  1 user,  load average: 0.08, 0.03, 0.01\r\n"
    
    elif command == "date":
        return datetime.datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y") + "\r\n"
    
    elif command == "df":
        return "Filesystem     1K-blocks    Used Available Use% Mounted on\r\n/dev/sda1       41284928 8234567  31234567  21% /\r\ntmpfs            4096000       0   4096000   0% /dev/shm\r\n"
    
    elif command == "free":
        return "              total        used        free      shared  buff/cache   available\r\nMem:        8167848     1234567     4567890      123456     2345678     6543210\r\nSwap:       2097148           0     2097148\r\n"
    
    elif command == "wget" or command == "curl":
        return f"{command}: command not found\r\n"
    
    elif command == "vim" or command == "vi" or command == "nano":
        return f"{command}: command not available in this shell\r\n"
    
    elif command == "touch":
        if paths:
            for target in paths:
                path = resolve_path(target, cwd, is_root, username)
                if path not in created_files:
                    created_files[path] = ""
                    log_event_func("INFO", "SSH", addr[0], f"touch: {path}")
        return ""
    
    elif command == "mkdir":
        if paths:
            for target in paths:
                path = resolve_path(target, cwd, is_root, username)
                created_files[path + "/"] = "__DIR__"
                log_event_func("INFO", "SSH", addr[0], f"mkdir: {path}")
        return ""
    
    elif command == "rm":
        if paths:
            for target in paths:
                path = resolve_path(target, cwd, is_root, username)
                if path in created_files:
                    del created_files[path]
                elif path + "/" in created_files:
                    del created_files[path + "/"]
                log_event_func("WARNING", "SSH", addr[0], f"rm command: {path}")
        return ""
    
    elif command == "cp" or command == "mv":
        return ""
    
    elif command == "head" or command == "tail":
        if not paths:
            return f"{command}: missing operand\r\n"
        target = paths[0]
        path = resolve_path(target, cwd, is_root, username)
        
        content = None
        if path in created_files:
            content = created_files[path]
        elif path in FAKE_FILE_CONTENTS:
            content = FAKE_FILE_CONTENTS[path]
        
        if content is not None:
            lines = content.split("\n")
            if command == "head":
                result = "\r\n".join(lines[:10])
            else:
                result = "\r\n".join(lines[-10:])
            return result + "\r\n"
        return f"{command}: {target}: No such file or directory\r\n"
    
    elif command == "grep":
        if len(args) < 2:
            return "Usage: grep PATTERN [FILE]...\r\n"
        return ""
    
    elif command == "find":
        return ""
    
    elif command == "which":
        if paths:
            known_commands = ["ls", "cat", "pwd", "cd", "whoami", "id", "ps", "echo", "hostname"]
            if paths[0] in known_commands:
                return f"/usr/bin/{paths[0]}\r\n"
        return ""
    
    elif command == "env":
        return f"USER={username}\r\nHOME=/home/{username}\r\nPWD={cwd}\r\nSHELL=/bin/bash\r\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\r\nLANG=en_US.UTF-8\r\n"
    
    elif command == "export":
        return ""
    
    elif command == "alias":
        return ""
    
    elif command == "type":
        if paths:
            return f"{paths[0]} is /usr/bin/{paths[0]}\r\n"
        return ""
    
    else:
        return f"-bash: {command}: command not found\r\n"
