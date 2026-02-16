# Honey POT - Multi-Protocol Honeypot

A Python-based honeypot that simulates multiple network services to capture attacker credentials and monitor intrusion attempts.

## Features

- **Multi-Protocol Support**
  - SSH (port 2222) - Full shell simulation with paramiko
  - Telnet (port 2233) - Interactive shell emulation
  - FTP (port 2121) - File transfer simulation with PASV mode
  - SMB (port 4445) - Share enumeration with DCE/RPC support

- **Credential Capture**
  - Login attempts across all services
  - Sudo password capture (privilege escalation trap)
  - Real-time Discord webhook alerts

- **Virtual Filesystem**
  - Realistic Linux filesystem simulation
  - Fake sensitive files (/etc/passwd, /etc/shadow, db_creds.txt, etc.)
  - Command execution logging

- **Modern GUI**
  - Real-time event monitoring
  - Credential and session tracking
  - Service status indicators
  - Threat level meter
  - Export to XML/XSLT and JSON reports

## Installation

```bash
git clone https://github.com/honney336/HoneyPot.git

# Install dependencies
pip install -r requirements.txt

# Run the honeypot
python3 honeypot.py
```

## Requirements

- Python 3.8+
- tkinter (usually included with Python)
- See `requirements.txt` for pip packages

## Project Structure

```
CW2/
├── honeypot.py      # Main application (GUI, services, config)
├── vfs.py           # Virtual filesystem simulation
├── commands.py      # FakeShell command handlers
├── export.py        # XML/JSON report export functions
├── requirements.txt # Python dependencies
└── README.md        # This file
```

## Configuration

Edit the `CONFIG` dictionary in `honeypot.py`:

```python
CONFIG = {
    "SSH_PORT": 2222,
    "TELNET_PORT": 2233,
    "FTP_PORT": 2121,
    "SMB_PORT": 4445,
    "DISCORD_WEBHOOK": "your_webhook_url",
    "HOSTNAME": "prod-db-server01",
}
```

## Usage

1. Start the honeypot:
   ```bash
   python3 honeypot.py
   ```

2. The GUI will open showing all services starting on their configured ports.

3. Test connections:
   ```bash
   # SSH
   ssh -p 2222 admin@localhost
   
   # Telnet
   telnet localhost 2233
   
   # FTP
   ftp localhost 2121
   
   # SMB
   smbclient -L //localhost -p 4445
   ```

4. Monitor activity in the GUI and export reports as needed.

## Discord Alerts

Configure a Discord webhook URL in the config to receive real-time alerts for:
- New connections
- Login attempts with credentials
- Sudo/privilege escalation attempts

## Export Reports

Click the "Export" button in the GUI to save reports:
- **XML/XSLT**: Opens styled in any web browser
- **JSON**: Machine-readable format for analysis

## Security Notes

- Run on non-standard ports (no root required)
- Do not expose to the internet without proper network isolation
- All captured data is stored in memory and log files
- Credentials are logged for research/analysis purposes only

## License

Educational/Research use only.
