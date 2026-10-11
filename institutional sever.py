import socket
import threading
import time
import os
import hashlib
import logging
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import sqlite3
import ssl
import hmac
import ipaddress
import base64
import json
import struct
from datetime import timezone, timedelta

# Global Configuration
all_connections = []
all_address = []
connection_times = []
connection_last_seen = []
connection_lock = threading.Lock()
s = None
app_instance = None
dead_connections = set()
pending_downloads = {}
download_lock = threading.Lock()
MAX_FILE_SIZE = 128 * 1024 * 1024
FILE_CHUNK_SIZE = 48 * 1024
MAX_CLIENTS = 32
MAX_FRAME_SIZE = 8 * 1024 * 1024


class FramedSocket:
    """Length framed JSON transport, kept inside the server application."""
    def __init__(self, sock):
        self.socket = sock
        self._send_lock = threading.Lock()
        self._receive_lock = threading.Lock()

    def send(self, message):
        with self._send_lock:
            self._send_unlocked(message)

    def send_sequence(self, messages):
        with self._send_lock:
            for message in messages:
                self._send_unlocked(message)

    def _send_unlocked(self, message):
        payload = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if not payload or len(payload) > MAX_FRAME_SIZE:
            raise ValueError("Message frame exceeds the configured size limit")
        self.socket.sendall(struct.pack("!I", len(payload)) + payload)

    def receive(self):
        with self._receive_lock:
            header = self._read_exactly(4)
            size = struct.unpack("!I", header)[0]
            if size < 1 or size > MAX_FRAME_SIZE:
                raise ValueError("Invalid message frame size")
            payload = self._read_exactly(size)
        try:
            value = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Invalid JSON message frame") from exc
        if not isinstance(value, dict) or not isinstance(value.get("type"), str):
            raise ValueError("Message frame must be an object with a type")
        return value

    def _read_exactly(self, size):
        parts = bytearray()
        while len(parts) < size:
            chunk = self.socket.recv(size - len(parts))
            if not chunk:
                raise ConnectionError("Peer closed the connection")
            parts.extend(chunk)
        return bytes(parts)

    def close(self):
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.socket.close()

    def settimeout(self, timeout):
        self.socket.settimeout(timeout)


def authenticate(channel, expected_token, allow_session=True):
    """Validate the shared token inside the authenticated TLS connection."""
    request = channel.receive()
    supplied = request.get("token", "") if request.get("type") == "auth" else ""
    valid_token = hmac.compare_digest(str(supplied), expected_token)
    accepted = valid_token and allow_session
    channel.send({"type": "auth_ok" if accepted else "auth_error",
                  "message": "Authenticated" if accepted else
                  ("Server session limit reached" if valid_token else "Authentication rejected")})
    return accepted

# Bind to all interfaces for routed client connections. Restrict this to a
# specific interface with REMOTE_ADMIN_BIND_HOST when appropriate.
SERVER_HOST = os.environ.get("REMOTE_ADMIN_BIND_HOST", "0.0.0.0")
SERVER_PORT = int(os.environ.get("REMOTE_ADMIN_PORT", "9999"))
TLS_CERT = os.environ.get("REMOTE_ADMIN_TLS_CERT", "server-cert.pem")
TLS_KEY = os.environ.get("REMOTE_ADMIN_TLS_KEY", "server-key.pem")
AUTH_TOKEN = os.environ.get("REMOTE_ADMIN_TOKEN", "")
TLS_NAME = os.environ.get("REMOTE_ADMIN_TLS_NAME", "127.0.0.1")


def ensure_tls_certificate():
    """Create a locally trusted, self signed certificate for this project MVP."""
    if os.path.exists(TLS_CERT) and os.path.exists(TLS_KEY):
        try:
            from cryptography import x509
            with open(TLS_CERT, "rb") as source:
                existing = x509.load_pem_x509_certificate(source.read())
            names = existing.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            try:
                configured_name = ipaddress.ip_address(TLS_NAME)
                matches = configured_name in names.get_values_for_type(x509.IPAddress)
            except ValueError:
                matches = TLS_NAME in names.get_values_for_type(x509.DNSName)
            if not matches:
                raise RuntimeError(f"The existing certificate does not match REMOTE_ADMIN_TLS_NAME={TLS_NAME}. Replace the certificate and key or use the matching name.")
            return
        except ImportError as exc:
            raise RuntimeError("The Python cryptography package is required to validate the TLS certificate") from exc
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, TLS_NAME)])
        try:
            san = x509.IPAddress(ipaddress.ip_address(TLS_NAME))
        except ValueError:
            san = x509.DNSName(TLS_NAME)
        certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=1))
            .not_valid_after(datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .sign(key, hashes.SHA256()))
        with open(TLS_KEY, "wb") as output:
            output.write(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))
        with open(TLS_CERT, "wb") as output:
            output.write(certificate.public_bytes(serialization.Encoding.PEM))
        try:
            os.chmod(TLS_KEY, 0o600)
        except OSError:
            pass
        logging.info("Created TLS certificate %s for %s", TLS_CERT, TLS_NAME)
    except ImportError as exc:
        raise RuntimeError("The Python cryptography package is required to create the TLS certificate") from exc

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('reverse_shell_server.log'),
        logging.StreamHandler()
    ]
)


class DatabaseManager:
    """
    Manage session history and connection logs in SQLite database
    """

    def __init__(self, db_file='reverse_shell.db'):
        self.db_file = db_file
        self.init_database()

    def init_database(self):
        """Initialize database schema"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        # Connections table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                port INTEGER NOT NULL,
                connect_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                disconnect_time TIMESTAMP,
                status TEXT DEFAULT 'connected'
            )
        ''')

        # Commands table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                connection_id INTEGER,
                command TEXT NOT NULL,
                output TEXT,
                execution_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (connection_id) REFERENCES connections(id)
            )
        ''')

        # File transfers table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_transfers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                connection_id INTEGER,
                filename TEXT NOT NULL,
                direction TEXT NOT NULL,
                size INTEGER,
                transfer_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'completed',
                FOREIGN KEY (connection_id) REFERENCES connections(id)
            )
        ''')

        conn.commit()
        conn.close()
        logging.info("Database initialized successfully")

    def log_connection(self, ip_address, port):
        """Log new connection"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO connections (ip_address, port) VALUES (?, ?)',
            (ip_address, port)
        )
        conn.commit()
        conn_id = cursor.lastrowid
        conn.close()
        return conn_id

    def log_command(self, connection_id, command, output=''):
        """Log executed command"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO commands (connection_id, command, output) VALUES (?, ?, ?)',
            (connection_id, command, output[:1000])  # Limit output size
        )
        conn.commit()
        conn.close()

    def log_file_transfer(self, connection_id, filename, direction, size, status='completed'):
        """Log file transfer"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO file_transfers (connection_id, filename, direction, size, status) VALUES (?, ?, ?, ?, ?)',
            (connection_id, filename, direction, size, status)
        )
        conn.commit()
        conn.close()

    def update_connection_status(self, connection_id, status='disconnected'):
        """Update connection status"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        if status == "connected":
            cursor.execute('UPDATE connections SET disconnect_time = NULL, status = ? WHERE id = ?',
                           (status, connection_id))
        else:
            cursor.execute('UPDATE connections SET disconnect_time = CURRENT_TIMESTAMP, status = ? WHERE id = ?',
                           (status, connection_id))
        conn.commit()
        conn.close()

    def get_connection_history(self, limit=100):
        """Get recent connection history"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'SELECT * FROM connections ORDER BY connect_time DESC LIMIT ?',
            (limit,)
        )
        results = cursor.fetchall()
        conn.close()
        return results

    def get_command_history(self, connection_id=None, limit=100):
        """Get command history"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        if connection_id:
            cursor.execute(
                'SELECT * FROM commands WHERE connection_id = ? ORDER BY execution_time DESC LIMIT ?',
                (connection_id, limit)
            )
        else:
            cursor.execute(
                'SELECT * FROM commands ORDER BY execution_time DESC LIMIT ?',
                (limit,)
            )

        results = cursor.fetchall()
        conn.close()
        return results

    def get_file_transfer_count(self):
        conn = sqlite3.connect(self.db_file)
        try:
            return conn.execute("SELECT COUNT(*) FROM file_transfers").fetchone()[0]
        finally:
            conn.close()


class ReverseShellGUI:
    """
    INSTITUTIONAL GRADE Reverse Shell Server GUI

    Features:
    - Database logging of all activities
    - Session history and analytics
    - Enhanced security with authentication hooks
    - Professional UI with metrics dashboard
    - Export capabilities for reports
    - Multi-level access control ready
    - Audit trail for compliance
    """

    def __init__(self, root):
        self.root = root
        self.root.title("Network Operations Console")
        self.root.geometry("1440x900")
        self.root.minsize(1100, 700)
        self.root.configure(bg='#0b1220')

        # Initialize database
        self.db = DatabaseManager()

        # Session management
        self.active_sessions = {}
        self.command_history = []
        self.history_index = -1
        self.current_session_id = None
        self.db_connection_ids = {}  # Map socket conn_id to database id

        # Server state
        self.server_running = False
        self.selected_connection = None

        # Statistics
        self.total_connections = 0
        self.total_commands = 0
        self.total_files_transferred = 0

        # Configure styles
        self.setup_styles()

        # Build GUI
        self.build_gui()

        # Start GUI update loop
        self.update_connections_display()
        self.update_statistics()

        logging.info("Network Operations Console initialized")

    def setup_styles(self):
        """Configure a restrained network operations dashboard theme."""
        style = ttk.Style()
        style.theme_use('clam')

        background = '#0b1220'
        panel = '#111c2e'
        foreground = '#e5edf7'
        muted = '#8ea1b8'
        accent = '#28b8a7'
        border = '#26364c'

        style.configure('TFrame', background=background)
        style.configure('TLabel', background=background, foreground=foreground,
                        font=('Segoe UI', 10))
        style.configure('TButton', background=panel, foreground=foreground,
                        font=('Segoe UI', 10, 'bold'), padding=(12, 8),
                        borderwidth=1, relief='flat')
        style.map('TButton', background=[('active', '#1b2b42'), ('disabled', '#172235')],
                  foreground=[('disabled', muted)])
        style.configure('Accent.TButton', background=accent, foreground='#07131b')
        style.map('Accent.TButton', background=[('active', '#37d0bd')])
        style.configure('Treeview', background=panel, foreground=foreground,
                        fieldbackground=panel, rowheight=30,
                        font=('Segoe UI', 10), borderwidth=0)
        style.map('Treeview', background=[('selected', '#174f5a')],
                  foreground=[('selected', '#ffffff')])
        style.configure('Treeview.Heading', background='#1a2940', foreground=muted,
                        font=('Segoe UI', 9, 'bold'), padding=(8, 9), relief='flat')
        style.configure('TNotebook', background=background, borderwidth=0)
        style.configure('TNotebook.Tab', background=panel, foreground=muted,
                        padding=(14, 8), font=('Segoe UI', 9, 'bold'))
        style.map('TNotebook.Tab', background=[('selected', '#1a2940')],
                  foreground=[('selected', foreground)])
        style.configure('Metric.TLabel', font=('Segoe UI', 22, 'bold'), foreground=accent)
        style.configure('MetricTitle.TLabel', font=('Segoe UI', 9, 'bold'), foreground=muted)

    def build_gui(self):
        """Build enterprise-grade GUI interface"""

        # Main container
        main_container = ttk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Top section - Server controls and metrics
        top_frame = ttk.Frame(main_container)
        top_frame.pack(fill=tk.X, pady=(0, 10))

        # Server status
        status_frame = ttk.Frame(top_frame)
        status_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)

        ttk.Label(status_frame, text="Server Status:", font=('Segoe UI', 12, 'bold')).pack(side=tk.LEFT, padx=5)
        self.status_label = ttk.Label(status_frame, text="● OFFLINE", foreground='#ff4444',
                                      font=('Segoe UI', 12, 'bold'))
        self.status_label.pack(side=tk.LEFT, padx=5)

        self.conn_count_label = ttk.Label(status_frame, text="Active: 0", font=('Segoe UI', 11))
        self.conn_count_label.pack(side=tk.LEFT, padx=20)

        # Control buttons
        button_frame = ttk.Frame(top_frame)
        button_frame.pack(side=tk.RIGHT)

        self.start_btn = ttk.Button(button_frame, text="Start listener", style="Accent.TButton", command=self.start_server)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        ttk.Button(button_frame, text="Refresh", command=self.refresh_connections).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Reports", command=self.show_reports).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Logs", command=self.show_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Close sessions", command=self.clear_all_sessions).pack(side=tk.LEFT, padx=5)

        # Metrics dashboard
        metrics_frame = ttk.Frame(main_container)
        metrics_frame.pack(fill=tk.X, pady=(0, 10))

        # Metric cards
        self.create_metric_card(metrics_frame, "Total Connections", "0", 0)
        self.create_metric_card(metrics_frame, "Commands Executed", "0", 1)
        self.create_metric_card(metrics_frame, "Files Transferred", "0", 2)
        self.create_metric_card(metrics_frame, "Uptime", "00:00:00", 3)

        # Middle section - Split pane
        paned_window = ttk.PanedWindow(main_container, orient=tk.HORIZONTAL)
        paned_window.pack(fill=tk.BOTH, expand=True)

        # Left panel - Connections list
        left_panel = ttk.Frame(paned_window)
        paned_window.add(left_panel, weight=1)

        ttk.Label(left_panel, text="Connected Clients", font=('Segoe UI', 11, 'bold')).pack(pady=5)

        # Treeview for connections
        tree_frame = ttk.Frame(left_panel)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        tree_scroll = ttk.Scrollbar(tree_frame)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.connections_tree = ttk.Treeview(
            tree_frame,
            columns=('ID', 'IP', 'Port', 'Status', 'Duration'),
            show='headings',
            yscrollcommand=tree_scroll.set,
            selectmode='browse'
        )
        tree_scroll.config(command=self.connections_tree.yview)

        self.connections_tree.heading('ID', text='ID')
        self.connections_tree.heading('IP', text='IP Address')
        self.connections_tree.heading('Port', text='Port')
        self.connections_tree.heading('Status', text='Status')
        self.connections_tree.heading('Duration', text='Duration')

        self.connections_tree.column('ID', width=40, anchor='center')
        self.connections_tree.column('IP', width=130, anchor='w')
        self.connections_tree.column('Port', width=60, anchor='center')
        self.connections_tree.column('Status', width=80, anchor='center')
        self.connections_tree.column('Duration', width=80, anchor='center')

        self.connections_tree.pack(fill=tk.BOTH, expand=True)
        self.connections_tree.bind('<Double-Button-1>', self.on_connection_double_click)
        self.connections_tree.bind('<<TreeviewSelect>>', self.on_tree_select)

        # Connection actions
        action_frame = ttk.Frame(left_panel)
        action_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(action_frame, text="Open session", command=self.open_selected_session).pack(fill=tk.X, pady=2)
        ttk.Button(action_frame, text="Send file", command=self.send_file_to_client).pack(fill=tk.X, pady=2)
        ttk.Button(action_frame, text="Receive file", command=self.receive_file_from_client).pack(fill=tk.X, pady=2)
        ttk.Button(action_frame, text="View history", command=self.view_client_history).pack(fill=tk.X, pady=2)
        ttk.Button(action_frame, text="Disconnect", command=self.disconnect_client).pack(fill=tk.X, pady=2)

        # Right panel - Session tabs
        right_panel = ttk.Frame(paned_window)
        paned_window.add(right_panel, weight=3)

        # Notebook for multiple sessions
        self.session_notebook = ttk.Notebook(right_panel)
        self.session_notebook.pack(fill=tk.BOTH, expand=True)
        self.session_notebook.bind('<<NotebookTabChanged>>', self.on_tab_changed)

        # Welcome tab
        self.create_welcome_tab()

        # Bottom status bar
        status_bar = ttk.Frame(main_container)
        status_bar.pack(fill=tk.X, pady=(10, 0))

        self.status_text = ttk.Label(status_bar, text="Ready to start server...", font=('Consolas', 9))
        self.status_text.pack(side=tk.LEFT)

        self.time_label = ttk.Label(status_bar, text="", font=('Consolas', 9))
        self.time_label.pack(side=tk.RIGHT)
        self.update_time()

    def create_metric_card(self, parent, title, value, column):
        """Create a metric display card"""
        card = ttk.Frame(parent, relief='raised', borderwidth=1)
        card.grid(row=0, column=column, padx=5, pady=5, sticky='ew')
        parent.columnconfigure(column, weight=1)

        ttk.Label(card, text=title, style='MetricTitle.TLabel').pack(pady=(10, 0))

        if column == 0:
            self.metric_connections = ttk.Label(card, text=value, style='Metric.TLabel')
            self.metric_connections.pack(pady=(0, 10))
        elif column == 1:
            self.metric_commands = ttk.Label(card, text=value, style='Metric.TLabel')
            self.metric_commands.pack(pady=(0, 10))
        elif column == 2:
            self.metric_files = ttk.Label(card, text=value, style='Metric.TLabel')
            self.metric_files.pack(pady=(0, 10))
        elif column == 3:
            self.metric_uptime = ttk.Label(card, text=value, style='Metric.TLabel')
            self.metric_uptime.pack(pady=(0, 10))

    def create_welcome_tab(self):
        """Create welcome tab with instructions"""
        welcome_frame = ttk.Frame(self.session_notebook)
        self.session_notebook.add(welcome_frame, text="📋 Welcome")

        welcome_text = scrolledtext.ScrolledText(
            welcome_frame,
            wrap=tk.WORD,
            bg='#1e1e1e',
            fg='#00ff00',
            font=('Consolas', 10),
            insertbackground='white'
        )
        welcome_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        welcome_message = """
NETWORK OPERATIONS CONSOLE

SESSION OVERVIEW
Connected clients appear in the left panel. Select a client and open a session
only when you have permission to administer that device.

SERVER CONTROLS
Start the listener to accept client connections. Refresh checks the current
connections. Reports and Logs provide access to the local activity records.

NETWORK CONFIGURATION
The listener accepts routed connections on all interfaces by default. Set
REMOTE_ADMIN_BIND_HOST to restrict it to one interface. Set REMOTE_ADMIN_TOKEN
to a shared random value of at least 24 characters. The client must trust a copy
of the generated server certificate. Set REMOTE_ADMIN_TLS_NAME to the server
address included in that certificate. A private Wi Fi address is not reachable
across the public Internet unless a route or forwarding rule exists.

SECURITY
The connection uses TLS and a shared authentication token. While a command is
running, follow up text is sent to that process input. On Unix like systems,
sudo is configured to read its password from that input. Submitted text is not
echoed or saved because it may contain credentials. This educational prototype
does not provide role based access control or a full terminal emulator.

ACTIVITY RECORDS
Connection records are stored locally in SQLite. Submitted input is omitted
from records to prevent password and prompt response disclosure.
        """

        welcome_text.insert('1.0', welcome_message)
        welcome_text.config(state=tk.DISABLED)

    def update_time(self):
        """Update time display"""
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.config(text=current_time)
        self.root.after(1000, self.update_time)

    def update_statistics(self):
        """Update statistics display"""
        # Update metrics from database
        try:
            conn_history = self.db.get_connection_history(limit=10000)
            self.total_connections = len(conn_history)
            self.metric_connections.config(text=str(self.total_connections))

            cmd_history = self.db.get_command_history(limit=100000)
            self.total_commands = len(cmd_history)
            self.metric_commands.config(text=str(self.total_commands))
            self.total_files_transferred = self.db.get_file_transfer_count()
            self.metric_files.config(text=str(self.total_files_transferred))

            # Update uptime if server is running
            if self.server_running and hasattr(self, 'start_time'):
                uptime = datetime.now() - self.start_time
                hours, remainder = divmod(int(uptime.total_seconds()), 3600)
                minutes, seconds = divmod(remainder, 60)
                self.metric_uptime.config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        except sqlite3.Error as exc:
            logging.warning("Could not refresh dashboard statistics: %s", exc)

        self.root.after(5000, self.update_statistics)

    def on_tree_select(self, event):
        """Handle tree selection"""
        selection = self.connections_tree.selection()
        if selection:
            item = self.connections_tree.item(selection[0])
            self.selected_connection = int(item['values'][0])

    def on_tab_changed(self, event):
        """Handle tab change"""
        current_tab = self.session_notebook.select()
        tab_text = self.session_notebook.tab(current_tab, "text")

        if tab_text.startswith("Session ") or tab_text.startswith("🖥️ Session "):
            try:
                self.current_session_id = int(tab_text.split()[1].split('-')[0])
            except:
                self.current_session_id = None

    def start_server(self):
        """Start the enterprise server"""
        if not self.server_running:
            if not AUTH_TOKEN or len(AUTH_TOKEN) < 24:
                messagebox.showerror("Authentication required", "Set REMOTE_ADMIN_TOKEN to a random value of at least 24 characters before starting the listener.")
                return
            try:
                ensure_tls_certificate()
            except Exception as exc:
                messagebox.showerror("TLS setup failed", str(exc))
                return
            if not os.path.isfile(TLS_CERT) or not os.path.isfile(TLS_KEY):
                messagebox.showerror("TLS certificate required", f"Create a TLS certificate and private key, then set REMOTE_ADMIN_TLS_CERT and REMOTE_ADMIN_TLS_KEY. Missing: {TLS_CERT} or {TLS_KEY}")
                return
            self.server_running = True
            self.start_time = datetime.now()
            self.status_label.config(text="● STARTING", foreground='#f0b34a')
            self.start_btn.config(state=tk.DISABLED)
            self.log_status(f"Listener started on {SERVER_HOST}:{SERVER_PORT}")

            logging.info("Server started successfully")

            global app_instance
            app_instance = self
            threading.Thread(target=listener_job, daemon=True).start()

    def log_status(self, message):
        """Log status with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.status_text.config(text=f"[{timestamp}] {message}")
        logging.info(message)

    def listener_failed(self, message):
        self.server_running = False
        self.status_label.config(text="● OFFLINE", foreground="#ff4444")
        self.start_btn.config(state=tk.NORMAL)
        self.log_status(f"Listener failed: {message}")
        messagebox.showerror("Listener failed", message)

    def listener_started(self):
        self.status_label.config(text="● ONLINE", foreground="#28b8a7")
        self.log_status(f"TLS listener active on {SERVER_HOST}:{SERVER_PORT}")

    def update_connections_display(self):
        """Update connections display with duration"""
        with connection_lock:
            existing = set(self.connections_tree.get_children())
            for i, (conn, addr) in enumerate(zip(all_connections, all_address)):
                if conn is None or addr is None:
                    continue
                status = "Offline" if i in dead_connections else ("Active" if i in self.active_sessions else "Connected")
                elapsed = int((datetime.now() - connection_times[i]).total_seconds()) if i < len(connection_times) else 0
                hours, remainder = divmod(elapsed, 3600)
                minutes, seconds = divmod(remainder, 60)
                duration = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
                item_id = str(i)
                values = (i, addr[0], addr[1], status, duration)
                if item_id in existing:
                    self.connections_tree.item(item_id, values=values)
                else:
                    self.connections_tree.insert('', tk.END, iid=item_id, values=values)

            active_count = sum(1 for i, conn in enumerate(all_connections)
                              if conn is not None and i not in dead_connections)
            self.conn_count_label.config(text=f"Active: {active_count}")

        self.root.after(1000, self.update_connections_display)

    def refresh_connections(self):
        """Refresh connection list"""
        self.log_status("Refreshing connections...")

        def validate_thread():
            validate_connections()
            self.root.after(0, lambda: self.log_status("Connections refreshed"))

        threading.Thread(target=validate_thread, daemon=True).start()

    def on_connection_double_click(self, event):
        """Handle double-click"""
        self.open_selected_session()

    def open_selected_session(self):
        """Open client session"""
        if self.selected_connection is None:
            selection = self.connections_tree.selection()
            if not selection:
                messagebox.showwarning("No Selection", "Please select a client first")
                return
            item = self.connections_tree.item(selection[0])
            conn_id = int(item['values'][0])
        else:
            conn_id = self.selected_connection

        if conn_id in self.active_sessions:
            tab = self.active_sessions[conn_id]['tab']
            self.session_notebook.select(tab)
            self.log_status(f"Switched to session {conn_id}")
            return

        self.create_session_tab(conn_id)

    def create_session_tab(self, conn_id):
        """Create new session tab"""
        try:
            with connection_lock:
                if conn_id >= len(all_connections) or all_connections[conn_id] is None or conn_id in dead_connections:
                    messagebox.showerror("Error", "Connection no longer exists")
                    return

                conn = all_connections[conn_id]
                addr = all_address[conn_id]

            # Log to database
            db_id = self.db_connection_ids.get(conn_id)
            if db_id is None:
                db_id = self.db.log_connection(addr[0], addr[1])
                self.db_connection_ids[conn_id] = db_id
            else:
                self.db.update_connection_status(db_id, "connected")

            session_frame = ttk.Frame(self.session_notebook)
            tab_title = f"Session {conn_id}  {addr[0]}"
            self.session_notebook.add(session_frame, text=tab_title)

            output_frame = ttk.Frame(session_frame)
            output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

            output_text = scrolledtext.ScrolledText(
                output_frame,
                wrap=tk.WORD,
                bg='#0c0c0c',
                fg='#00ff00',
                font=('Consolas', 10),
                insertbackground='white'
            )
            output_text.pack(fill=tk.BOTH, expand=True)

            welcome = f"""
╔══════════════════════════════════════════════════════════════╗
  ENTERPRISE SESSION {conn_id} - {addr[0]}:{addr[1]}
╚══════════════════════════════════════════════════════════════╝

Session ID: {db_id}
Established: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Status: Active
Transport: TLS encrypted
Authentication: Shared token

Input is not echoed or recorded because it may contain credentials.
While a process is running, the next entry is sent to its standard input.

"""
            output_text.insert(tk.END, welcome)
            output_text.see(tk.END)

            input_frame = ttk.Frame(session_frame)
            input_frame.pack(fill=tk.X, padx=5, pady=5)

            ttk.Label(input_frame, text=f"{addr[0]}>", font=('Consolas', 10, 'bold')).pack(side=tk.LEFT, padx=(0, 5))

            input_entry = ttk.Entry(input_frame, font=('Consolas', 10))
            input_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

            send_btn = ttk.Button(
                input_frame,
                text="Send",
                command=lambda: self.send_command(conn_id, input_entry, output_text)
            )
            send_btn.pack(side=tk.LEFT, padx=5)

            ttk.Button(
                input_frame,
                text="Message",
                command=lambda: self.send_message_to_client(conn_id, input_entry, output_text)
            ).pack(side=tk.LEFT, padx=5)

            ttk.Button(
                input_frame,
                text="Interrupt",
                command=lambda: self.interrupt_command(conn_id)
            ).pack(side=tk.LEFT, padx=5)

            input_entry.bind('<Return>', lambda e: self.send_command(conn_id, input_entry, output_text))

            self.active_sessions[conn_id] = {
                'tab': session_frame,
                'output': output_text,
                'input': input_entry,
                'history': [],
                'history_index': -1,
                'conn': conn,
                'db_id': db_id
            }

            self.session_notebook.select(session_frame)
            self.current_session_id = conn_id
            input_entry.focus()

            self.log_status(f"Enterprise session {conn_id} opened")
            logging.info(f"Session opened: {addr[0]}:{addr[1]} (DB ID: {db_id})")

        except Exception as e:
            messagebox.showerror("Session Error", f"Failed to create session: {str(e)}")
            logging.error(f"Session creation failed: {e}")

    def send_command(self, conn_id, input_entry, output_text):
        text = input_entry.get()
        if text == "":
            return
        if len(text) > 65536:
            messagebox.showerror("Input too long", "Input must not exceed 65536 characters.")
            return
        try:
            with connection_lock:
                if conn_id >= len(all_connections) or all_connections[conn_id] is None or conn_id in dead_connections:
                    raise ConnectionError("Client is disconnected")
                channel = all_connections[conn_id]
            output_text.insert(tk.END, "\n[sending input; hidden for privacy]\n", "command")
            input_entry.delete(0, tk.END)

            def transmit():
                try:
                    channel.send({"type": "input", "text": text})
                    session = self.active_sessions.get(conn_id)
                    if session and session.get("db_id"):
                        self.db.log_command(session["db_id"], "[input omitted for privacy]")
                    self.root.after(0, lambda: output_text.insert(tk.END, "[input sent]\n", "command"))
                except Exception as exc:
                    detail = str(exc)
                    self.root.after(0, lambda: output_text.insert(tk.END, f"[ERROR] Could not send input: {detail}\n", "error"))
                    logging.error("Could not send input to client %s: %s", conn_id, exc)
                self.root.after(0, output_text.see, tk.END)
            threading.Thread(target=transmit, daemon=True).start()
        except Exception as exc:
            output_text.insert(tk.END, f"\n[ERROR] Could not send input: {exc}\n", "error")
            output_text.tag_config("error", foreground="#ff4444")
            logging.error("Could not send input to client %s: %s", conn_id, exc)

    def interrupt_command(self, conn_id):
        try:
            with connection_lock:
                if conn_id >= len(all_connections) or all_connections[conn_id] is None or conn_id in dead_connections:
                    raise ConnectionError("Client is disconnected")
                all_connections[conn_id].send({"type": "interrupt"})
            self.log_status(f"Interrupt requested for client {conn_id}")
        except Exception as exc:
            messagebox.showerror("Interrupt failed", str(exc))

    def send_message_to_client(self, conn_id, input_entry, output_text):
        text = input_entry.get()
        if not text:
            return
        if len(text) > 65536:
            messagebox.showerror("Message too long", "Message must not exceed 65536 characters.")
            return
        with connection_lock:
            if conn_id >= len(all_connections) or all_connections[conn_id] is None or conn_id in dead_connections:
                messagebox.showerror("Client unavailable", "The selected client is disconnected.")
                return
            channel = all_connections[conn_id]
        input_entry.delete(0, tk.END)
        output_text.insert(tk.END, "\n[sending client message]\n", "command")
        def transmit():
            try:
                channel.send({"type": "message", "text": text})
            except Exception as exc:
                detail = str(exc)
                self.root.after(0, lambda message=detail: output_text.insert(tk.END, f"[ERROR] Message delivery failed: {message}\n", "error"))
        threading.Thread(target=transmit, daemon=True).start()

    def history_up(self, conn_id, input_entry):
        """Navigate command history up"""
        if conn_id not in self.active_sessions:
            return

        session = self.active_sessions[conn_id]
        history = session['history']

        if not history:
            return

        if session['history_index'] > 0:
            session['history_index'] -= 1

        if session['history_index'] >= 0 and session['history_index'] < len(history):
            input_entry.delete(0, tk.END)
            input_entry.insert(0, history[session['history_index']])

    def history_down(self, conn_id, input_entry):
        """Navigate command history down"""
        if conn_id not in self.active_sessions:
            return

        session = self.active_sessions[conn_id]
        history = session['history']

        if not history:
            return

        if session['history_index'] < len(history) - 1:
            session['history_index'] += 1
            input_entry.delete(0, tk.END)
            input_entry.insert(0, history[session['history_index']])
        else:
            session['history_index'] = len(history)
            input_entry.delete(0, tk.END)

    def close_session(self, conn_id):
        """Close session with database update"""
        if conn_id in self.active_sessions:
            # Update database
            db_id = self.active_sessions[conn_id].get('db_id')
            if db_id:
                self.db.update_connection_status(db_id, 'closed')

            tab = self.active_sessions[conn_id]['tab']
            self.session_notebook.forget(tab)
            del self.active_sessions[conn_id]
            self.log_status(f"Session {conn_id} closed")
            logging.info(f"Session {conn_id} closed")

    def send_file_to_client(self):
        if self.selected_connection is None:
            selection = self.connections_tree.selection()
            if not selection:
                messagebox.showwarning("No Selection", "Select a connected client first")
                return
            conn_id = int(self.connections_tree.item(selection[0])["values"][0])
        else:
            conn_id = self.selected_connection
        path = filedialog.askopenfilename(title="Select a file to send")
        if not path:
            return
        size = os.path.getsize(path)
        if size > MAX_FILE_SIZE:
            messagebox.showerror("File too large", "The maximum transfer size is 128 MiB.")
            return
        with connection_lock:
            if conn_id >= len(all_connections) or all_connections[conn_id] is None or conn_id in dead_connections:
                messagebox.showerror("Client unavailable", "The selected client is disconnected.")
                return
            channel = all_connections[conn_id]
        def transfer():
            try:
                expected = file_sha256(path)
                def frames():
                    yield {"type": "upload_start", "name": os.path.basename(path), "size": size, "sha256": expected}
                    with open(path, "rb") as source:
                        while chunk := source.read(FILE_CHUNK_SIZE):
                            yield {"type": "upload_chunk", "data": base64.b64encode(chunk).decode("ascii")}
                    yield {"type": "upload_end"}
                channel.send_sequence(frames())
                self.root.after(0, lambda: self.log_status(f"Upload sent to client for verification: {os.path.basename(path)}"))
            except Exception as exc:
                error_text = str(exc)
                try:
                    channel.send({"type": "upload_error", "message": error_text[:500]})
                except Exception:
                    pass
                self.root.after(0, lambda message=error_text: messagebox.showerror("Transfer failed", message))
        threading.Thread(target=transfer, daemon=True).start()

    def receive_file_from_client(self):
        if self.selected_connection is None:
            selection = self.connections_tree.selection()
            if not selection:
                messagebox.showwarning("No Selection", "Select a connected client first")
                return
            conn_id = int(self.connections_tree.item(selection[0])["values"][0])
        else:
            conn_id = self.selected_connection
        from tkinter import simpledialog
        remote_path = simpledialog.askstring("Download from client", "Enter the file path on the client:")
        if not remote_path:
            return
        save_path = filedialog.asksaveasfilename(title="Save received file", initialfile=os.path.basename(remote_path))
        if not save_path:
            return
        with connection_lock:
            if conn_id >= len(all_connections) or all_connections[conn_id] is None or conn_id in dead_connections:
                messagebox.showerror("Client unavailable", "The selected client is disconnected.")
                return
            channel = all_connections[conn_id]
        with download_lock:
            if channel in pending_downloads:
                messagebox.showwarning("Download active", "A download is already active for this client.")
                return
            pending_downloads[channel] = save_path
        try:
            channel.send({"type": "download_request", "path": remote_path})
            self.log_status("Requested a client file download")
        except Exception as exc:
            with download_lock:
                pending_downloads.pop(channel, None)
            messagebox.showerror("Download failed", str(exc))

    def view_client_history(self):
        """View command history for selected client"""
        if self.selected_connection is None:
            selection = self.connections_tree.selection()
            if not selection:
                messagebox.showwarning("No Selection", "Please select a client first")
                return
            item = self.connections_tree.item(selection[0])
            conn_id = int(item['values'][0])
        else:
            conn_id = self.selected_connection

        if conn_id not in self.active_sessions:
            messagebox.showinfo("No History", "Open a session first to view history")
            return

        db_id = self.active_sessions[conn_id].get('db_id')
        if not db_id:
            messagebox.showinfo("No History", "No database record found")
            return

        history = self.db.get_command_history(db_id, limit=50)

        # Create history window
        history_window = tk.Toplevel(self.root)
        history_window.title(f"Command History - Client {conn_id}")
        history_window.geometry("800x600")
        history_window.configure(bg='#1e1e1e')

        text = scrolledtext.ScrolledText(
            history_window,
            wrap=tk.WORD,
            bg='#0c0c0c',
            fg='#00ff00',
            font=('Consolas', 9)
        )
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        text.insert('1.0', f"Command History for Client {conn_id} (Database ID: {db_id})\n")
        text.insert(tk.END, "=" * 80 + "\n\n")

        for record in history:
            cmd_id, conn_id_db, command, output, exec_time = record
            text.insert(tk.END, f"[{exec_time}] $ {command}\n", 'command')
            if output:
                text.insert(tk.END, f"{output[:200]}...\n\n" if len(output) > 200 else f"{output}\n\n")

        text.tag_config('command', foreground='#00aaff')
        text.config(state=tk.DISABLED)

    def disconnect_client(self):
        """Disconnect client with database update"""
        if self.selected_connection is None:
            selection = self.connections_tree.selection()
            if not selection:
                messagebox.showwarning("No Selection", "Please select a client first")
                return
            item = self.connections_tree.item(selection[0])
            conn_id = int(item['values'][0])
        else:
            conn_id = self.selected_connection

        if messagebox.askyesno("Confirm", f"Disconnect client {conn_id}?"):
            try:
                if conn_id in self.active_sessions:
                    db_id = self.active_sessions[conn_id].get('db_id')
                    if db_id:
                        self.db.update_connection_status(db_id, 'disconnected')
                    self.close_session(conn_id)

                with connection_lock:
                    if conn_id < len(all_connections):
                        conn = all_connections[conn_id]
                        if conn is not None:
                            conn.close()
                        all_connections[conn_id] = None
                        all_address[conn_id] = None
                        dead_connections.add(conn_id)

                self.log_status(f"Client {conn_id} disconnected")
                logging.info(f"Client {conn_id} disconnected by user")

            except Exception as e:
                messagebox.showerror("Error", f"Failed to disconnect: {str(e)}")
                logging.error(f"Disconnect failed: {e}")

    def show_reports(self):
        """Show reports window"""
        reports_window = tk.Toplevel(self.root)
        reports_window.title("System Reports")
        reports_window.geometry("900x700")
        reports_window.configure(bg='#1e1e1e')

        notebook = ttk.Notebook(reports_window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Connection report
        conn_frame = ttk.Frame(notebook)
        notebook.add(conn_frame, text="📊 Connections")

        conn_text = scrolledtext.ScrolledText(conn_frame, wrap=tk.WORD, bg='#0c0c0c', fg='#00ff00',
                                              font=('Consolas', 9))
        conn_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        conn_history = self.db.get_connection_history(100)
        conn_text.insert('1.0', "CONNECTION HISTORY REPORT\n")
        conn_text.insert(tk.END, "=" * 80 + "\n\n")

        for record in conn_history:
            conn_id, ip, port, connect_time, disconnect_time, status = record
            conn_text.insert(tk.END, f"ID: {conn_id} | {ip}:{port} | {status}\n")
            conn_text.insert(tk.END, f"  Connected: {connect_time}\n")
            if disconnect_time:
                conn_text.insert(tk.END, f"  Disconnected: {disconnect_time}\n")
            conn_text.insert(tk.END, "\n")

        conn_text.config(state=tk.DISABLED)

        # Command report
        cmd_frame = ttk.Frame(notebook)
        notebook.add(cmd_frame, text="⌨️ Commands")

        cmd_text = scrolledtext.ScrolledText(cmd_frame, wrap=tk.WORD, bg='#0c0c0c', fg='#00ff00', font=('Consolas', 9))
        cmd_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        cmd_history = self.db.get_command_history(limit=100)
        cmd_text.insert('1.0', "COMMAND EXECUTION REPORT\n")
        cmd_text.insert(tk.END, "=" * 80 + "\n\n")

        for record in cmd_history:
            cmd_id, conn_id, command, output, exec_time = record
            cmd_text.insert(tk.END, f"[{exec_time}] Connection {conn_id}\n")
            cmd_text.insert(tk.END, f"  Command: {command}\n\n")

        cmd_text.config(state=tk.DISABLED)

    def show_logs(self):
        """Show log file"""
        try:
            with open('reverse_shell_server.log', 'r') as f:
                logs = f.read()

            log_window = tk.Toplevel(self.root)
            log_window.title("Server Logs")
            log_window.geometry("1000x700")
            log_window.configure(bg='#1e1e1e')

            log_text = scrolledtext.ScrolledText(
                log_window,
                wrap=tk.WORD,
                bg='#0c0c0c',
                fg='#00ff00',
                font=('Consolas', 9)
            )
            log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            log_text.insert('1.0', logs)
            log_text.see(tk.END)
            log_text.config(state=tk.DISABLED)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to open logs: {str(e)}")

    def clear_all_sessions(self):
        """Clear all sessions"""
        if messagebox.askyesno("Confirm", "Close all active sessions?"):
            for conn_id in list(self.active_sessions.keys()):
                self.close_session(conn_id)
            self.log_status("All sessions cleared")
            logging.info("All sessions cleared by user")


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        while chunk := source.read(FILE_CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def create_socket():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((SERVER_HOST, SERVER_PORT))
        server_socket.listen(20)
        return server_socket
    except OSError:
        server_socket.close()
        raise


def client_reader(channel, index, address):
    download = None
    try:
        while True:
            message = channel.receive()
            with connection_lock:
                if index < len(connection_last_seen):
                    connection_last_seen[index] = time.monotonic()
            kind = message["type"]
            if kind == "output":
                value = str(message.get("text", ""))
                if len(value) > 200000:
                    value = value[:200000] + "\n[output chunk clipped]\n"
                if app_instance:
                    def display_output(value=value):
                        session = app_instance.active_sessions.get(index)
                        if session:
                            widget = session["output"]
                            widget.insert(tk.END, value)
                            widget.see(tk.END)
                    app_instance.root.after(0, display_output)
            elif kind == "process_exit":
                pass
            elif kind == "message_ack":
                size = int(message.get("length", 0))
                if app_instance:
                    def show_ack(size=size):
                        session = app_instance.active_sessions.get(index)
                        if session:
                            widget = session["output"]
                            widget.insert(tk.END, f"\n[message delivered to client, {size} characters]\n")
                            widget.see(tk.END)
                    app_instance.root.after(0, show_ack)
            elif kind == "upload_complete":
                name = os.path.basename(str(message.get("name", "file")))
                size = int(message.get("size", 0))
                if app_instance:
                    db_id = app_instance.db_connection_ids.get(index)
                    if db_id:
                        app_instance.db.log_file_transfer(db_id, name, "upload", size)
                    app_instance.root.after(0, lambda n=name, z=size: app_instance.log_status(f"Uploaded {n} ({z} bytes) to client {index}"))
            elif kind == "download_start":
                size = message.get("size")
                name = os.path.basename(str(message.get("name", "download")))
                with download_lock:
                    save_path = pending_downloads.get(channel)
                if not isinstance(size, int) or size < 0 or size > MAX_FILE_SIZE or not save_path:
                    download = {"failed": "Invalid size or no pending destination"}
                    continue
                temporary = save_path + ".part"
                try:
                    output_file = open(temporary, "wb")
                    download = {"path": save_path, "temporary": temporary, "size": size,
                                "expected_hash": str(message.get("sha256", "")),
                                "received": 0, "digest": hashlib.sha256(), "name": name,
                                "file": output_file}
                except OSError as exc:
                    download = {"failed": f"Could not create download file: {exc}"}
            elif kind == "download_chunk":
                if not download:
                    raise ValueError("Received download data without a start frame")
                if download.get("failed"):
                    continue
                try:
                    chunk = base64.b64decode(message.get("data", ""), validate=True)
                    download["received"] += len(chunk)
                    if download["received"] > download["size"]:
                        raise ValueError("Download exceeded its declared size")
                    download["file"].write(chunk)
                    download["digest"].update(chunk)
                except (ValueError, OSError) as exc:
                    download["failed"] = str(exc)
                    try:
                        download["file"].close()
                        os.remove(download["temporary"])
                    except OSError:
                        pass
            elif kind == "download_end":
                if not download:
                    raise ValueError("Received download end without a start frame")
                if download.get("failed"):
                    error = str(download["failed"])[:500]
                    channel.send({"type": "download_error", "message": error})
                    with download_lock:
                        pending_downloads.pop(channel, None)
                    if app_instance:
                        app_instance.root.after(0, lambda t=error: app_instance.log_status(f"Transfer error: {t}"))
                    download = None
                    continue
                download["file"].close()
                expected = str(message.get("sha256", ""))
                if (download["received"] != download["size"] or
                        not hmac.compare_digest(download["expected_hash"], expected) or
                        not hmac.compare_digest(download["digest"].hexdigest(), expected)):
                    download["file"].close()
                    try:
                        os.remove(download["temporary"])
                    except OSError:
                        pass
                    download = None
                    with download_lock:
                        pending_downloads.pop(channel, None)
                    channel.send({"type": "download_error", "message": "Download size or integrity check failed"})
                    if app_instance:
                        app_instance.root.after(0, lambda: app_instance.log_status("Transfer error: download integrity check failed"))
                    continue
                os.replace(download["temporary"], download["path"])
                if app_instance:
                    save_path = download["path"]
                    db_id = app_instance.db_connection_ids.get(index)
                    if db_id:
                        app_instance.db.log_file_transfer(db_id, download["name"], "download", download["size"])
                    app_instance.root.after(0, lambda p=save_path: app_instance.log_status(f"Download saved to {p}"))
                with download_lock:
                    pending_downloads.pop(channel, None)
                download = None
            elif kind in {"upload_error", "download_error"}:
                text = str(message.get("message", "Transfer failed"))[:500]
                if kind == "download_error":
                    with download_lock:
                        pending_downloads.pop(channel, None)
                if app_instance:
                    app_instance.root.after(0, lambda t=text: app_instance.log_status(f"Transfer error: {t}"))
                if download:
                    download["file"].close()
                    try:
                        os.remove(download["temporary"])
                    except OSError:
                        pass
                    download = None
            elif kind == "pong":
                continue
            else:
                logging.warning("Unknown client message type %s from %s", kind, address[0])
    except (ConnectionError, OSError, ssl.SSLError, ValueError) as exc:
        logging.info("Client %s disconnected: %s", address[0], exc)
    finally:
        with download_lock:
            pending_downloads.pop(channel, None)
        if download:
            try:
                if download.get("file"):
                    download["file"].close()
                if download.get("temporary"):
                    os.remove(download["temporary"])
            except (OSError, KeyError):
                pass
        with connection_lock:
            dead_connections.add(index)
        if app_instance:
            db_id = app_instance.db_connection_ids.get(index)
            if db_id:
                try:
                    app_instance.db.update_connection_status(db_id, "disconnected")
                except sqlite3.Error:
                    logging.exception("Could not update disconnected session record")
            app_instance.root.after(0, lambda: app_instance.log_status(f"Client {index} disconnected"))
        try:
            channel.close()
        except OSError:
            pass


def accepting_connections():
    global s
    try:
        s = create_socket()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(TLS_CERT, TLS_KEY)
        logging.info("TLS listener active on %s:%s", SERVER_HOST, SERVER_PORT)
        if app_instance:
            app_instance.root.after(0, app_instance.listener_started)
    except OSError as exc:
        logging.exception("Could not start listener")
        if s is not None:
            try:
                s.close()
            except OSError:
                pass
            s = None
        if app_instance:
            error_message = str(exc)
            app_instance.root.after(0, lambda text=error_message: app_instance.listener_failed(text))
        return

    while True:
        try:
            raw, address = s.accept()
            raw.settimeout(12)
            try:
                secure = context.wrap_socket(raw, server_side=True)
                channel = FramedSocket(secure)
                with connection_lock:
                    active_total = sum(1 for i, item in enumerate(all_connections)
                                       if item is not None and i not in dead_connections)
                if not authenticate(channel, AUTH_TOKEN, active_total < MAX_CLIENTS):
                    channel.close()
                    logging.warning("Rejected unauthenticated client %s", address[0])
                    continue
                channel.settimeout(None)
            except Exception:
                raw.close()
                logging.warning("Rejected invalid TLS or authentication handshake from %s", address[0])
                continue
            with connection_lock:
                index = len(all_connections)
                all_connections.append(channel)
                all_address.append(address)
                connection_times.append(datetime.now())
                connection_last_seen.append(time.monotonic())
                dead_connections.discard(index)
            logging.info("Authenticated client connected from %s:%s", address[0], address[1])
            threading.Thread(target=client_reader, args=(channel, index, address), daemon=True).start()
        except OSError as exc:
            logging.error("Listener accept failed: %s", exc)
            time.sleep(0.5)


def validate_connections():
    """Send framed heartbeat requests without competing for the receive stream."""
    now = time.monotonic()
    with connection_lock:
        clients = [(i, conn) for i, conn in enumerate(all_connections)
                   if conn is not None and i not in dead_connections]
    for index, channel in clients:
        if index < len(connection_last_seen) and now - connection_last_seen[index] > 45:
            with connection_lock:
                dead_connections.add(index)
            try:
                channel.close()
            except OSError:
                pass
            continue
        try:
            channel.send({"type": "ping"})
        except (OSError, ValueError, ConnectionError):
            with connection_lock:
                dead_connections.add(index)


def listener_job():
    threading.Thread(target=heartbeat_loop, daemon=True).start()
    accepting_connections()


def heartbeat_loop():
    while True:
        time.sleep(15)
        validate_connections()


def main():
    """Main entry point"""
    logging.info("=" * 80)
    logging.info("REVERSE SHELL SERVER")
    logging.info("=" * 80)

    root = tk.Tk()
    app = ReverseShellGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
