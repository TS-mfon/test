"""Authenticated TLS client for the Python remote administration project."""
import base64
import codecs
import hashlib
import json
import ntpath
import os
import re
import socket
import ssl
import struct
import signal
import subprocess
import threading
import time
from pathlib import Path

SERVER_IP = os.environ.get("REMOTE_ADMIN_SERVER", "192.168.0.22")
SERVER_PORT = int(os.environ.get("REMOTE_ADMIN_PORT", "9999"))
SERVER_CERT = os.environ.get("REMOTE_ADMIN_SERVER_CERT", "server-cert.pem")
AUTH_TOKEN = os.environ.get("REMOTE_ADMIN_TOKEN", "yoX2XXdUhc1PIY8boIwPHAzFnNG61ydo51aZDVH7VKQ")
MAX_FILE_SIZE = 128 * 1024 * 1024
FILE_CHUNK_SIZE = 48 * 1024
active_process = None
process_lock = threading.Lock()
MAX_FRAME_SIZE = 8 * 1024 * 1024


class FramedSocket:
    """Length framed JSON transport, kept inside the client application."""
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


def connect_to_server():
    if len(AUTH_TOKEN) < 24:
        raise RuntimeError("REMOTE_ADMIN_TOKEN must contain at least 24 characters")
    if not os.path.isfile(SERVER_CERT):
        raise RuntimeError(f"Trusted server certificate was not found: {SERVER_CERT}")
    context = ssl.create_default_context(cafile=SERVER_CERT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    delay = 2
    while True:
        raw = None
        try:
            raw = socket.create_connection((SERVER_IP, SERVER_PORT), timeout=12)
            tls_socket = context.wrap_socket(raw, server_hostname=SERVER_IP)
            tls_socket.settimeout(12)
            channel = FramedSocket(tls_socket)
            channel.send({"type": "auth", "token": AUTH_TOKEN})
            response = channel.receive()
            if response["type"] != "auth_ok":
                channel.close()
                raise RuntimeError(str(response.get("message", "Server rejected authentication")))
            tls_socket.settimeout(None)
            print(f"[+] Authenticated TLS connection to {SERVER_IP}:{SERVER_PORT}")
            return channel
        except (ssl.SSLCertVerificationError, RuntimeError, ValueError):
            if raw:
                raw.close()
            raise
        except (OSError, ssl.SSLError, ConnectionError) as exc:
            if raw:
                try:
                    raw.close()
                except OSError:
                    pass
            print(f"[-] Connection unavailable: {exc}. Retrying in {delay} seconds")
            time.sleep(delay)
            delay = min(delay * 2, 30)


def send_output(channel, text):
    if text:
        channel.send({"type": "output", "text": text})


def stop_process(process, force=False):
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL if force else signal.SIGTERM)
        elif force:
            process.kill()
        else:
            process.terminate()
    except (OSError, ProcessLookupError):
        pass


def run_interactive(command, channel):
    global active_process
    if len(command) > 65536:
        send_output(channel, "Command is too long. Maximum length is 65536 characters.\n")
        return
    with process_lock:
        if active_process is not None and active_process.poll() is None:
            send_output(channel, "A process is already running. Send its input or interrupt it first.\n")
            return
        try:
            if os.name == "posix":
                command = re.sub(r"^(\s*)sudo(?=\s|$)", r"\1sudo -S", command, count=1)
            process = subprocess.Popen(
                command,
                shell=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=(os.name == "posix"),
            )
            active_process = process
        except (OSError, ValueError) as exc:
            send_output(channel, f"Could not start command: {exc}\n")
            return

    def stream_output():
        global active_process
        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        try:
            while True:
                # read1 returns currently available pipe data instead of
                # waiting for a full chunk, which keeps short prompts visible.
                data = process.stdout.read1(FILE_CHUNK_SIZE)
                if not data:
                    break
                send_output(channel, decoder.decode(data))
            remaining = decoder.decode(b"", final=True)
            if remaining:
                send_output(channel, remaining)
            return_code = process.wait()
            send_output(channel, f"\n[process exited with status {return_code}]\n")
        except (OSError, ssl.SSLError, ConnectionError, ValueError):
            stop_process(process, force=True)
        finally:
            with process_lock:
                if active_process is process:
                    active_process = None

    threading.Thread(target=stream_output, daemon=True).start()


def route_input(channel, text):
    global active_process
    with process_lock:
        process = active_process
        if process is not None and process.poll() is None:
            try:
                process.stdin.write((text + "\n").encode("utf-8"))
                process.stdin.flush()
            except (BrokenPipeError, OSError):
                send_output(channel, "The running process no longer accepts input.\n")
            return
    command = text.strip()
    if not command:
        return
    if command.lower() in {"exit", "quit"}:
        raise EOFError
    if command.lower() == "help":
        send_output(channel, "Commands run on this client. Follow up input goes to a running process. Use exit to disconnect.\n")
        return
    if command.lower().startswith("cd "):
        try:
            os.chdir(os.path.expanduser(command[3:].strip()))
            send_output(channel, f"Changed directory to: {os.getcwd()}\n")
        except OSError as exc:
            send_output(channel, f"Directory change failed: {exc}\n")
        return
    run_interactive(command, channel)


def receive_upload(channel, start):
    supplied_name = str(start.get("name", "upload.bin"))
    name = Path(ntpath.basename(supplied_name)).name
    if name in {"", ".", ".."}:
        name = "upload.bin"
    size = start.get("size")
    expected_hash = start.get("sha256")
    if not isinstance(size, int) or size < 0 or size > MAX_FILE_SIZE:
        send_output(channel, "Upload rejected: invalid or oversized file.\n")
        return
    destination = Path.cwd() / name
    temporary = destination.with_name(destination.name + ".part")
    if destination.exists():
        channel.send({"type": "upload_error", "message": f"Destination already exists: {name}"})
        return
    digest = hashlib.sha256()
    received = 0
    try:
        with temporary.open("wb") as output:
            while True:
                message = channel.receive()
                if message["type"] == "upload_end":
                    break
                if message["type"] == "upload_error":
                    raise ValueError(str(message.get("message", "Upload was rejected")))
                if message["type"] != "upload_chunk":
                    raise ValueError("Unexpected message during file upload")
                chunk = base64.b64decode(message.get("data", ""), validate=True)
                received += len(chunk)
                if received > size:
                    raise ValueError("Upload exceeded its declared size")
                output.write(chunk)
                digest.update(chunk)
        if received != size or digest.hexdigest() != expected_hash:
            raise ValueError("Upload size or integrity check failed")
        os.replace(temporary, destination)
        channel.send({"type": "upload_complete", "name": name, "size": size})
    except Exception as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        channel.send({"type": "upload_error", "message": str(exc)[:500]})


def send_download(channel, request):
    path = Path(os.path.expanduser(str(request.get("path", "")))).resolve()
    if not path.is_file():
        channel.send({"type": "download_error", "message": "File not found"})
        return
    size = path.stat().st_size
    if size > MAX_FILE_SIZE:
        channel.send({"type": "download_error", "message": "File exceeds 128 MiB limit"})
        return
    expected = _file_hash(path)
    def frames():
        yield {"type": "download_start", "name": path.name, "size": size, "sha256": expected}
        with path.open("rb") as source:
            while chunk := source.read(FILE_CHUNK_SIZE):
                yield {"type": "download_chunk", "data": base64.b64encode(chunk).decode("ascii")}
        yield {"type": "download_end", "sha256": expected}
    try:
        channel.send_sequence(frames())
    except (OSError, ValueError, ConnectionError) as exc:
        channel.send({"type": "download_error", "message": str(exc)[:500]})


def _file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(FILE_CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def handle_message(channel, message):
    kind = message["type"]
    if kind == "input":
        route_input(channel, str(message.get("text", "")))
    elif kind == "upload_start":
        receive_upload(channel, message)
    elif kind == "download_request":
        send_download(channel, message)
    elif kind == "download_error":
        send_output(channel, "File download failed: " + str(message.get("message", "unknown error")) + "\n")
    elif kind == "message":
        text = str(message.get("text", ""))[:65536]
        print(f"\n[SERVER MESSAGE] {text}", flush=True)
        channel.send({"type": "message_ack", "length": len(text)})
    elif kind == "ping":
        channel.send({"type": "pong"})
    elif kind == "interrupt":
        with process_lock:
            process = active_process
        if process is not None and process.poll() is None:
            try:
                if os.name == "posix": os.killpg(process.pid, signal.SIGINT)
                else: process.terminate()
            except OSError as exc:
                send_output(channel, f"Could not interrupt process: {exc}\n")
    elif kind == "shutdown":
        raise EOFError


def main():
    global active_process
    print("NETWORK OPERATIONS CLIENT")
    print(f"Server: {SERVER_IP}:{SERVER_PORT}")
    try:
        channel = connect_to_server()
    except (RuntimeError, OSError, ssl.SSLError) as exc:
        print(f"[-] Client setup failed: {exc}")
        return
    print("[*] TLS encrypted and authenticated session established")
    print("[*] Follow up input is sent to the active process")
    try:
        while True:
            handle_message(channel, channel.receive())
    except (EOFError, ConnectionError):
        pass
    except KeyboardInterrupt:
        print("\n[*] Disconnecting")
    except Exception as exc:
        print(f"[-] Session ended: {exc}")
    finally:
        with process_lock:
            process = active_process
        if process is not None and process.poll() is None:
            stop_process(process)
        channel.close()


if __name__ == "__main__":
    main()
