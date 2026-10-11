# Python Remote Administration Project

## Project files

`institutional sever.py` is the graphical server application. The original filename contains the spelling `sever`, so use that exact filename when launching it. `institutional client.py` is the client program that runs on each managed computer. These are the only two Python application files. Each file contains its own implementation of the same length framed JSON transport. `PJ reworked.docx` is the project report. The server and client are written in Python. The server uses Tkinter for its desktop interface and the Python `cryptography` package to create and validate its TLS certificate.

## What the application does

The client initiates an outbound connection to the configured server. After TLS certificate validation and shared token authentication, the server displays the client in its connection table. Selecting the client and opening a session enables command input, streamed output, process interruption, file upload, and file download. If a command is waiting for input, the next entry is sent to that running process. This includes answers such as `y` or `n` and line based password prompts. On Unix like systems, commands beginning with `sudo` are changed to use `sudo -S`, which reads the password from standard input.

Submitted text is hidden in the server interface and is not stored in SQLite. The database records a redacted activity marker and file transfer metadata. The communication channel uses TLS. The client trusts a copy of the server certificate, and the server requires a shared authentication token. The application does not provide automatic Internet discovery, a relay service, a full terminal emulator, individual user accounts, or role based access control.

A client cannot connect to a server address that is not routable from the client. A Wi Fi adapter address is usually private. A connection from another network therefore needs a reachable public address with router forwarding, a VPN route, or another network path to the server. The client connects outward to the server. It does not make an unreachable server discoverable.

## Requirements

Use Python 3.10 or later on both computers. The server computer needs Python with Tkinter enabled and the Python dependency listed in `requirements.txt`. The client needs Python 3.10 or later. Run both programs from the project directory, or configure full paths for the certificate and other files.

Install the server dependency from the project directory with `python -m pip install -r requirements.txt` on Windows or `python3 -m pip install -r requirements.txt` on Linux. Tkinter is included with many Python installers. Some Linux distributions package Tkinter separately from Python, so the server interpreter must have its Tk support installed. No third party package is needed on the client.

## Generate the shared authentication token

Generate a strong token on the server computer with Python. The following command creates a URL safe secret with 32 random bytes.

On Windows PowerShell, run:

```powershell
$token = python -c "import secrets; print(secrets.token_urlsafe(32))"
$env:REMOTE_ADMIN_TOKEN = $token
$token
```

On Linux or macOS, run:

```sh
export REMOTE_ADMIN_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
printf '%s\n' "$REMOTE_ADMIN_TOKEN"
```

Keep the printed value private. Set the same value in the environment of the client process on each test computer. The server refuses to start if the token has fewer than 24 characters. The generated token is 43 characters. A new PowerShell window or terminal does not inherit variables from another window, so set the variable again in each process environment that needs it. Do not put the token in source code, screenshots, the report, or a public repository.

## Configure the server certificate

Choose the exact address the client will use before the first server start. The certificate identity must match `REMOTE_ADMIN_SERVER` on the client. For a local test use `127.0.0.1`. For a LAN test use the server computer's reachable LAN address. For a public test use the public IP address or DNS name that the client will connect to.

Set `REMOTE_ADMIN_TLS_NAME` before starting the server. On PowerShell, for example:

```powershell
$env:REMOTE_ADMIN_TLS_NAME = "127.0.0.1"
```

On Linux or macOS:

```sh
export REMOTE_ADMIN_TLS_NAME="127.0.0.1"
```

The first time the listener starts, it creates `server-cert.pem` and `server-key.pem` in the current project directory. The private key must remain on the server computer. Copy only `server-cert.pem` to each client using a trusted method. Do not send the private key to a client. The client uses the certificate file to verify the server.

If the server certificate already exists with a different name, the server reports a name mismatch. Set the desired `REMOTE_ADMIN_TLS_NAME`, then remove or rename the old certificate and key so the server can create a new pair. Keep a backup only if needed. Replacing the certificate requires copying the new certificate to every client. The certificate is self signed, so trust comes from distributing that exact certificate securely.

The Python server requires the `cryptography` package when it generates a certificate. A supplied certificate and matching private key can also be selected with `REMOTE_ADMIN_TLS_CERT` and `REMOTE_ADMIN_TLS_KEY`. The certificate still needs the correct subject alternative name and must be copied to the client trust path.

## Start the server

In the server terminal, set the token and certificate name as described above. Optionally set `REMOTE_ADMIN_BIND_HOST`. Its default is `0.0.0.0`, which listens on all IPv4 interfaces. To listen only on a particular interface, set it to that interface address. The default port is `9999`; set `REMOTE_ADMIN_PORT` on the server to use another port.

Launch the desktop interface from the project directory:

```powershell
python "institutional sever.py"
```

```sh
python3 "institutional sever.py"
```

Press **Start Listener**. The status changes to online only after the socket has bound successfully. The server accepts up to 32 active clients. Failed certificate setup, a missing token, or a port binding error is reported in the interface.

## Configure and start a client

Copy `institutional client.py` and the trusted `server-cert.pem` to the client computer. Set the same token used by the server. Set `REMOTE_ADMIN_SERVER` to the reachable server IP address or DNS name. Set `REMOTE_ADMIN_SERVER_CERT` to the certificate file path. Set `REMOTE_ADMIN_PORT` if the server is not using port `9999`.

PowerShell example:

```powershell
$env:REMOTE_ADMIN_TOKEN = "paste the same secret value here"
$env:REMOTE_ADMIN_SERVER = "127.0.0.1"
$env:REMOTE_ADMIN_SERVER_CERT = ".\server-cert.pem"
$env:REMOTE_ADMIN_PORT = "9999"
python "institutional client.py"
```

Linux or macOS example:

```sh
export REMOTE_ADMIN_TOKEN="paste the same secret value here"
export REMOTE_ADMIN_SERVER="127.0.0.1"
export REMOTE_ADMIN_SERVER_CERT="./server-cert.pem"
export REMOTE_ADMIN_PORT="9999"
python3 "institutional client.py"
```

The client retries temporary network failures with an increasing delay. Certificate validation failures and token rejection stop the client with an error. When authenticated, the client appears in the server connection table. Keep the client process running during the demonstration.

## Use the interface

Select an online client row and open its session. Enter a harmless command such as `whoami` on Linux or `whoami` on Windows and press Enter. The output appears in the session panel. The server hides the submitted input so that a password is not echoed. The database stores a redacted activity marker rather than the text.

To test messaging separately from command execution, type a short note into the session field and press **Message**. The client prints the message in its console and sends a delivery acknowledgement to the session output. Message text is not stored in the activity database.

For a follow up response test, send a command that asks for a line of input. For example, on a client with Python available, enter:

```text
python -c "print('Continue? ', end='', flush=True); answer=input(); print('Received:', answer)"
```

Wait for the prompt in the session output, enter `y`, and confirm that the process prints `Received: y`. The `y` is delivered to the already running process. It is not launched as another command. The same behavior applies to `n` and other line based responses while a process remains active.

On a Unix like client, send a command such as `sudo -v`. When the sudo prompt appears, enter the password in the server input field. The client uses `sudo -S` for a command beginning with `sudo`. The password travels inside the TLS connection and is not echoed or recorded by the application. Do not use a real administrator password for a demonstration unless the computer owner authorizes that test. Windows does not provide the Unix sudo command. Programs requiring a graphical prompt, terminal control sequences, or a full pseudo terminal may not work.

Use **Interrupt** to request cancellation of the active command. On POSIX systems the client sends an interrupt signal to the command process group. On Windows the current process is terminated. The action can interrupt an operation, so use it only on a test command.

For upload, select a client and use **Send file**. The client saves the file into its current working directory and refuses to overwrite an existing file of the same name. For download, choose **Receive file**, enter a path on the client, and choose a destination on the server. Each transfer is limited to 128 MiB and checked with SHA 256. Transfers use temporary files so incomplete or damaged data is not installed as the final file.

Use **Refresh** to send a heartbeat request. A disconnected client is marked offline and its row index remains stable, so another client does not inherit the old session index. Use **Disconnect** to close the selected connection. The Reports and Logs views show local connection and redacted activity records.

## Test plan

First test on one computer. Set the server name to `127.0.0.1`, create the certificate, start the server, copy the certificate to the client path, set the same token in both processes, and start the client. Confirm that the client row appears. Run `whoami`, send a separate Message, run the follow up prompt example, transfer a small test file in each direction, and use the interrupt control on a harmless long running command.

Next test on two computers on the same LAN. Set the certificate name and client server address to the server computer's LAN address. Ensure the client can reach the server computer and port `9999`. Run the same command, response, and file tests. This validates routing on the local network but does not prove public Internet reachability.

For a public network test, the server address must be reachable from the client's network. Allow inbound TCP on the selected server port in the server firewall. If the server is behind a router, forward that TCP port to the server computer's LAN address and keep that address stable. Set the certificate name to the same public IP or DNS name configured on the client. Some providers use carrier grade NAT and do not permit inbound connections; in that case a VPN or a routed relay is required. A private Wi Fi address alone is not a public endpoint.

The following behaviours were exercised in the isolated client harness for this revision: a running Python prompt received a later `yes` response; a file upload used a safe basename and passed its SHA 256 check; corrupted upload content was rejected; and download chunks matched the declared size and digest. Both Python application files compiled successfully. The GUI listener, real TLS socket handshake, actual server token rejection, two computer connection, public routing, and real sudo password prompt were not run in this environment because Tkinter is unavailable and socket operations are restricted. Complete those end to end checks on the target computers before presenting a live network result.

## Troubleshooting

If the server reports a missing token, set `REMOTE_ADMIN_TOKEN` in the terminal that launches the server. If the client reports token rejection, check that the server and client have exactly the same token and restart the client after changing it.

If the client reports a certificate verification error, make sure the client certificate file is the current `server-cert.pem`, the certificate was copied from the intended server, and the configured server address matches the certificate name. If the certificate name changed, create a new certificate pair and recopy the public certificate.

If the client keeps retrying, confirm that the listener is online, both processes use the same port, and a route exists between them. A public IP address may change. The operating system firewall and router must permit the connection. If the listener cannot bind, another application may already be using the port; choose another `REMOTE_ADMIN_PORT` value and set it on both computers.

If a command appears to wait for input, enter the response in the session input field. If it no longer responds, use **Interrupt**. Follow up input is line based. Interactive programs that require a real terminal are outside this prototype's support.

If an upload fails because the destination exists, rename or remove the test file on the client before retrying. If a transfer checksum fails, the incomplete temporary file is removed and the transfer should be repeated. The configured transfer limit is 128 MiB.

## Security and operational limitations

This application can execute shell commands on a connected client. Run it only on computers whose owners have explicitly authorized the test. The token is shared by the server and every client, so any holder can authenticate as a client. Rotate the token on both sides if it is disclosed. Keep `server-key.pem`, the token, the SQLite database, and logs private. The client trusts the certificate file supplied to it, so distribute that file through a trusted channel.

TLS protects data in transit and server certificate validation helps prevent impersonation. The project does not provide separate client identities, role based permissions, centralized key rotation, a complete terminal, or an Internet relay. Shell commands and file access run with the permissions of the operating system account running the client. SQLite records are not encrypted. The current application is an educational minimum viable prototype and is not a replacement for SSH or managed remote support software.
