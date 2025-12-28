#!/usr/bin/env python3
"""
P3 (Three-Process) Test for Node.js Implementation
"""

import sys
import os
import time
import subprocess
import threading
import queue
import signal

# Paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.join(SCRIPT_DIR, "../../..")
FRPS_PATH = os.path.join(PROJECT_ROOT, "build/frps")
# Node scripts
SERVER_SCRIPT = os.path.join(SCRIPT_DIR, "p3_server.js")
VISITOR_SCRIPT = os.path.join(SCRIPT_DIR, "p3_visitor.js")

# Configuration
TOKEN = "test_token"

def find_free_port():
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

class AsyncOutputReader(threading.Thread):
    def __init__(self, process, name, queue):
        super().__init__()
        self.process = process
        self.name = name
        self.queue = queue
        self.daemon = True
        self.stop_event = threading.Event()

    def run(self):
        try:
            for line in iter(self.process.stdout.readline, ''):
                if self.stop_event.is_set():
                    break
                if line:
                    self.queue.put((self.name, line.strip()))
        except ValueError:
            pass 
        finally:
            self.process.stdout.close()

    def stop(self):
        self.stop_event.set()

class ProcessManager:
    def __init__(self):
        self.processes = []
        self.output_queue = queue.Queue()
        self.readers = []

    def start_process(self, name, cmd, env=None):
        print(f"[{name}] Starting: {' '.join(cmd)}")
        p = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE,
            bufsize=1,
            universal_newlines=True,
            env=env
        )
        self.processes.append((name, p))
        
        reader = AsyncOutputReader(p, name, self.output_queue)
        reader.start()
        self.readers.append(reader)
        return p

    def send_input(self, name, text):
        for n, p in self.processes:
            if n == name:
                if p.poll() is None:
                    try:
                        p.stdin.write(text + "\n")
                        p.stdin.flush()
                    except BrokenPipeError:
                        print(f"Warning: Pipe broken for {name}")
                return
        raise Exception(f"Process {name} not found or dead")

    def kill_all(self):
        for _, p in self.processes:
            if p.poll() is None:
                try:
                    p.terminate()
                    p.wait(timeout=1)
                except:
                    p.kill()
        for r in self.readers:
            r.stop()

    def get_output(self, timeout=0.1):
        try:
            return self.output_queue.get(timeout=timeout)
        except queue.Empty:
            return None

class P3E2ETest:
    def __init__(self):
        self.port = find_free_port()
        self.pm = ProcessManager()
        self.logs = [] 
        
    def start_frps(self):
        import tempfile
        self.config_file = tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False)
        self.config_file.write(f"""
bindPort = {self.port}
[auth]
method = "token"
token = "{TOKEN}"
[transport]
tcpMux = false
[log]
level = "info"
""")
        self.config_file.close()
        
        self.pm.start_process("FRPS", [FRPS_PATH, "-c", self.config_file.name])
        time.sleep(2)

    def get_env(self):
        env = os.environ.copy()
        env["TINY_FRPC_VERBOSE"] = "1"
        # Add build dir to library path for dynamic linker
        lib_path = os.path.join(PROJECT_ROOT, "build")
        if "DYLD_LIBRARY_PATH" in env:
            env["DYLD_LIBRARY_PATH"] += ":" + lib_path
        else:
            env["DYLD_LIBRARY_PATH"] = lib_path
            
        if "LD_LIBRARY_PATH" in env:
            env["LD_LIBRARY_PATH"] += ":" + lib_path
        else:
            env["LD_LIBRARY_PATH"] = lib_path
        return env

    def start_server(self):
        self.pm.start_process("Server", ["node", SERVER_SCRIPT, "127.0.0.1", str(self.port)], env=self.get_env())

    def start_visitor(self, name):
        self.pm.start_process(f"Vis-{name}", ["node", VISITOR_SCRIPT, "127.0.0.1", str(self.port), name], env=self.get_env())

    def collect_logs(self):
        while True:
            item = self.pm.get_output(timeout=0)
            if item is None: break
            name, line = item
            if not line.strip(): continue
            self.logs.append(item)

    def dump_logs(self):
        self.collect_logs()
        print("\n[DUMP LOGS]")
        for name, line in self.logs:
            print(f"[{name}] {line}")
        print("[END DUMP]\n")

    def expect_log(self, name, pattern, timeout=10):
        start = time.time()
        while time.time() - start < timeout:
            self.collect_logs()
            for n, line in reversed(self.logs):
                if n == name and pattern in line:
                    return True
            time.sleep(0.1)
        self.dump_logs()
        return False
    
    def cleanup(self):
        self.pm.kill_all()
        if hasattr(self, 'config_file'):
            try: os.unlink(self.config_file.name)
            except: pass

def test_multi_visitor():
    print("="*60)
    print("  Test: Node.js Implementation (Server & Visitors)")
    print("="*60)
    
    t = P3E2ETest()
    try:
        t.start_frps()
        
        t.start_server()
        if not t.expect_log("Server", "Server started", timeout=10):
            print("Failed to start server")
            return False
        
        t.start_visitor("Alice")
        if not t.expect_log("Vis-Alice", "Visitor started", timeout=5):
            print("Failed to start Alice")
            return False
            
        t.start_visitor("Bob")
        if not t.expect_log("Vis-Bob", "Visitor started", timeout=5):
            print("Failed to start Bob")
            return False
            
        print("[5] Alice sends 'Hello from Alice'")
        t.pm.send_input("Vis-Alice", "Hello from Alice")
        if t.expect_log("Server", "[Received] [Alice] Hello from Alice", timeout=5):
            print("    ✓ Server received Alice's message")
        else:
            print("    ✗ Server DID NOT receive Alice messsage")
            return False
            
        print("[7] Bob sends 'Hello from Bob'")
        t.pm.send_input("Vis-Bob", "Hello from Bob")
        if t.expect_log("Server", "[Received] [Bob] Hello from Bob", timeout=5):
            print("    ✓ Server received Bob's message")
        else:
            print("    ✗ Server DID NOT receive Bob's message")
            return False
            
        print("[9] Server broadcasts 'Server Broadcast'")
        t.pm.send_input("Server", "Server Broadcast")

        if t.expect_log("Vis-Alice", "[Received] [Server] Server Broadcast", timeout=5):
             print("    ✓ Alice received broadcast")
        else:
             print("    ✗ Alice DID NOT receive broadcast")
             return False

        if t.expect_log("Vis-Bob", "[Received] [Server] Server Broadcast", timeout=5):
             print("    ✓ Bob received broadcast")
        else:
             print("    ✗ Bob DID NOT receive broadcast")
             return False

        print("\nPASSED: Node.js implementation works!")
        return True
        
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        t.cleanup()

def main():
    test_multi_visitor()

if __name__ == "__main__":
    main()
