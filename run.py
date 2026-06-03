
import os
import subprocess
import sys
import time
import webbrowser
import threading
from http.server import SimpleHTTPRequestHandler, HTTPServer

# --- CONFIGURATION ---
BACKEND_DIR  = os.path.join(os.getcwd(), "backend")
FRONTEND_DIR = os.path.join(os.getcwd(), "frontend")
VENV_PYTHON  = os.path.join(BACKEND_DIR, "venv", "Scripts", "python.exe")
BACKEND_PORT = 8000
FRONTEND_PORT = 5500

def run_backend():
    print(f"🚀 Starting Backend on port {BACKEND_PORT}...")
    try:
        # Use the venv python to run main.py
        subprocess.run([VENV_PYTHON, "main.py"], cwd=BACKEND_DIR, check=True)
    except Exception as e:
        print(f"❌ Backend failed to start: {e}")
        print("💡 Make sure you have created the virtual environment in 'backend/venv'")

def run_frontend():
    print(f"🌐 Starting Frontend Server on port {FRONTEND_PORT}...")
    class MyHandler(SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            pass # Keep it quiet
            
    os.chdir(FRONTEND_DIR)
    server = HTTPServer(('localhost', FRONTEND_PORT), MyHandler)
    server.serve_forever()

if __name__ == "__main__":
    print("\n" + "="*50)
    print("🛡️  CYBERAI SHIELD - LAUNCHER")
    print("="*50 + "\n")

    if not os.path.exists(VENV_PYTHON):
        print(f"❌ ERROR: Virtual environment not found at {VENV_PYTHON}")
        print("💡 Please run: cd backend; python -m venv venv; .\\venv\\Scripts\\pip install -r requirements.txt")
        sys.exit(1)

    # Start Frontend in a background thread
    frontend_thread = threading.Thread(target=run_frontend, daemon=True)
    frontend_thread.start()

    # Wait a second for servers to initialize
    time.sleep(1.5)

    # Open the browser
    login_url = f"http://localhost:{FRONTEND_PORT}/pages/login.html"
    print(f"🌍 Opening {login_url} ...")
    webbrowser.open(login_url)

    # Start Backend (blocking)
    run_backend()
