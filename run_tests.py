import subprocess
import sys
import time
import requests
import os

ROOT = os.path.dirname(os.path.abspath(__file__))
PYTHON = sys.executable  # current interpreter


def run(cmd, cwd=ROOT, check=True):
    print(f"$ {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd)
    if check and result.returncode != 0:
        raise SystemExit(result.returncode)
    return result.returncode


def wait_for_server(url="http://127.0.0.1:5000", timeout=40):
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(url, timeout=2)
            if r.status_code in (200, 302, 401):
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def main():
    # 1) Seed admin
    run([PYTHON, os.path.join(ROOT, 'seed_admin.py')])

    # 2) Start server
    print("Starting Flask server...")
    server = subprocess.Popen([PYTHON, os.path.join(ROOT, 'app.py')], cwd=ROOT)

    try:
        # 3) Wait until server is ready
        if not wait_for_server():
            print("Server did not become ready in time.")
            server.terminate()
            server.wait(timeout=10)
            sys.exit(1)

        # 4) Run tests
        auth_rc = run([PYTHON, os.path.join(ROOT, 'testes', 'test_auth.py')], check=False)
        api_rc = run([PYTHON, os.path.join(ROOT, 'testes', 'test_api.py')], check=False)

        rc = 0 if (auth_rc == 0 and api_rc == 0) else 1
        print("\n=== Summary ===")
        print(f"test_auth.py: {'OK' if auth_rc == 0 else 'FAIL'}")
        print(f"test_api.py : {'OK' if api_rc == 0 else 'FAIL'}")
        sys.exit(rc)

    finally:
        # 5) Shutdown server
        try:
            server.terminate()
            server.wait(timeout=10)
        except Exception:
            try:
                server.kill()
            except Exception:
                pass


if __name__ == '__main__':
    main()