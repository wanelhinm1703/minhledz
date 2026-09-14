#!/usr/bin/env python3
import sys
import subprocess
import pathlib

root = pathlib.Path(__file__).resolve().parent

def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print("AI-Pentest Copilot - Universal CLI Runner")
        print("  python run.py setup")
        print("  python run.py scan TARGET=<target>")
        print("  python run.py test")
        print("  python run.py dev")
        return

    cmd = sys.argv[1]
    if cmd == "setup":
        res = subprocess.run([sys.executable, str(root / "toolkit" / "scripts" / "init_dirs.py")])
        sys.exit(res.returncode)
    elif cmd == "scan":
        target = None
        for arg in sys.argv[2:]:
            if arg.startswith("TARGET="):
                target = arg.split("=", 1)[1]
            elif not target:
                target = arg
        if not target:
            print("ERROR: TARGET is required. Example: python run.py scan TARGET=192.168.56.101")
            sys.exit(1)
        res = subprocess.run([sys.executable, str(root / "toolkit" / "scripts" / "targets.py"), "scan", "--target", target])
        sys.exit(res.returncode)
    elif cmd == "test":
        res = subprocess.run([sys.executable, "-m", "pytest", "backend/tests", "-v"])
        sys.exit(res.returncode)
    elif cmd == "dev":
        res = subprocess.run(["uvicorn", "backend.app.main:app", "--reload", "--port", "8000"])
        sys.exit(res.returncode)
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)

if __name__ == "__main__":
    main()
