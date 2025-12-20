import os
import subprocess
import sys

def build():
    print("Starting build process for AntigravityCollector.exe...")
    
    # Check for PyInstaller
    try:
        import PyInstaller
    except ImportError:
        print("Error: PyInstaller not found. Installing requirements...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "scripts/requirements_collector.txt"])

    # Define build command
    command = [
        "pyinstaller",
        "--noconfirm",
        "--onefile",
        "--console",
        "--name", "KodiakAiOps-Collector",
        "--uac-admin",  # Request admin privileges in manifest
        "--collect-submodules", "scapy",
        "--hidden-import", "win32evtlog",
        "--hidden-import", "win32evtlogutil",
        "scripts/collector.py"
    ]

    print(f"Running command: {' '.join(command)}")
    try:
        subprocess.check_call(command)
        print("\nBuild Successful!")
        print(f"Executable located in: {os.path.abspath('dist/AntigravityCollector.exe')}")
    except subprocess.CalledProcessError as e:
        print(f"\nBuild Failed with error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    build()
