from threading import Thread
import argparse
import subprocess
import os
import signal
import fcntl
import time
import sys

# Maximum time we wait for the unload 
# process to finish before we kill the
# process
MAX_UNLOAD_TIME = 120

VM_IMAGE = "/home/sam/pyrebox/images/WinXP.qcow2"
PYREBOX_PATH = os.environ.get("PYREBOX_PATH", None)
RAM = 1024
TIMEOUT = 300
CONFIG_PATH = "/home/sam/pyrebox/pyrebox.conf"

# Process handle
p = None

def signal_handler(sig, frame):
    global p
    if p:
        print("Killing PyREBox process...")
        os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        p = None
    sys.exit(0)

def start_pyrebox(vm_image = VM_IMAGE,
                pyrebox_path = PYREBOX_PATH,
                ram = RAM,
                timeout_analysis = TIMEOUT,
                config = CONFIG_PATH):

if __name__ == "__main__":
    #Parse arguments
    parser = argparse.ArgumentParser(description='Start PyREBox')
    parser.add_argument("--image", help="Path to VM image")
    parser.add_argument("--path", help="PyREBox path")
    parser.add_argument("--ram", help="RAM memory to load the image (in Mb)")
    parser.add_argument("--timeout", help="Analysis timeout, in seconds")
    parser.add_argument("--config", help="Path to pyrebox configuration file")
    args = parser.parse_args()

    start_pyrebox(vm_image = args.image if args.image else VM_IMAGE,
                pyrebox_path = args.path if args.path else PYREBOX_PATH, 
                ram = args.ram if args.ram else RAM,
                timeout_analysis = int(args.timeout) if args.timeout else TIMEOUT,
                config = args.config if args.config else CONFIG_PATH)