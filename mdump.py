# mdump basic function

from __future__ import print_function
import time
from api import CallbackManager
from ipython_shell import start_shell
import api
# from libdamm.api import API as DAMM
# import sqlite3

requirements = ["plugins.guest_agent"]

# Callback manager
cm = None
# Printer
pyrebox_print = None

target_procname = ""

longest_time = 600


def new_proc(params):
    '''
    Process creation callback. Receives 3 parameters:
        :param pid: The pid of the process(int)
        :param pgd: The PGD of the process(int)
        :param name: The name of the process(str)
    '''
    global pyrebox_print
    global cm

    pid = params["pid"]
    pgd = params["pgd"]
    name = params["name"]
    
    if name.lower() == "malware.exe":
        pyrebox_print("Malware started! pid: %x, pgd: %x, name: %s" % (pid, pgd, name))
        cm.rm_callback("new_proc")
        cm.add_callback(CallbackManager.BLOCK_END_CB, my_function, name="block_end")
        api.start_monitoring_process(pgd)
   
def my_function(params):
    global cm

    # cpu_index = params["cpu_index"]
    # cpu = params["cpu"]
    # tb = params["tb"]
    # cur_pc = params["cur_pc"]
    # next_pc = params["next_pc"]

    # pgd = api.get_running_process(cpu_index)
    # pyrebox_print("Block end at (%x) %x -> %x\n" % (pgd, cur_pc, next_pc))
    pyrebox_print("damm is coming soon...")
    cm.rm_callback("block_end")
    # damm = DAMM(plugins=['all'], memimg=os.path.abspath(dump_path+"thefile.dump"), profile="WinXPSP3x86",db=dump_path+"res0.db")
    # results = damm.run_plugins()
    # for elem in results:
    #     print elem
    # sqlite_to_json(dump_path+"res0.db",dump_path+"res0.json")
    
    
    

def initialize_callbacks(module_hdl, printer):
    '''
    Initilize callbacks for this module.

    This function will be triggered whenever
    the script is loaded for the first time,
    either with the import_module command,
    or when loaded at startup.
    '''
    global cm
    global pyrebox_print

    pyrebox_print = printer
    pyrebox_print("[*] Snapshoting ...")
    api.save_vm("isnapshot") # Noooooooo Waaaaaaaaaay
    pyrebox_print("[*] Snapshot complete :)")
    pyrebox_print("[*]    Initializing callbacks")
    
    cm = CallbackManager(module_hdl, new_style = True)
    cm.add_callback(CallbackManager.CREATEPROC_CB, new_proc, name="new_proc")
    pyrebox_print("[*]    Initialized callbacks\n")
    copy_execute("/home/sam/malware.exe")


def clean():
    pyrebox_print("[*] Recovering snapshot...")
    api.load_vm("isnapshot")
    pyrebox_print("[*] Recover snapshot complete:)")
    global cm
    print("[*]    Cleaning module")
    cm.clean()
    print("[*]    Cleaned module")


def copy_execute(line):
    '''Copy a file from host to guest, execute it, and pause VM on its EP - Custom command

       This command will first use the guest agent to copy a file to the guest
       and execute if afterwards.

       This file will be set as target, so that the script will start monitoring
       context changes and retrieve the module entry point as soon as it is
       available in memory. Then it will place a breakpoint on the entry point.
    '''
    global pyrebox_print
    global target_procname
    from plugins.guest_agent import guest_agent

    pyrebox_print("Copying host file to guest, using agent...")

    guest_agent.copy_file(line.strip(), "C:\\malware.exe")
    guest_agent.execute_file("C:\\malware.exe")
    guest_agent.stop_agent()

    # Set target proc name:
    target_procname = "malware.exe"
    pyrebox_print("Waiting for process %s to start\n" % target_procname)


if __name__ == "__main__":
    print("[*] Loading python lalala module %s" % (__file__))
   
    # start_time = time.time()
    # end_time = time.time()
    # while end_time - start_time <= longest_time:
    #     end_time = time.time()
    
    print("[*] hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh")