# mdump basic function

from __future__ import print_function
import time
from api import CallbackManager
import api
from libdamm.api import API as DAMM
from scripts.dealjson import sqlite_to_json
from scripts.dealjson import diff2Graph
import os

requirements = ["plugins.guest_agent"]

# Callback manager
cm = None
# Printer
pyrebox_print = None

target_procname = ""

longest_time = 600
# script initial start time
s_start_time = 0
# callback start time
c_start_time = 0

dump_path = "dump_result/"

# number of db file
db_num = 0

# number of diff.json file
diff_num = 1

# exe file copy to VM, by default is calculator.exe
exe_file = "cal.exe"


def new_proc(params):
    '''
    Process creation callback. Receives 3 parameters:
        :param pid: The pid of the process(int)
        :param pgd: The PGD of the process(int)
        :param name: The name of the process(str)
    '''
    global pyrebox_print
    global cm
    global s_start_time
    global c_start_time
    global target_procname

    pid = params["pid"]
    pgd = params["pgd"]
    name = params["name"]

    if name.lower() == target_procname:
        pyrebox_print("Malware started! pid: %x, pgd: %x, name: %s" % (pid, pgd, name))
        cm.rm_callback("mdump_new_proc")
        s_start_time = time.time()
        c_start_time = time.time()
        api.start_monitoring_process(pgd)
        pyrebox_print("Malware started! set the process monitor")
        cm.add_callback(CallbackManager.BLOCK_END_CB, mdump_function, name="block_end")


def mdump_function(params):
    global pyrebox_print
    global cm
    global s_start_time
    global longest_time
    global dump_path
    global db_num
    global diff_num
    global c_start_time

    if time.time() - c_start_time >= 10 or db_num == 0:
        damm = DAMM(plugins=['all'], profile="WinXPSP3x86", db=dump_path+"res"+str(db_num)+".db")
        pyrebox_print("damm initialized")
        results = damm.run_plugins()
        for elem in results:
            # print(elem)
            pass

        sqlite_to_json(dump_path+"res%d.db" % (db_num), dump_path+"res%d.json" % (db_num))
        pyrebox_print("res%d.json file has been created" % (db_num))

        # compare the diff between two res.json and create diff.json file 
        if db_num > 0:
            ret = diff2Graph(dump_path+"res%d.json" % (db_num-1), dump_path+"res%d.json" % (db_num), dump_path+"diff%d.json" % (diff_num))
            print(ret)
            if ret is True:
                pyrebox_print("diff%d.json file has been created" % (diff_num))
                diff_num += 1
        db_num += 1
        c_start_time = time.time()

    if time.time() - s_start_time >= longest_time:
        pyrebox_print("analyze over :)")
        cm.rm_callback("block_end")


def copy_execute(line):
    '''Copy a file from host to guest, execute it, and pause VM on its EP

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
    global exe_file

    mal_path = os.getcwd() + "/malware"  # malware's path
    malists = os.listdir(mal_path)
    if len(malists) > 1:
        malists.remove("cal.exe")
        exe_file = malists[0]

    pyrebox_print = printer
    pyrebox_print("[*]    Initializing callbacks")
    
    cm = CallbackManager(module_hdl, new_style=True)

    cm.add_callback(CallbackManager.CREATEPROC_CB, new_proc, name="mdump_new_proc")

    pyrebox_print("[*]    Initialized callbacks\n")
    copy_execute("malware/"+exe_file)


def clean():
    global cm
    print("[*]    Cleaning module")
    cm.clean()
    print("[*]    Cleaned module")


if __name__ == "__main__":
    print("[*] Loading python lalala module %s" % (__file__))