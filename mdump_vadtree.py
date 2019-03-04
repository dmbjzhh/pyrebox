# mdump basic function

from __future__ import print_function
from api import CallbackManager
import api
from libdamm.api import API as DAMM
import os
from utils import ConfigurationManager as conf_m

import copy, StringIO, json


requirements = ["plugins.guest_agent"]

# Callback manager
cm = None
# Printer
pyrebox_print = None
target_procname = "calculator.exe"
dump_path = "dump_result/"


def new_proc(params):
    global pyrebox_print
    global cm

    pid = params["pid"]
    pgd = params["pgd"]
    name = params["name"]

    if name.lower() == target_procname:
        pyrebox_print("Malware started! pid: %x, pgd: %x, name: %s" % (pid, pgd, name))
        cm.rm_callback("mdump_new_proc")
        api.start_monitoring_process(pgd)
        pyrebox_print("Malware started! set the process monitor")
        cm.add_callback(CallbackManager.BLOCK_END_CB, mdump_function, name="block_end")


def get_json(config, plugin_class):
    strio = StringIO.StringIO()
    plugin = plugin_class(copy.deepcopy(config))
    plugin.render_json(strio, plugin.calculate())
    return json.loads(strio.getvalue())


def get_dot(config, plugin_class):
    strio = StringIO.StringIO()
    plugin = plugin_class(copy.deepcopy(config))
    try:
        plugin.render_dot(strio, plugin.calculate())
        with open(dump_path+"graph.dot", "w") as f:
            f.write(strio.getvalue())
    except Exception, e:
        print(repr(e))
        print("This plugin can not generate dot file!")
    


def mdump_vad_tree():
    import volatility.plugins.vadinfo as vadinfo

    # vtree = vadinfo.VADTree(conf_m.vol_conf).calculate()
    # for task in vtree:
    config = conf_m.vol_conf
    vadata = get_json(config, vadinfo.VADTree)
    # pid_index = vadata['columns'].index('Pid')
    # for row in vadata['rows']:
    #     print("pid are: "+str(row[pid_index]))
    with open(dump_path+"vad.json","w") as f:
        json.dump(vadata, f)
    get_dot(config, vadinfo.VADTree)
    print("json complete")


def mdump_function(params):
    mdump_call_damm()


def mdump_call_damm():
    global pyrebox_print
    global cm

    damm = DAMM(plugins=['all'], profile="WinXPSP3x86", db=dump_path+"vadtest.db")
    pyrebox_print("damm initialized")
    results = damm.run_plugins()
    for elem in results:
        pass
    pyrebox_print("Start analyse vad :)")
    mdump_vad_tree()
    pyrebox_print("analyze over :)")
    cm.clean()

def copy_execute(line):
    global pyrebox_print
    global target_procname
    from plugins.guest_agent import guest_agent

    pyrebox_print("Copying host file to guest, using agent...")
    guest_agent.copy_file(line.strip(), "C:\\"+target_procname)
    guest_agent.execute_file("C:\\"+target_procname)
    guest_agent.stop_agent()

    pyrebox_print("Waiting for process %s to start\n" % target_procname)
    

def initialize_callbacks(module_hdl, printer):
    global cm
    global pyrebox_print
    global target_procname

    pyrebox_print = printer
    pyrebox_print("[*]    Initializing callbacks")
    
    cm = CallbackManager(module_hdl, new_style=True)

    cm.add_callback(CallbackManager.CREATEPROC_CB, new_proc, name="mdump_new_proc")

    pyrebox_print("[*]    Initialized callbacks\n")
    copy_execute("malware/"+target_procname)


def clean():
    global cm
    print("[*]    Cleaning module")
    cm.clean()
    print("[*]    Cleaned module")


if __name__ == "__main__":
    pass
