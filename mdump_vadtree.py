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
        return strio.getvalue()
    except Exception, e:
        print(repr(e))
        print("This plugin can not generate dot file!")
    

# def get_vad_json(config, plugin_class, num):
#     plugin = plugin_class(copy.deepcopy(config))
#     plugin_result_json = plugin.calculate()
#     plugin_result_dot = copy.deepcopy(plugin_result_json)

#     strio_json = StringIO.StringIO()
#     plugin.render_json(strio_json, plugin_result_json)
#     strio_dot = StringIO.StringIO()
#     plugin.render_dot(strio_dot, plugin_result_dot)

#     with open(dump_path+"vad.json","w") as f:
#         f.write(strio_json.getvalue())
#         pass
#     with open(dump_path+"graph.dot", "w") as f:
#         f.write(strio_dot.getvalue())


def mdump_vad_tree(num):
    import volatility.plugins.vadinfo as vadinfo
    config = conf_m.vol_conf
    vad_temp_json = get_json(config, vadinfo.VADTree)
    vad_dot = get_dot(config, vadinfo.VADTree)

    # adjust json format
    head = ['pid', 'vad', 'start', 'end', 'VadTag', 'flags', 'protection', 'VadType', 'ControlArea', 'segment', \
           'NumberOfSectionReferences', 'NumberOfPfnReferences', 'NumberOfMappedViews', 'NumberOfUserReferences',\
           'ControlFlags', 'FileObject', 'FileName', 'FirstprototypePTE', 'LastcontiguousPTE', 'Flags2']

    vad_json = dict()
    for vad_item in vad_temp_json["rows"]:
        temp = dict(zip(head,vad_item))
        if not vad_json.has_key(str(temp["pid"])):
            vad_json[str(temp["pid"])] = list()
        vad_json[str(temp["pid"])].append(temp)

    with open(dump_path+"vad"+str(num)+".json", "w") as f:
        try:
            json_str = {"nodes":{}, "edges":{}}
            # transform vad dot data to json data
            pid_flag = False
            for line in vad_dot.split("\n"):
                if "Pid" in line:
                    pid_flag = True
                    root = True
                    pid = line[7:14].strip()
                    json_str["nodes"][pid] = {}
                    json_str["edges"][pid] = []
                    continue
                if pid_flag:
                    if "->" in line:
                        if root:
                            vad = line[:12]
                            start_address = vad_json[pid][0]["start"]
                            end_address = vad_json[pid][0]["end"]
                            address = hex(start_address)[2:] + " - " + hex(end_address)[2:]
                            json_str["nodes"][pid][vad] = {"color":"blue", "address":address}
                            root = False
                        tmp = {"source":line[0:12], "target":line[16:28]}
                        json_str["edges"][pid].append(tmp)
                    if "label" in line:
                        vad = line[:12]
                        address = line[31:50]
                        color = line[115:-3]
                        if color == "red":
                            color = "purple"
                        json_str["nodes"][pid][vad] = {"color": color, "address":address}
                    if "/*" in line:
                        pid_flag = False
                        continue
            # add vad info to nodes
            for pid in vad_json.keys():
                for node in vad_json[pid]:
                    k = "vad_"+hex(node["vad"])[2:]
                    json_str["nodes"][pid][k].update(node)
        except Exception, e:
            print(repr(e))
        
        f.write(json.dumps(json_str))
    
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
    mdump_vad_tree(0)
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
