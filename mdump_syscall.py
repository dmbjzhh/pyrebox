# mdump basic function

from __future__ import print_function
import time
import sys
from api import CallbackManager
import api
import bisect
from collections import defaultdict
import functools
from volatility.plugins.overlays.windows.xp_sp2_x86_syscalls import syscalls
from utils import ConfigurationManager as conf_m

requirements = ["plugins.guest_agent"]

# Callback manager
cm = None

# Set printer
pyrebox_print = None
mdump_path = "dump_result/"

# max running time from config file
try:
    MAX_RUNNING_TIME = conf_m.config.get('MDUMP', 'runtime')
except:
    pyrebox_print("No run time is specified, the default run time will be used.")
    MAX_RUNNING_TIME = 600
# script initial start time
s_start_time = 0

# number of db file
db_num = 0
# number of diff.json file
diff_num = 1
# calling damm or not
MDUMP_DAMM = conf_m.config.get('MDUMP', 'damm')
# print on the screen and a txt file
MDUMP_LOG = conf_m.config.get('MDUMP', 'text_log')
# a buffer that stores the log
mdump_buffer = []

# Get the API list mode
MDUMP_AT_SYSCALL = 1
MDUMP_AT_CALL_API = 2
MDUMP_AT_RUN_TB = 3

MDUMP_MODE_TYPE = MDUMP_AT_SYSCALL
mdump_mode = conf_m.config.get('MDUMP', 'mode')
if mdump_mode not in ['api', 'syscall', 'tb']:
    pyrebox_print("error API LIST mode:{}".format(mdump_mode))

if mdump_mode == 'api':
    MDUMP_MODE_TYPE = MDUMP_AT_CALL_API
elif mdump_mode == 'syscall':
    MDUMP_MODE_TYPE = MDUMP_AT_SYSCALL
else:
    MDUMP_MODE_TYPE = MDUMP_AT_RUN_TB

# modules for the process
modules = defaultdict(lambda :(0,0))


# symbols info
mdump_symbols_loaded = False
TARGET_LONG_SIZE = api.get_os_bits() / 8

process_syms = []
target_procname = conf_m.config.get('MDUMP', 'target')
process_symbols_file = "/tmp/"+target_procname+'.'+conf_m.config.get('VOL', 'profile')+'.bin'

# symbols for ntdll
ntdll_syms = []
ntdll_name= "ntdll.dll"
ntdll_symbols_file = "/tmp/ntdll.symbols."+conf_m.config.get('VOL', 'profile')+'.bin'
KiFastSystemCall_addr = -1  #xp sp2=0x7c92e4f0
KiFastSystemCall_name = "KiFastSystemCall"

winXP_Exclude_syscalls = [0x11a5, #NtUserGetMessage
                          0x1165  #NtUserDispatchMessage
                          ]

class Symbol:
    def __init__(self, mod, func, addr):
        self.mod = mod
        self.func = func
        self.addr = addr
    def __lt__(self, other):
        return self.addr < other.addr
    def __le__(self, other):
        return self.addr <= other.addr
    def __eq__(self, other):
        return self.addr == other.addr
    def __ne__(self, other):
        return self.addr != other.addr
    def __gt__(self, other):
        return self.addr > other.addr
    def __ge__(self, other):
        return self.addr >= other.addr


def mdump_print(mdump_log):
    global mdump_buffer
    if type(mdump_log) != str:
        mdump_log = str(mdump_log)
    if MDUMP_LOG:
        if len(mdump_buffer) >= 100:
            with open("{0}/{1}_{2}_log.txt".format(mdump_path, target_procname, mdump_mode), 'a') as f:
                for log in mdump_buffer:
                    f.write(log+'\n')
                f.write(mdump_log+'\n')
            mdump_buffer = []
        else:
            mdump_buffer.append(mdump_log)


def mdump_call_damm():
    from libdamm.api import API as DAMM
    # from scripts.dealjson import sqlite_to_json
    # from scripts.dealjson import diff2Graph
    global pyrebox_print
    global cm
    global db_num
    global diff_num

    damm = DAMM(plugins=['all'], profile=conf_m.config.get('VOL', 'profile'), db=mdump_path+"res"+str(db_num)+".db")
    pyrebox_print("damm initialized")
    results = damm.run_plugins()
    for elem in results:
        # print(elem)
        pass

    # sqlite_to_json(mdump_path+"res%d.db" % db_num, mdump_path+"res%d.json" % db_num)
    # pyrebox_print("res%d.json file has been created" % (db_num))

    # # compare the diff between two res.json and create diff.json files
    # if db_num > 0:
    #     ret = diff2Graph(mdump_path+"res%d.json" % (db_num-1), mdump_path+"res%d.json" % db_num, mdump_path+"diff%d.json" % diff_num)
    #     print(ret)
    #     if ret is True:
    #         pyrebox_print("diff%d.json file has been created" % diff_num)
    #         diff_num += 1
    db_num += 1

    if time.time() - s_start_time >= MAX_RUNNING_TIME:
        pyrebox_print("analyze over :)")
        cm.clean()


def locate_module(addr):
    global modules

    for mod, value in modules.items():
        base, size = value
        if addr >= base and addr < base+size:
            return mod

    return None

def locate_nearest_symbol(addr):
    global process_syms

    mod = locate_module(addr)
    if mod == None:
        return None

    base, size = modules[mod]

    pos = bisect.bisect_left(process_syms, Symbol('', '', addr-base))
    if pos < 0 or pos >= len(process_syms):
        return None
    while process_syms[pos].mod != mod and process_syms[pos].addr == addr - base and pos < len(process_syms)+1:
        pos += 1
    if (addr - process_syms[pos].addr - base) == 0:    
        return process_syms[pos]
    else:
        return None

def mdump_syscall_func(dest_pid, dest_pgd, params):
    global pyrebox_print
    global cm

    cpu_index = params['cpu_index']
    cpu = params['cpu']
    tb = params['tb']
    if cpu.EIP != KiFastSystemCall_addr:
        pyrebox_print("Error in syscall_func")
        return

    if TARGET_LONG_SIZE == 4:
        if not cpu.EAX in winXP_Exclude_syscalls:
            pos = (cpu.EAX & 0xf000) >> 12
            num = (cpu.EAX & 0x0fff)
            if pos > 1 :
                pyrebox_print("Error in syscall index")
                return
            pyrebox_print("[PID:%x] %s:0x%08x" % (dest_pid, syscalls[pos][num], cpu.EAX))
            mdump_print("[PID:%x] %s:0x%08x" % (dest_pid, syscalls[pos][num], cpu.EAX))
            # call DAMM to analyze
            pyrebox_print("DAMMMMMMMMM is "+MDUMP_DAMM)
            if MDUMP_DAMM:
                mdump_call_damm()
    elif TARGET_LONG_SIZE == 8:    
        pyrebox_print("[PID:%x] KiFastSystemCall RAX:%016x" % (dest_pid, cpu.RAX))
        mdump_print("[PID:%x] KiFastSystemCall RAX:%016x" % (dest_pid, cpu.RAX))
        if MDUMP_DAMM:
                mdump_call_damm()

def mdump_opcodes(dest_pid, dest_pgd, params):
    global pyrebox_print
    global cm

    cpu_index = params['cpu_index']
    cpu = params['cpu']
    pc = params['cur_pc']
    next_pc = params['next_pc']

    if not mdump_symbols_loaded:
        return

    try:
        sym = locate_nearest_symbol(next_pc)
        if sym is None:
            return

        mod = sym.mod
        func = sym.func

        if mod != ntdll_name: #???
            return

        base, size = modules[mod]
        real_api_addr = sym.addr + base
        if real_api_addr < base and real_api_addr >= base+size:
            return
        #pyrebox_print("mod:{}, func:{}, addr:{}".format(mod, func, hex(real_api_addr)))
        if next_pc != real_api_addr:
            return

        if TARGET_LONG_SIZE == 4:
            pyrebox_print("[PID:%x] pc:%08x-->mod:%s,func:%s(%08x)" % (dest_pid, pc, mod, func, real_api_addr))
            mdump_print("[PID:%x] pc:%08x-->mod:%s,func:%s(%08x)" % (dest_pid, pc, mod, func, real_api_addr))
                
        elif TARGET_LONG_SIZE == 8:    
            pyrebox_print("[PID:%x] pc:%016x-->mod:%s,func:%s(%016x)" % (dest_pid, pc, mod, func, real_api_addr))
            mdump_print("[PID:%x] pc:%016x-->mod:%s,func:%s(%016x)" % (dest_pid, pc, mod, func, real_api_addr))

    except Exception as e:
        pyrebox_print(str(e))
        traceback.print_exec()
    finally:
        return


def mdump_api_trace(dest_pid, dest_pgd):
    global pyrebox_print
    global cm
    pyrebox_print("Initializing ntdll trace......")

    cm.add_callback(CallbackManager.OPCODE_RANGE_CB, functools.partial(mdump_opcodes, dest_pid, dest_pgd), name="mdump_opcode1_%x" % dest_pid, start_opcode=0xFF, end_opcode=0xFF)
    
    cm.add_trigger(("mdump_opcode1_%x" % dest_pid), "triggers/trigger_opcode_user_only.so")
    cm.set_trigger_var(("mdump_opcode1_%x" % dest_pid), "cr3", dest_pgd)

def mdump_syscall_trace(dest_pid, dest_pgd):
    global pyrebox_print
    global cm
    global modules
    global ntdll_syms
    global KiFastSystemCall_addr

    pyrebox_print("Initializing syscall trace......")

    base, size = modules[ntdll_name]
    if base == 0:
        pyrebox_print("Error ntdll base addr")
        return

    for s in ntdll_syms:
        if s.func == KiFastSystemCall_name:
            KiFastSystemCall_addr = s.addr+base
            pyrebox_print("KiFastSystemCall addr:{}".format(hex(KiFastSystemCall_addr)))
            mdump_print("KiFastSystemCall addr:{}".format(hex(KiFastSystemCall_addr)))


    if KiFastSystemCall_addr == -1:
        pyrebox_print("Error, there is no KiFastSystemCall symbol")
        return

    cm.add_callback(CallbackManager.BLOCK_BEGIN_CB, functools.partial(mdump_syscall_func, dest_pid, dest_pgd), name="mdump_syscall_trace_{}".format(dest_pid), addr=KiFastSystemCall_addr, pgd=dest_pgd)
    

def module_loaded(params):
    global ntdll_syms
    global process_syms
    global modules
    global mdump_symbols_loaded
    global MDUMP_MODE_TYPE
    global cm

    pid = params["pid"]
    pgd = params["pgd"]
    base = params["base"]
    size = params["size"]
    name = params["name"]
    fullname = params["fullname"]
    modules[name] = (base, size)
    pyrebox_print("Module name:%s" % name)
    mdump_print("Module name:%s" % name)

    
    if  mdump_symbols_loaded == False and  MDUMP_MODE_TYPE == MDUMP_AT_SYSCALL:
        #only update symbols for the process
        proc_syms = api.get_symbol_list(pgd)
        if len(proc_syms) == 0: #can't get syms at the time
            return
            
        pyrebox_print("Translate proc_syms({}) to ntdll symbols".format(len(proc_syms)))
        for s in proc_syms:
            mod = s['mod']
            func = s['name']
            addr = s['addr']
            if mod == ntdll_name:
                base, size = modules[mod]
                pos = bisect.bisect_left(ntdll_syms, Symbol('', '', addr))
                if pos >= 0 and pos < len(ntdll_syms) and ntdll_syms[pos].addr == addr:
                    continue
                bisect.insort(ntdll_syms, Symbol(mod, func, addr))

        if len(ntdll_syms):
            mdump_symbols_loaded = True

        if mdump_symbols_loaded:
            try:
                import cPickle as pickle

                if MDUMP_MODE_TYPE == MDUMP_AT_SYSCALL:
                    pyrebox_print("Begin ntdll symbols serialization, len: {}".format(len(ntdll_syms)))
                    f = open(ntdll_symbols_file, 'wb')
                    pickle.dump(ntdll_syms, f)
                    f.close()
                    pyrebox_print("End ntdll symbols serialization, len: {}".format(len(ntdll_syms)))
            except Exception as e:
                pyrebox_print("serial error:{}".format(e))

            #add syscall trace        
            ntdll_base, ntdll_size = modules[ntdll_name]
            if ntdll_base == 0:
                return

            if not cm.callback_exists("mdump_syscall_trace_{}".format(pid)):
                pyrebox_print("Tracing syscalls of pid:{}".format(pid))
                mdump_syscall_trace(pid, pgd)

    #process mdump at calling an API
    if MDUMP_MODE_TYPE == MDUMP_AT_CALL_API:
        #only update symbols for the process
        proc_syms = api.get_symbol_list(pgd)
        if len(proc_syms) == 0: #can't get syms at the time
            return

        pyrebox_print("Translate process symbols")
        modules_in_syms = set(target_procname)
        for s in proc_syms:
            mod = s['mod']
            func = s['name']
            addr = s['addr']
            base, size = modules[mod]
            modules_in_syms.add(mod)
            pos = bisect.bisect_left(process_syms, Symbol('', '', addr))
            if pos >= 0 and pos < len(process_syms) and process_syms[pos].addr == addr:
                continue
            bisect.insort(process_syms, Symbol(mod, func, addr))

            if(len(modules) == len(modules_in_syms)):
                mdump_symbols_loaded = True

        if mdump_symbols_loaded:
            try:
                import cPickle as pickle

                if MDUMP_MODE_TYPE == MDUMP_AT_CALL_API:
                    pyrebox_print("Begin process symbols serialization, len: {}".format(len(process_syms)))
                    f = open(process_symbols_file, 'wb')
                    pickle.dump(process_syms, f)
                    f.close()
                    pyrebox_print("End process symbols serialization, len: {}".format(len(process_syms)))

            except Exception as e:
                pyrebox_print("serial error:{}".format(e))



def mdump_new_proc(params):
    '''
    Process creation callback. Receives 3 parameters:
        :param pid: The pid of the process(int)
        :param pgd: The PGD of the process(int)
        :param name: The name of the process(str)
    '''
    global pyrebox_print
    global cm
    global ntdll_syms
    global process_syms
    global mdump_symbols_loaded
    global MDUMP_MODE_TYPE
    global s_start_time

    pid = params["pid"]
    pgd = params["pgd"]
    name = params["name"]


    if name.lower() == target_procname:
        #load serial symbols
        try:
            pyrebox_print("Begin load symbols")
            import cPickle as pickle
            if MDUMP_MODE_TYPE == MDUMP_AT_SYSCALL:
                f = open(ntdll_symbols_file, 'rb')
                ntdll_syms = pickle.load(f)
                f.close()
                pyrebox_print("End load ntdll symbols, len:{}".format(len(ntdll_syms)))
                if len(ntdll_syms): 
                    mdump_symbols_loaded = True
            elif MDUMP_MODE_TYPE == MDUMP_AT_CALL_API:
                f = open(process_symbols_file, 'rb')
                process_syms = pickle.load(f)
                f.close()
                pyrebox_print("End load process symbols, len:{}".format(len(process_syms)))
                if len(process_syms): 
                    mdump_symbols_loaded = True
            else:
                pass
        except Exception as e:
            pyrebox_print("Load syms error:{}".format(e))

        #monitor the malware process
        pyrebox_print("Malware started! pid: %x, pgd: %x, name: %s" % (pid, pgd, name))
        cm.rm_callback("mdump_new_proc")
        s_start_time = time.time()
        cm.add_callback(CallbackManager.LOADMODULE_CB, module_loaded, pgd = pgd, name = "mdump_module_loaded")
        pyrebox_print("Malware started! set the load module monitor")
        if MDUMP_MODE_TYPE == MDUMP_AT_CALL_API:
            mdump_api_trace(pid, pgd)
        api.start_monitoring_process(pgd)
        pyrebox_print("Malware started! set the process monitor" )


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
    guest_agent.copy_file(line.strip(), "C:\\"+target_procname)
    guest_agent.execute_file("C:\\"+target_procname)
    guest_agent.stop_agent()

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
    global target_procname

    pyrebox_print = printer
    pyrebox_print("[*]  Initializing callbacks")
    
    cm = CallbackManager(module_hdl, new_style = True)

    cm.add_callback(CallbackManager.CREATEPROC_CB, mdump_new_proc, name="mdump_new_proc")

    pyrebox_print("[*]  Initialized callbacks\n")
    # check if the target process exists, set calculator.exe as the default target process if it does not exist
    from os import listdir
    if target_procname not in listdir("malware/"):
        target_procname = "calculator.exe"
    copy_execute("malware/"+target_procname)


def clean():
    global cm
    global mdump_buffer
    if mdump_buffer:
        with open("{0}/{1}_{2}_log.txt".format(mdump_path, target_procname, mdump_mode), 'a') as f:
            for log in mdump_buffer:
                f.write(log+'\n')
        mdump_buffer = []
    print("[*]    Cleaning module")
    cm.clean()
    print("[*]    Cleaned module")

if __name__ == "__main__":
    pass
