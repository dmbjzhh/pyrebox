# mdump basic function

from __future__ import print_function
import time
from api import CallbackManager
import api
import bisect
import time
from collections import defaultdict
import functools
from volatility.plugins.overlays.windows.xp_sp2_x86_syscalls import syscalls

# from libdamm.api import API as DAMM
# import sqlite3

requirements = ["plugins.guest_agent"]

# Callback manager
cm = None
# Printer
pyrebox_print = None
target_procname = ''
dump_path = "dump_result/"

# modules for the process
modules = defaultdict(lambda :(0,0))

# symbols for the process
ntdll_syms = []
ntdll_name= "ntdll.dll"
ntdll_symbols_file = "/tmp/ntdll.symbols.bin"
KiFastSystemCall_addr = -1  # xp sp2=0x7c92e4f0
KiFastSystemCall_name = "KiFastSystemCall"

TRACE_ALL_NTDLL_API = False
TARGET_LONG_SIZE = api.get_os_bits() / 8

winXP_Exclude_APIs = [0x11a5, # NtUserGetMessage
                      0x1165  # NtUserDispatchMessage
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
    
    
def locate_nearest_symbol(addr):
    global ntdll_syms
    base, size = modules[ntdll_name]
    if base == 0:
        return None
    pos = bisect.bisect_left(ntdll_syms, Symbol('', '', addr-base))
    if pos < 0 or pos >= len(ntdll_syms):
        return None
    if ntdll_syms[pos].addr+base != addr:
        pos -= 1
    if (addr - ntdll_syms[pos].addr - base) < 0x32 and (addr - ntdll_syms[pos].addr - base) >= 0:    
        return ntdll_syms[pos]
    else:
        return None

def syscall_func(dest_pid, dest_pgd, params):
    global pyrebox_print
    global cm

    cpu_index = params['cpu_index']
    cpu = params['cpu']
    tb = params['tb']
    if cpu.EIP != KiFastSystemCall_addr:
        pyrebox_print("Error in syscall_func")
        return

    if TARGET_LONG_SIZE == 4:
        if not cpu.EAX in winXP_Exclude_APIs:
            pos = (cpu.EAX & 0xf000) >> 12
            num = (cpu.EAX & 0x0fff)
            if pos > 1 :
                pyrebox_print("Error in syscall index")
                return
            pyrebox_print("[PID:%x] %s:%08x" % (dest_pid, syscalls[pos][num], cpu.EAX))
    elif TARGET_LONG_SIZE == 8:    
        pyrebox_print("[PID:%x] KiFastSystemCall RAX:%016x" % (dest_pid, cpu.RAX))


def opcodes(dest_pid, dest_pgd, params):
    global pyrebox_print
    global cm

    cpu_index = params['cpu_index']
    cpu = params['cpu']
    pc = params['cur_pc']
    next_pc = params['next_pc']

    # if is_in_pending_resolution(pgd, next_pc):
    #    update_symbols()
    try:
        sym = locate_nearest_symbol(next_pc)
        if sym is None:
            return

        mod = sym.mod
        func = sym.func

        if mod != ntdll_name:
            return

        base, size = modules[mod]
        real_api_addr = sym.addr + base
        if real_api_addr < base and real_api_addr >= base+size:
            return
        # pyrebox_print("mod:{}, func:{}, addr:{}".format(mod, func, hex(real_api_addr)))
        if next_pc != real_api_addr:
            return

        if TARGET_LONG_SIZE == 4:
            pyrebox_print("[PID:%x] pc:%08x-->mod:%s,func:%s(%08x)" % (dest_pid, pc, mod, func, real_api_addr))
        elif TARGET_LONG_SIZE == 8:    
            pyrebox_print("[PID:%x] pc:%016x-->mod:%s,func:%s(%016x)" % (dest_pid, pc, mod, func, real_api_addr))

    except Exception as e:
        pyrebox_print(str(e))
        traceback.print_exec()
    finally:
        return


def ntdll_trace(dest_pid, dest_pgd):
    global pyrebox_print
    global cm
    pyrebox_print("Initializing ntdll trace......")

    cm.add_callback(CallbackManager.OPCODE_RANGE_CB, functools.partial(opcodes, dest_pid, dest_pgd), name="opcode1_%x" % dest_pid, start_opcode=0xFF, end_opcode=0xFF)
    
    cm.add_trigger(("opcode1_%x" % dest_pid), "triggers/trigger_opcode_user_only.so")
    cm.set_trigger_var(("opcode1_%x" % dest_pid), "cr3", dest_pgd)

def syscall_trace(dest_pid, dest_pgd):
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

    if KiFastSystemCall_addr == -1:
        pyrebox_print("Error, there is no KiFastSystemCall symbol")
        return

    cm.add_callback(CallbackManager.BLOCK_BEGIN_CB, functools.partial(syscall_func, dest_pid, dest_pgd), name="syscall_trace_{}".format(dest_pid), addr=KiFastSystemCall_addr, pgd=dest_pgd)
    

def module_loaded(params):
    global ntdll_syms
    global modules
    global cm

    pid = params["pid"]
    pgd = params["pgd"]
    base = params["base"]
    size = params["size"]
    name = params["name"]
    fullname = params["fullname"]
    modules[name] = (base, size)
    pyrebox_print("Module name:%s" % name)

    
    if  len(ntdll_syms) == 0:
        # only update symbols for the process
        proc_syms = api.get_symbol_list(pgd)
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
            pyrebox_print("Begin symbol serialization, len: {}".format(len(ntdll_syms)))
            try:
                import cPickle as pickle
                f = open(ntdll_symbols_file, 'wb')
                pickle.dump(ntdll_syms, f)
                f.close()
            except Exception as e:
                pyrebox_print("serial error:{}".format(e))
            pyrebox_print("End symbol serialization, len: {}".format(len(ntdll_syms)))

            
    if len(ntdll_syms):
        ntdll_base, ntdll_size = modules[ntdll_name]
        if ntdll_base == 0:
            return

        if not cm.callback_exists("syscall_trace_{}".format(pid)):
            if not TRACE_ALL_NTDLL_API:
                pyrebox_print("Tracing syscalls of %s" % name)
                syscall_trace(pid, pgd)

def new_proc(params):
    '''
    Process creation callback. Receives 3 parameters:
        :param pid: The pid of the process(int)
        :param pgd: The PGD of the process(int)
        :param name: The name of the process(str)
    '''
    global pyrebox_print
    global cm
    global ntdll_syms

    pid = params["pid"]
    pgd = params["pgd"]
    name = params["name"]


    if name.lower() == target_procname:
        # load serial symbols
        try:
            pyrebox_print("Begin load symbols")
            import cPickle as pickle
            f = open(ntdll_symbols_file, 'rb')
            ntdll_syms = pickle.load(f)
            f.close()
            pyrebox_print("End load symbols, len:{}".format(len(ntdll_syms)))
        except Exception as e:
            pyrebox_print("Load ntdll_syms error:{}".format(e))

        # monitor the malware process
        pyrebox_print("Malware started! pid: %x, pgd: %x, name: %s" % (pid, pgd, name))
        cm.rm_callback("mdump_new_proc")
        cm.add_callback(CallbackManager.LOADMODULE_CB, module_loaded, pgd = pgd, name = "mdump_module_loaded")
        pyrebox_print("Malware started! set the load module monitor")
        if TRACE_ALL_NTDLL_API:
            ntdll_trace(pid, pgd)
        api.start_monitoring_process(pgd)
        pyrebox_print("Malware started! set the process monitor")


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

    pyrebox_print = printer
    pyrebox_print("[*]  Initializing callbacks")
    
    cm = CallbackManager(module_hdl, new_style = True)

    cm.add_callback(CallbackManager.CREATEPROC_CB, new_proc, name="mdump_new_proc")
    
    pyrebox_print("[*]  Initialized callbacks\n")
    copy_execute("malware/malware.exe")


def clean():
    global cm
    print("[*]    Cleaning module")
    cm.clean()
    print("[*]    Cleaned module")

if __name__ == "__main__":
    pass
