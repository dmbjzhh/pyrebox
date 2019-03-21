from __future__ import print_function
from ipython_shell import start_shell
from api import CallbackManager

# Callback manager
cm = None
# Printer
pyrebox_print = None
# monitored pid
monitored_pid = []


def read_return_parameter(cpu):
    '''
        Returns the return parameter (EAX/RAX)
    '''
    import api
    TARGET_LONG_SIZE = api.get_os_bits() / 8
    if TARGET_LONG_SIZE == 4:
        return cpu.EAX
    elif TARGET_LONG_SIZE == 8:
        return cpu.RAX
    else:
        raise Exception(
            "[mdump::read_return_parameter(cpu)] : Non-supported TARGET_LONG_SIZE: %d" % TARGET_LONG_SIZE)

def dereference_target_long(addr, pgd):
    import api
    TARGET_LONG_SIZE = api.get_os_bits() / 8
    typ = "<I" if TARGET_LONG_SIZE == 4 else "<Q"
    try:
        buff = api.r_va(pgd, addr, TARGET_LONG_SIZE)
    except:
        buff = "\x00" * TARGET_LONG_SIZE
        pyrebox_print("Could not dereference TARGET_LONG in mdump_syscall.py")
    return struct.unpack(typ, buff)[0]

# def mdump_check_ppid(params, pid):
    # import volatility.win32.tasks as tasks
    # global pyrebox_print
    # global cm
    # from api import get_running_process
    # from utils import get_addr_space
    # import api

    # TARGET_LONG_SIZE = api.get_os_bits() / 8

    # cpu_index = params["cpu_index"]
    # cpu = params["cpu"]

    # pgd = get_running_process(cpu_index)

    # # Do not continue if EAX/RAX returns and invalid return code.
    # if read_return_parameter(cpu) != 0:
    #     return

    # # Load volatility address space
    # addr_space = get_addr_space(pgd)

    # # Get list of processes, and filter out by the process that triggered the
    # # call (current process id)
    # eprocs = [t for t in tasks.pslist(addr_space) if t.UniqueProcessId == pid]

    # print(eprocs)

    # # Initialize proc_obj, that will point to the eprocess of the new created process
    # proc_obj = None

    # # Dereference the output argument containing the hdl of the newly created process
    # proc_hdl = dereference_target_long(proc_hdl_p, pgd)

    # # Search handle table for the new created process
    # for task in eprocs:
    #     if task.UniqueProcessId == pid and task.ObjectTable.HandleTableList:
    #         for handle in task.ObjectTable.handles():
    #             if handle.is_valid() and handle.HandleValue == proc_hdl and handle.get_object_type() == "Process":
    #                 proc_obj = handle.dereference_as("_EPROCESS")
    #                 break
    #         break
    
    # if proc_obj is not None:
    #     pyrebox_print("[PID: %x] NtCreateProcess: %s - PID: %x - CR3: %x\n" % (pid,
    #                                                                      str(proc_obj.ImageFileName),
    #                                                                      int(proc_obj.UniqueProcessId),
    #                                                                      int(proc_obj.Pcb.DirectoryTableBase.v())))

    #     # Check if we are already monitoring the process
    #     if api.is_monitored_process(pgd):
    #         return
        
    #     pyrebox_print("Following %s %x %x" %
    #     (proc_obj.ImageFileName,proc_obj.UniqueProcessId,proc_obj.Pcb.DirectoryTableBase.v()))
        
    #     api.start_monitoring_process(pgd)
    # else:
    #     if TARGET_LONG_SIZE == 4: 
    #         pyrebox_print("Error while trying to retrieve EPROCESS for handle %x, PID %x, EAX: %x" % (proc_hdl, pid, cpu.EAX))
    #     elif TARGET_LONG_SIZE == 8:
    #         pyrebox_print("Error while trying to retrieve EPROCESS for handle %x, PID %x, EAX: %x" % (proc_hdl, pid, cpu.RAX))

    # return



def new_proc(params):
    '''
    Process creation callback. Receives 3 parameters:
        :param pid: The pid of the process
        :type pid: int
        :param pgd: The PGD of the process
        :type pgd: int
        :param name: The name of the process
        :type name: str
    '''
    global pyrebox_print
    global cm

    pid = params["pid"]
    pgd = params["pgd"]
    name = params["name"]

    # Print a message.
    pyrebox_print("New process created! pid: %x, pgd: %x, name: %s" % (pid, pgd, name))

    import volatility.win32.tasks as tasks
    from api import get_running_process
    from utils import get_addr_space
    import api

    # Load volatility address space
    addr_space = get_addr_space(pgd)

    # Get list of processes, and filter out by the process that triggered the
    # call (current process id)
    eprocs = [t for t in tasks.pslist(addr_space) if t.UniqueProcessId == pid]

    for t in tasks.pslist(addr_space):
        print(t.UniqueProcessId)

    # Initialize proc_obj, that will point to the eprocess of the new created process
    proc_obj = None

    
    # Search handle table for the new created process
    for task in eprocs:
        if task.UniqueProcessId == pid and task.ObjectTable.HandleTableList:
            for handle in task.ObjectTable.handles():
                if handle.is_valid() and handle.get_object_type() == "Process":
                    proc_obj = handle.dereference_as("_EPROCESS")
                    break
            break
    
    if proc_obj is not None:
        pyrebox_print("[PID: %x] NtCreateProcess: %s - PID: %x - CR3: %x\n" % (pid,
                                                                         str(proc_obj.ImageFileName),
                                                                         int(proc_obj.UniqueProcessId),
                                                                         int(proc_obj.Pcb.DirectoryTableBase.v())))

        # Check if we are already monitoring the process
        if api.is_monitored_process(pgd):
            return
        
        pyrebox_print("Following %s %x %x" %
        (proc_obj.ImageFileName,proc_obj.UniqueProcessId,proc_obj.Pcb.DirectoryTableBase.v()))
        
        api.start_monitoring_process(pgd)
    else:
        pyrebox_print("Error")
    return
    


def initialize_callbacks(module_hdl, printer):
    '''
    Initilize callbacks for this module.
    '''
    global cm
    global pyrebox_print
    # Initialize printer function
    pyrebox_print = printer
    pyrebox_print("[*]    Initializing callbacks")
    # Initialize the callback manager
    cm = CallbackManager(module_hdl, new_style = True)

    # Register a process creation callback
    cm.add_callback(CallbackManager.CREATEPROC_CB, new_proc)

    pyrebox_print("[*]    Initialized callbacks")


def clean():
    '''
    Clean up everything.
    '''
    global cm
    print("[*]    Cleaning module")
    # This call will unregister all existing callbacks
    cm.clean()
    print("[*]    Cleaned module")


if __name__ == "__main__":
    # This message will be displayed when the script is loaded in memory
    print("[*] Loading python module %s" % (__file__))