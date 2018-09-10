# -------------------------------------------------------------------------------
#
#   Copyright (C) 2017 Cisco Talos Security Intelligence and Research Group
#
#   PyREBox: Python scriptable Reverse Engineering Sandbox
#   Author: Xabier Ugarte-Pedrero
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License version 2 as
#   published by the Free Software Foundation.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#   MA 02110-1301, USA.
#
# -------------------------------------------------------------------------------

from __future__ import print_function

# Callback manager
cm = None
pyrebox_print = None


def tlb_exec(params):
    global cm
    global counter
    import api

    cpu = params["cpu"]
    addr = params["vaddr"]

    pgd = api.get_running_process(cpu.CPU_INDEX)
    pyrebox_print("TLB exec, PGD %x Addr %x\n" % (pgd, addr))


def context_change(params):
    global cm
    global counter

    old_pgd = params["old_pgd"]
    new_pgd = params["new_pgd"]

    pyrebox_print("Context change %x -> %x\n" % (old_pgd, new_pgd))


def clean():
    '''
    Clean up everything. At least you need to place this
    clean() call to the callback manager, that will
    unregister all the registered callbacks.
    '''
    global cm
    print("[*]    Cleaning module")
    cm.clean()
    print("[*]    Cleaned module")


def initialize_callbacks(module_hdl, printer):
    '''
    Initilize callbacks for this module. This function
    will be triggered whenever import_module command
    is triggered.
    '''
    global cm
    global pyrebox_print
    from api import CallbackManager
    # Initialize printer
    pyrebox_print = printer
    pyrebox_print("[*]    Initializing callbacks")
    cm = CallbackManager(module_hdl, new_style = True)
    cm.add_callback(CallbackManager.TLB_EXEC_CB, tlb_exec, name="tlb_exec")
    cm.add_callback(CallbackManager.CONTEXTCHANGE_CB, context_change, name="context_change")
    pyrebox_print("[*]    Initialized callbacks")


if __name__ == "__main__":
    print("[*] Loading python module %s" % (__file__))
