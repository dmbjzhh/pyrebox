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


def my_function(params):
    global cm

    cpu_index = params["cpu_index"]
    addr = params["vaddr"]
    size = params["size"]
    haddr = params["haddr"]
    data = params["data"]

    pyrebox_print("Memory  write at address %x with size %x\n" % (addr, size))


def clean():
    '''
    Clean up everything. At least you need to place this
    clean() call to the callback manager, that will
    unregister all the registered callbacks.
    '''
    global cm
    pyrebox_print("[*]    Cleaning module\n")
    cm.clean()
    pyrebox_print("[*]    Cleaned module\n")


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
    pyrebox_print("[*]    Initializing callbacks\n")
    cm = CallbackManager(module_hdl, new_style = True)
    cm.add_callback(CallbackManager.MEM_WRITE_CB, my_function, name="mem_write")
    pyrebox_print("[*]    Initialized callbacks\n")
    pyrebox_print("[!]    Test: Open calc.exe and monitor the process")


if __name__ == "__main__":
    print("[*] Loading python module %s" % (__file__))
