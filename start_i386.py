from __future__ import print_function
import subprocess
import os
import sys
import time

# check the snapshot
print("Check the snapshot")

if "clean" in subprocess.check_output("qemu-img snapshot -l ../pyrebox_venv/images/WinXP_test.qcow2", shell=True):
    print("VM already has a clean snapshot")
else:
    print("Taking clean snapshot...")
    subprocess.call("cp pyrebox.conf.snapshot pyrebox.conf", shell=True)
    p1 = subprocess.Popen("./pyrebox-i386 -monitor stdio -m 256 -usb -device usb-tablet -drive file=../pyrebox_venv/images/WinXP_test.qcow2,index=0,media=disk,format=qcow2,cache=unsafe", shell=True, stdin=subprocess.PIPE)
    time.sleep(300)
    p1.stdin.write("\n")
    p1.stdin.write("savevm clean\n")
    time.sleep(2)
    p1.stdin.write("info snapshots\n")
    time.sleep(2)
    p1.stdin.write("q\n")
    time.sleep(2)
    
#make the trigger
print("Check the trigger")
opcode_trigger="trigger/trigger_opcode_user_only-i386-softmmu.so"
if not os.path.isfile(opcode_trigger):
    print("Make the trigger")
    subprocess.call("make triggers/trigger_opcode_user_only-i386-softmmu.so", shell=True)

#produce the symbols file 
serialFile = "/tmp/ntdll.symbols.bin"
if not os.path.isfile(serialFile) or os.path.getsize(serialFile) == 0:
    print("Produce the symbols file")
    p = subprocess.Popen("./pyrebox-i386 -monitor stdio -m 256 -usb -device usb-tablet -drive file=../pyrebox_venv/images/WinXP.qcow2,index=0,media=disk,format=qcow2,cache=unsafe -loadvm clean", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)
    res = p.poll()
    while res is None:
        line = p.stdout.readline()
        time.sleep(1) if line == None else print(line.strip())
        if 'End symbol serialization' in line:
            p.stdin.write('q\n')
        #time.sleep(1)
        res = p.poll()

#run the malware
print("Run malware")
subprocess.call("cp pyrebox.conf.mdump pyrebox.conf", shell=True)
subprocess.call("./pyrebox-i386 -monitor stdio -m 256 -usb -device usb-tablet -drive file=../pyrebox_venv/images/WinXP_test.qcow2,index=0,media=disk,format=qcow2,cache=unsafe -loadvm clean", shell=True)
