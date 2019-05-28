# -*- coding:utf-8 -*-
from __future__ import print_function
import subprocess
import os
import time
import argparse
import zipfile

DEFAULT_TARGET = "calculator.exe"

# check the target process name by terminal argument
parser = argparse.ArgumentParser(description="Check target process name")
parser.add_argument("--target", help="Name of the target malware")
args = parser.parse_args()
target_procname = args.target if args.target else DEFAULT_TARGET

# check folder /tmp/dump_result
if not os.path.exists("/tmp/dump_result"):
    os.makedirs("/tmp/dump_result")

# decompress malware if not exsits
if not os.path.exists("malware/"+target_procname):
    try:
        zip_name = "malware/"+target_procname[:-4]+".zip"
        zipFile = zipfile.ZipFile(zip_name)
        zipFile.extractall(path="malware/",pwd=bytes("mdump"))
    except:
        print("specified target zip file does not exsit!")

# check the snapshot
print("Check the snapshot")

if "clean" in subprocess.check_output("qemu-img snapshot -l ../../images/WinXP.qcow2", shell=True):
    print("VM already has a clean snapshot")
else:
    print("Taking clean snapshot...")
    # set pyrebox.conf for snapshot
    try:
        f1 = open("pyrebox.conf")
        temp = f1.read()
        temp = temp.replace('plugins.guest_agent: False\n', 'plugins.guest_agent: True\n')
        temp = temp.replace('scripts.mdump_syscall: True\n', 'scripts.mdump_syscall: False\n')
        f2 = open("pyrebox.conf", "w")
        f2.write(temp)
    finally:
        if f1:
            f1.close()
        if f2:
            f2.close()
    p1 = subprocess.Popen("./pyrebox-i386 -monitor stdio -m 256 -usb -device usb-tablet -drive file=../../images/WinXP.qcow2,index=0,media=disk,format=qcow2,cache=unsafe", shell=True, stdin=subprocess.PIPE)
    time.sleep(300)
    p1.stdin.write("\n")
    p1.stdin.write("savevm clean\n")
    time.sleep(2)
    p1.stdin.write("info snapshots\n")
    time.sleep(2)
    p1.stdin.write("q\n")
    time.sleep(2)

# make the trigger
print("Check the trigger")
opcode_trigger = "trigger/trigger_opcode_user_only-i386-softmmu.so"
if not os.path.isfile(opcode_trigger):
    print("Make the trigger")
    subprocess.call("make triggers/trigger_opcode_user_only-i386-softmmu.so", shell=True)

# set pyrebox.conf for symbol file
try:
    f1 = open("pyrebox.conf", "r")
    result = list()
    for line in f1.readlines():
        if "plugins.guest_agent: True" in line:
            line = line.replace("True", "False")

        if "scripts.mdump_syscall: False" in line:
            line = line.replace("False", "True")

        if "target:" in line:
            line = line.replace(line, "target: {}\n".format(target_procname))

        if "mode: " in line:
            mdump_mode = line[5:].strip()
        result.append(line)

    f2 = open("pyrebox.conf", "w")
    f2.write('%s' % ''.join(result))
finally:
    if f1:
        f1.close()
    if f2:
        f2.close()

# produce the symbols file
from symbolfile import ntdll_symbols_file, process_symbols_file

if mdump_mode == 'syscall':
    serialFile = ntdll_symbols_file
    if not os.path.isfile(serialFile) or os.path.getsize(serialFile) == 0:
        print("Produce the ntdll symbols file")
        p = subprocess.Popen("./pyrebox-i386 -monitor stdio -m 256 -usb -device usb-tablet -drive file=../../images/WinXP.qcow2,index=0,media=disk,format=qcow2,cache=unsafe -loadvm clean", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)
        res = p.poll()
        while res is None:
            line = p.stdout.readline()
            time.sleep(1) if line is None else print(line.strip())
            if 'End ntdll symbols serialization' in line:
                p.stdin.write('q\n')
            # time.sleep(1)
            res = p.poll()
    else:
        print("Already has ntdll symbols file")

if mdump_mode == 'api':
    serialFile = process_symbols_file
    if not os.path.isfile(serialFile) or os.path.getsize(serialFile) == 0:
        print("Produce the process symbols file")
        p = subprocess.Popen("./pyrebox-i386 -monitor stdio -m 256 -usb -device usb-tablet -drive file=../../images/WinXP.qcow2,index=0,media=disk,format=qcow2,cache=unsafe -loadvm clean", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)
        res = p.poll()
        while res is None:
            line = p.stdout.readline()
            time.sleep(1) if line is None else print(line.strip())
            if 'End process symbols serialization' in line:
                p.stdin.write('q\n')
            # time.sleep(1)
            res = p.poll()
    else:
        print("Already has process symbols file")


# run the malware
import ConfigParser
import threading

# 读取配置文件
config = ConfigParser.RawConfigParser()
config.read('pyrebox.conf.mdump')
# 获取 pyrebox 要运行的最长时间
runtime_str = config.get('SETTING', 'runtime')
runtime = int(runtime_str)

# 指明是否已经退出了pyrebox
if_exit_pyrebox = False

p1 = subprocess.Popen("./pyrebox-i386 -monitor stdio -m 256 -usb -device usb-tablet -drive file=../../images/WinXP.qcow2,index=0,media=disk,format=qcow2,cache=unsafe -loadvm clean -vnc :1", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

def timer_pyrebox_close(p1):
    global if_exit_pyrebox
    global timer1

    if_exit_pyrebox  = True
    if p1.poll() is None:
        p1.stdin.write('\r')
        p1.stdin.write('uaq\n')
    timer1.cancel()
    os._exit(0)



def log_show(p):
    res = p.poll()
    while res is None:
        line = p.stdout.readline()
        if line is None:
            time.sleep(1) 
        else:
            print(line.strip())
        res = p.poll()


# 打印日志
timer1 = threading.Timer(0, log_show, [p1])
timer1.start()

# runtime 即为 pyrebox 要运行的最长时间
timer2 = threading.Timer(runtime, timer_pyrebox_close, [p1])
timer2.start()

# 获取主进程终端实时的输入
line = raw_input("(qemu) ")
# 如果想要提前退出，就输入exit
while if_exit_pyrebox is False and line != "exit":
    print(line)
    line = raw_input("(qemu) ")


# 如果此时还没到达最长运行时间，就提前结束
if if_exit_pyrebox is False and p1.poll() is None:
    timer2.cancel()  # 关闭定时任务
    p1.stdin.write('\r')
    p1.stdin.write('uaq\n')
