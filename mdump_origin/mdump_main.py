#coding=utf-8
import os
import sys
import socket
import webbrowser
from SimpleHTTPServer import SimpleHTTPRequestHandler
import BaseHTTPServer
from argparse import ArgumentParser
import subprocess,shlex
from dump.analy_host import *
from analyse.dealjson import diff2Graph
from analyse.stage2_analy import *

current_path=os.getcwd()
# const var define
os_image = current_path+"/dump/winxp_sp3.img"
malware = current_path+"/dump/malware.exe"
run_malware = current_path+"/dump/run_malware.exe"
tmp_path = "dump/dump_tmp/"	

qemu_path = current_path+"/dump/qemu-1.0/i386-softmmu/qemu-system-i386"
qemu_memory = 128
qemu_cmd = "%s -hda %s -m %d -net nic,model=rtl8139 -net user -monitor stdio" % (
    qemu_path, os_image,qemu_memory)
copy_position="Documents\ and\ Settings/tonny/「开始」菜单/程序/启动"
port = 8000
mdump_p = 500
mdump_d = 4
startup = "C:\\malware.exe"

def clean(tmppath):
	rmfiles = []
	rmfiles.extend(glob.glob(tmppath + "*.json"))
	rmfiles.extend(glob.glob(tmppath + "*.db"))
	rmfiles.extend(glob.glob(tmppath + "*.dump"))
	rmfiles.extend(glob.glob(tmppath + "*.dmp"))
	for f in rmfiles:
		os.remove(f)


def presentation():
	is_open = False
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		s.connect(("127.0.0.1", int(port)))
		s.shutdown(2)
		is_open = True
	except:
		pass
	if is_open is True:
		print "is_open"		
		webbrowser.open_new_tab("http://localhost:%d/presentation/presentation.html"%port)	
	else:
		Handler=SimpleHTTPRequestHandler
	 	Server=BaseHTTPServer.HTTPServer
	 	Protocol="HTTP/1.0"
	 	server_address=("127.0.0.1",port)
	 	Handler.protocol_version=Protocol
	 	httpd=Server(server_address,Handler)
	 	webbrowser.open_new_tab("http://localhost:%d/presentation/presentation.html"%port)
	 	httpd.serve_forever()

def version():
	print "version: mdump 1.0"

def parse_dump_file(dump_dir):
    dump_file = get_dump_file(dump_dir)
    parse_stage2_file(dump_dir,dump_file[0])
    for i in range(1,len(dump_file)):
        parse_stage2_merge(dump_dir,dump_file[i], i)
    

    #compare the diff between two res.json
    res_nums=len(dump_file)
    order=1
    for i in range(1,res_nums):
    	ret=diff2Graph(dump_dir+"res%d.json"%(i-1),dump_dir+"res%d.json"%(i),dump_dir+"diff%d.json"%(order))
    	if ret is True:
    		order += 1

def IsCmdExist(cmd):
    all_cmds = []
    for p in os.environ['PATH'].split(':'):
        all_cmds.extend(os.listdir(p))
    return cmd in all_cmds

if __name__=="__main__":
	parser = ArgumentParser()
	parser.add_argument("-mp","--malware",dest="malware",help="malware path,default=./dump/malware.exe")
	parser.add_argument("-imgp","--os_image",help="os image file path,default=./dump/winxp.img")
	parser.add_argument("-qp","--qemu",help="qemu path")
	parser.add_argument("-m","--memory",type=int,default=128,help="dump file size,default=128M")
	parser.add_argument("-p","--port",type=int,default=8000,help="presentation http server port,default=8000")
	parser.add_argument("--mdump_p",type=int,default=500,help="mdump period,default=500ms")
	parser.add_argument("--mdump_d",type=int,default=4,help="mdump duration,default=4s")
	parser.add_argument("-s","--startup",help="malware startup arguement")
	parser.add_argument("-pt",dest="presentation",action="store_true",default=False,help="presentation directly")
	parser.add_argument("-i",dest="cp_ignore",action="store_true",default=False,help="prase dump and presentation directly")
	parser.add_argument("-v","--version",action="store_true",help="version information")
	options=parser.parse_args()
	
	if options.presentation is True:
		presentation()
		sys.exit()
	
	if options.version is True:
		version()
	if options.startup is not None:
		startup=options.startup
	if options.malware is not None:
		malware=options.malware
	if options.os_image is not None:
		os_image=options.os_image
	if options.qemu is not None:
		qemu_path=options.qemu
	if options.memory is not None:
		qemu_memory=options.memory
	if options.port is not None:
		port=options.port
	if options.mdump_p is not None:
		mdump_p=options.mdump_p
	if options.mdump_d is not None:
		mdump_d=options.mdump_d
		
	if options.cp_ignore is False:
		clean(tmp_path)
        if not IsCmdExist('qemu-img'):
            print 'error!, qemu-img command is not exist.'
            quit()
        snapshot = "qemu-img snapshot -c tmp_snapshot {}".format(os_image)
        os.system(snapshot)
    
		ret=copy_to_guestWinXP(img_path=os_image,copy_where=copy_position,run_malware_path=run_malware,malware_path=malware)
		if ret is not True:
			print ret
			sys.exit()

		qemu_args = shlex.split(qemu_cmd)
		child = subprocess.Popen(qemu_args,stdin=subprocess.PIPE)
		listen_from_guest(child,startup,mdump_p,mdump_d)
		child.kill()
	
        recsnap = "qemu-img snapshot -d tmp_snapshot {}".format(os_image)
        os.system(recsnap)
	
	parse_dump_file(tmp_path)
	presentation()




           
