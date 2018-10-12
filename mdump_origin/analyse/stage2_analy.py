# -*- coding: cp936 -*-
import sqlite3
import struct
import re
import os
from libdamm.api import API as DAMM
import webbrowser
from dealjson import sqlite_to_json


int64_size = 8;
fix_str='pc.ram';


def parse_stage2_file(dump_path,filename):
    file_output=open(dump_path+'thefile.dump','wb') 
    with open(filename, 'rb') as f:
        total_b = f.read(int64_size)
        total = struct.unpack(">Q",total_b)[0]
        
        idlen_b = f.read(1)
        idlen = struct.unpack("b",idlen_b)[0]
        idbuf_b = f.read(idlen)
        format_str = "{0}s".format(idlen)
        idbuf = struct.unpack(format_str,idbuf_b)[0]
	
        while True:
            #print "total=%d" % total	
            if total & 2 :
            #print "1 byte"
                cont=4096
                blocklen_b = f.read(1)
                while cont:
                    file_output.write(blocklen_b)
                    cont=cont-1
            elif total & 8:
                #print "4096 byte"
                blocklen_b = f.read(4096)
                file_output.write(blocklen_b)
            
            total_b = f.read(int64_size)
            total = struct.unpack(">Q",total_b)[0]
            #print "total=%d" % total
            if not total & 32 :
                print "thefile.dump has been create"
                damm = DAMM(plugins=['all'], memimg=os.path.abspath(dump_path+"thefile.dump"), profile="WinXPSP3x86",db=dump_path+"res0.db")
                results = damm.run_plugins()
                for elem in results:
                    print elem
                sqlite_to_json(dump_path+"res0.db",dump_path+"res0.json")
                break

def parse_stage2_merge(dump_path,addfile,order):
    with open(addfile, 'rb') as f:
        while True:
            while True:
                idbuf_b = f.read(6)
                if idbuf_b == "":
                    #print "end of file"
                    damm = DAMM(plugins=['all'], memimg=os.path.abspath(dump_path+"thefile.dump"), profile="WinXPSP3x86",db=dump_path+"res%d.db"%(order))
                    results = damm.run_plugins()
                    for elem in results:
                        print elem
                    damm = DAMM(plugins=['all'],db=dump_path+'res%d.db'%(order),diff=dump_path+'res%d.db'%(order-1))
                    results1=damm.do_diffs_screen()
                    diff_output=open(dump_path+'ddddiff%d.txt'%(order-1),'wb')  
                    for elem in results1:
                        diff_output.write(elem)
                        diff_output.write("\n")
                    sqlite_to_json(dump_path+"res%d.db"%(order),dump_path+"res%d.json"%(order))
                    return
                elif len(idbuf_b) == 6:
                    format_str = "{0}s".format(6)
                    idbuf = struct.unpack(format_str,idbuf_b)[0]
                    if idbuf==fix_str :
                        break
                    f.seek(-5,1)
                    
            f.seek(-15,1)
            total_b = f.read(int64_size)
            total = struct.unpack(">Q",total_b)[0]
            
            idlen_b = f.read(1)
            idlen = struct.unpack("b",idlen_b)[0]
            
            idbuf_b = f.read(idlen)
            format_str = "{0}s".format(idlen)
            idbuf = struct.unpack(format_str,idbuf_b)[0]
            
            with open(dump_path+"thefile.dump",'r+b') as f1:
                while True:
                    #print "total=%d" % total	
                    if total & 2 :
                        #print "1 byte"
                        temp=(total/4096)*4096
                        f1.seek(temp,0)
                        cont=4096
                        blocklen_b = f.read(1)
                        #print blocklen_b
                        while cont:
                            f1.write(blocklen_b)
                            cont=cont-1
                    elif total & 8:
                            #print "4096 byte"
                        temp=(total/4096)*4096
                        f1.seek(temp,0)
                        blocklen_b = f.read(4096)
                        f1.write(blocklen_b)
            
                    total_b = f.read(int64_size)
                    if total_b=="":
                        print "thefile.dump has been changed" 
                        break
                    total = struct.unpack(">Q",total_b)[0]
                    #print "total=%d" % total
                    if not total & 32 :
                        print "thefile%d.dump has been created" %(order)
                        break 

