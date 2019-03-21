target_procname = 'calculator.exe'
vol_profile = "WinXPSP3x86"

try:
    f1 = open("pyrebox.conf", "r")

    for line in f1:
        if "target: " in line:
            target_procname = line[7:].strip()
        if "profile: " in line:
            vol_profile = line[8:].strip()
except:
    print("No target_procname specified in pyrebox.conf, the default value will be used.")
finally:
    if f1:
        f1.close()

process_symbols_file = "/tmp/proc.symbols."+target_procname+'.'+vol_profile+'.bin'
ntdll_symbols_file = "/tmp/ntdll.symbols."+target_procname+'.'+vol_profile+'.bin'