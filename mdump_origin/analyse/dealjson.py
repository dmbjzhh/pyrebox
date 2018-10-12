# conding=utf-8
import json
import sqlite3

def diff2Graph(json1,json2,resultjson="diff.json"):
    fp=open(json1,"r")
    j1=json.load(fp)
    fp.close()

    fp=open(json2,"r")
    j2=json.load(fp)
    fp.close()

    links1=j1["links"]
    links2=j2["links"]
    nodes1=[]
    nodes2=[]

    for link in links1:
        snode={"name":link["source"],"group":link["source_group"]}
        tnode={"name":link["target"],"group":link["target_group"]}
        if snode not in nodes1:
            nodes1.append(snode)
        if tnode not in nodes1:
            nodes1.append(tnode)

    for link in links2:
        snode={"name":link["source"],"group":link["source_group"]}
        tnode={"name":link["target"],"group":link["target_group"]}
        if snode not in nodes2:
            nodes2.append(snode)
        if tnode not in nodes2:
            nodes2.append(tnode)

	#compare links
    links_add=[]
    links_remove=[]
    for link in links2:
        if link not in links1:
			links_add.append(link)

    for link in links1:
        if link not in links2:
            links_remove.append(link)

	#compare nodes
    nodes_add=[]
    nodes_remove=[]
    for node in nodes2:
        if node not in nodes1:
            nodes_add.append(node)

    for node in nodes1:
        if node not in nodes2:
            nodes_remove.append(node)

    res={}
    res["links_add"]=links_add
    res["links_remove"]=links_remove
    res["nodes_add"]=nodes_add
    res["nodes_remove"]=nodes_remove

    change=len(nodes_add)+len(nodes_remove)+len(links_add)+len(links_remove)
    print change
    if change==0:
        return False
    
    fp=open(resultjson,"w")
    json.dump(res,fp)
    fp.close()
    return True


def sqlite_to_json(dbname,resname):
    CODEC = 'utf-8'
    G=globals()
    temp={}
    tem={}
    f=file(resname,"w+")
    conn = sqlite3.connect(dbname)

    nodes=[]
    #processes_ProcessSet
    cur_proc = conn.execute('select * from %s' % "processes_ProcessSet")
    rows_proc = cur_proc.fetchall()

    pid_dict=[]
    ppid=[]
    dict={}
    m=1
    count=0
    count_dict={}
    ppid_dict={}

    for proc in rows_proc:
        pid_dict.append(proc[2].encode(CODEC))
        ppid.append(proc[3].encode(CODEC))
        dict[proc[2].encode(CODEC)]=proc[1].encode(CODEC)
    for i in pid_dict:
        count_dict[count]=i
        G['dict'+str(count)]={}
        temp['name']=dict[i]
        temp['pid']=i
        temp['count']=count
        temp['group']=m
        G['dict'+str(count)]=temp.copy()
        nodes.append(G['dict'+str(count)])
        count=count+1
    proc_count=count-1
    m=m+1

    k=0
    for i in ppid:
        ppid_dict[k]=i
        k=k+1

    #injections_InjectionSet
    cur_inje = conn.execute('select * from %s' % "injections_InjectionSet")
    rows_inje = cur_inje.fetchall()

    inje_set=set()
    injenode_start=count
    for inje in rows_inje:
        inje_set.add("%s_injection" %inje[1].encode(CODEC))
    for i in inje_set:
        G['dict'+str(count)]={}
        temp['name']= filter(str.isalpha, i)
        temp['pid']=filter(str.isdigit, i)
        temp['count']=count
        temp['group']=m
        G['dict'+str(count)]=temp.copy()
        nodes.append(G['dict'+str(count)])
        count_dict[count]=filter(str.isdigit, i)
        count=count+1
    injenode_end=count-1
    m=m+1
    inje_start=count
    for inje in rows_inje:
        if inje[1]!="":
            count_dict[count]=inje[1].encode(CODEC)
            G['dict'+str(count)]={}
            temp['name']=(inje[2].encode(CODEC),inje[3].encode(CODEC))
            temp['pid']=inje[1].encode(CODEC)
            temp['count']=count
            temp['group']=m
            G['dict'+str(count)]=temp.copy()
            nodes.append(G['dict'+str(count)])
            count=count+1

    m=m+1
    inje_end=count-1


    #connections_ConnectionSet
    cur_cone= conn.execute('select * from %s' % "connections_ConnectionSet")
    rows_cone = cur_cone.fetchall()

    cone_set=set()
    conenode_start=count
    for cone in rows_cone:
        cone_set.add("%s_connection" %cone[1].encode(CODEC))
    for i in cone_set:
        G['dict'+str(count)]={}
        temp['name']=filter(str.isalpha, i)
        temp['pid']=filter(str.isdigit, i)
        temp['count']=count
        temp['group']=m
        G['dict'+str(count)]=temp.copy()
        nodes.append(G['dict'+str(count)])
        count_dict[count]=filter(str.isdigit, i)
        count=count+1
    conenode_end=count-1
    m=m+1
    cone_start=count
    for cone in rows_cone:
        if cone[1]!="":    
            G['dict'+str(count)]={}
            temp['name']=(cone[2].encode(CODEC),cone[3].encode(CODEC))
            temp['pid']=cone[1].encode(CODEC)
            temp['count']=count
            temp['group']=m
            G['dict'+str(count)]=temp.copy()
            nodes.append(G['dict'+str(count)])
            count_dict[count]=cone[1].encode(CODEC)    
            count=count+1
    
    m=m+1
    cone_end=count-1

    #privileges_PrivilegeSet
    cur_priv= conn.execute('select * from %s' % "privileges_PrivilegeSet")
    rows_priv = cur_priv.fetchall()

    priv_set=set()
    privnode_start=count
    for priv in rows_priv:
        priv_set.add("%s_privileges" %priv[0].encode(CODEC))
    for i in priv_set:
        G['dict'+str(count)]={}
        temp['name']=filter(str.isalpha, i)
        temp['pid']=filter(str.isdigit, i)
        temp['count']=count
        temp['group']=m
        G['dict'+str(count)]=temp.copy()
        nodes.append(G['dict'+str(count)])
        count_dict[count]=filter(str.isdigit, i)
        count=count+1
    privnode_end=count-1
    m=m+1
    priv_start=count
    for priv in rows_priv:
        if priv[0]!="":
            G['dict'+str(count)]={}
            temp['name']=(priv[3].encode(CODEC),priv[7].encode(CODEC))
            temp['pid']=priv[0].encode(CODEC)
            temp['count']=count
            temp['group']=m
            G['dict'+str(count)]=temp.copy()
            nodes.append(G['dict'+str(count)])
            count_dict[count]=priv[0].encode(CODEC)
            count=count+1
    m=m+1
    priv_end=count-1

    '''
    #apihooks_APIHookSet
    cur_apih= conn.execute('select * from %s' % "apihooks_APIHookSet")
    rows_apih = cur_apih.fetchall()

    apih_set=set()
    apihnode_start=count
    for apih in rows_apih:
        apih_set.add("%s_apihook" %apih[3].encode(CODEC))
    for i in apih_set:
        G['dict'+str(count)]={}
        temp['name']=filter(str.isalpha, i)
        temp['pid']=filter(str.isdigit, i)
        temp['count']=count
        temp['group']=m
        G['dict'+str(count)]=temp.copy()
        nodes.append(G['dict'+str(count)])
        count_dict[count]=filter(str.isdigit, i)
        count=count+1
    apihnode_end=count-1
    m=m+1
    apih_start=count
    for apih in rows_apih:
        if apih[3]!="":
            G['dict'+str(count)]={}
            temp['name']=(apih[10].encode(CODEC),apih[8].encode(CODEC))
            temp['pid']=apih[3].encode(CODEC)
            temp['count']=count
            temp['group']=m
            G['dict'+str(count)]=temp.copy()
            nodes.append(G['dict'+str(count)])
            count_dict[count]=apih[3].encode(CODEC)
            count=count+1
    m=m+1
    apih_end=count-1


    #dlls_DLLSet
    cur_dlls= conn.execute('select * from %s' % "dlls_DLLSet")
    rows_dlls = cur_dlls.fetchall()

    dlls_set=set()
    dllsnode_start=count
    for dlls in rows_dlls:
        dlls_set.add("%s_dlls" %dlls[0].encode(CODEC))
    for i in dlls_set:
        G['dict'+str(count)]={}
        temp['name']=filter(str.isalpha, i)
        temp['pid']=filter(str.isdigit, i)
        temp['count']=count
        temp['group']=m
        G['dict'+str(count)]=temp.copy()
        nodes.append(G['dict'+str(count)])
        count_dict[count]=filter(str.isdigit, i)
        count=count+1
    dllsnode_end=count-1
    m=m+1
    dlls_start=count
    for dlls in rows_dlls:
        if dlls[0]!="":
            G['dict'+str(count)]={}
            temp['name']=dlls[9].encode(CODEC)
            temp['pid']=dlls[0].encode(CODEC)
            temp['count']=count
            temp['group']=m
            G['dict'+str(count)]=temp.copy()
            nodes.append(G['dict'+str(count)])
            count_dict[count]=dlls[0].encode(CODEC)
            count=count+1
    m=m+1
    dlls_end=count-1

    #mutants_MutantSet
    cur_muta= conn.execute('select * from %s' % "mutants_MutantSet")
    rows_muta = cur_muta.fetchall()

    muta_set=set()
    mutanode_start=count
    for muta in rows_muta:
        if muta[6]!="":       
            muta_set.add("%s_mutants" %muta[6].encode(CODEC))
    for i in muta_set:
        G['dict'+str(count)]={}
        temp['name']=filter(str.isalpha, i)
        temp['pid']=filter(str.isdigit, i)
        temp['count']=count
        temp['group']=m
        G['dict'+str(count)]=temp.copy()
        nodes.append(G['dict'+str(count)])
        count_dict[count]=filter(str.isdigit, i)
        count=count+1
    mutanode_end=count-1
    m=m+1
    muta_start=count
    for muta in rows_muta:
        if muta[6]!="":
            G['dict'+str(count)]={}
            temp['name']=muta[5].encode(CODEC)
            temp['pid']=muta[6].encode(CODEC)
            temp['count']=count
            temp['group']=m
            G['dict'+str(count)]=temp.copy()
            nodes.append(G['dict'+str(count)])
            count_dict[count]=dlls[0].encode(CODEC)
            count=count+1
    m=m+1
    muta_end=count-1
    '''

    links=[]
    link_start=count
    for i in range(proc_count+1):
        for j in range(proc_count+1):
            if count_dict[i]==ppid_dict[j]:
                G['dict'+str(count)]={}
                tem['target']="%s:%s"%(G['dict'+str(j)]['pid'],G['dict'+str(j)]['name'])
                tem['source']="%s:%s"%(G['dict'+str(i)]['pid'],G['dict'+str(i)]['name'])
                tem['source_group']=G['dict'+str(i)]['group']
                tem['target_group']=G['dict'+str(j)]['group']
                #tem['count']=count
                #tem["value"]=5
                G['dict'+str(count)]=tem.copy()
                links.append(G['dict'+str(count)])
                count=count+1

    #injections_InjectionSetca
    for i in range(injenode_start,injenode_end+1):
        for j in range(proc_count+1):
            if count_dict[i]==count_dict[j]:
                G['dict'+str(count)]={}
                tem['target']="%s:%s"%(G['dict'+str(i)]['pid'],G['dict'+str(i)]['name'])
                tem['source']="%s:%s"%(G['dict'+str(j)]['pid'],G['dict'+str(j)]['name'])
                tem['target_group']=G['dict'+str(i)]['group']
                tem['source_group']=G['dict'+str(j)]['group']
                tem['group']=G['dict'+str(i)]['group']
                #tem['count']=count
                #tem["value"]=1
                G['dict'+str(count)]=tem.copy()
                links.append(G['dict'+str(count)])
                count=count+1
    for i in range(inje_start,inje_end+1):
        for j in range(injenode_start,injenode_end+1):
            if count_dict[j]==count_dict[i]:
                G['dict'+str(count)]={}
                tem['target']="%s:%s"%(G['dict'+str(i)]['pid'],G['dict'+str(i)]['name'])
                tem['source']="%s:%s"%(G['dict'+str(j)]['pid'],G['dict'+str(j)]['name'])
                tem['target_group']=G['dict'+str(i)]['group']
                tem['source_group']=G['dict'+str(j)]['group']
                tem['group']=G['dict'+str(i)]['group']
                #tem['count']=count
                #tem["value"]=1
                G['dict'+str(count)]=tem.copy()
                links.append(G['dict'+str(count)])
                count=count+1    

    #connections_ConnectionSet
    for i in range(conenode_start,conenode_end+1):
        for j in range(proc_count+1):
            if count_dict[j]==count_dict[i]:
                G['dict'+str(count)]={}
                tem['target']="%s:%s"%(G['dict'+str(i)]['pid'],G['dict'+str(i)]['name'])
                tem['source']="%s:%s"%(G['dict'+str(j)]['pid'],G['dict'+str(j)]['name'])
                tem['target_group']=G['dict'+str(i)]['group']
                tem['source_group']=G['dict'+str(j)]['group']
                tem['group']=G['dict'+str(i)]['group']
                #tem['value']=1
                #tem['count']=count
                G['dict'+str(count)]=tem.copy()
                links.append(G['dict'+str(count)])
                count=count+1
    for i in range(cone_start,cone_end+1):
        for j in range(conenode_start,conenode_end+1):
            if count_dict[j]==count_dict[i]:
                G['dict'+str(count)]={}
                tem['target']="%s:%s"%(G['dict'+str(i)]['pid'],G['dict'+str(i)]['name'])
                tem['source']="%s:%s"%(G['dict'+str(j)]['pid'],G['dict'+str(j)]['name'])
                tem['target_group']=G['dict'+str(i)]['group']
                tem['source_group']=G['dict'+str(j)]['group']
                tem['group']=G['dict'+str(i)]['group']
                #tem['value']=1
                #tem['count']=count
                G['dict'+str(count)]=tem.copy()
                links.append(G['dict'+str(count)])
                count=count+1

    #privileges_PrivilegeSet
    for i in range(privnode_start,privnode_end+1):
        for j in range(proc_count+1):
            if count_dict[j]==count_dict[i]:
                G['dict'+str(count)]={}
                tem['target']="%s:%s"%(G['dict'+str(i)]['pid'],G['dict'+str(i)]['name'])
                tem['source']="%s:%s"%(G['dict'+str(j)]['pid'],G['dict'+str(j)]['name'])
                tem['target_group']=G['dict'+str(i)]['group']
                tem['source_group']=G['dict'+str(j)]['group']
                tem['group']=G['dict'+str(i)]['group']
                #tem['value']=1
                #tem['count']=count
                G['dict'+str(count)]=tem.copy()
                links.append(G['dict'+str(count)])
                count=count+1
    for i in range(priv_start,priv_end+1):
        for j in range(privnode_start,privnode_end+1):
            if count_dict[j]==count_dict[i]:
                G['dict'+str(count)]={}
                tem['target']="%s:%s"%(G['dict'+str(i)]['pid'],G['dict'+str(i)]['name'])
                tem['source']="%s:%s"%(G['dict'+str(j)]['pid'],G['dict'+str(j)]['name'])
                tem['target_group']=G['dict'+str(i)]['group']
                tem['source_group']=G['dict'+str(j)]['group']
                tem['group']=G['dict'+str(i)]['group']
                #tem['value']=1
                #tem['count']=count
                G['dict'+str(count)]=tem.copy()
                links.append(G['dict'+str(count)])
                count=count+1
    '''        
    #apihooks_APIHookSet
    for i in range(apihnode_start,apihnode_end+1):
        for j in range(proc_count+1):
            if count_dict[j]==count_dict[i]:
                G['dict'+str(count)]={}
                tem['target']="%s:%s"%(G['dict'+str(i)]['pid'],G['dict'+str(i)]['name'])
                tem['source']="%s:%s"%(G['dict'+str(j)]['pid'],G['dict'+str(j)]['name'])
                tem['target_group']=G['dict'+str(i)]['group']
                tem['source_group']=G['dict'+str(j)]['group']
                #tem['value']=1
                #tem['count']=count
                G['dict'+str(count)]=tem.copy()
                links.append(G['dict'+str(count)])
                count=count+1
    for i in range(apih_start,apih_end+1):
        for j in range(apihnode_start,apihnode_end+1):
            if count_dict[j]==count_dict[i]:
                G['dict'+str(count)]={}
                tem['target']="%s:%s"%(G['dict'+str(i)]['pid'],G['dict'+str(i)]['name'])
                tem['source']="%s:%s"%(G['dict'+str(j)]['pid'],G['dict'+str(j)]['name'])
                tem['target_group']=G['dict'+str(i)]['group']
                tem['source_group']=G['dict'+str(j)]['group']
                #tem['value']=1
                #tem['count']=count
                G['dict'+str(count)]=tem.copy()
                links.append(G['dict'+str(count)])
                count=count+1
           
    #dlls_DLLSet
    for i in range(dllsnode_start,dllsnode_end+1):
        for j in range(proc_count+1):
            if count_dict[j]==count_dict[i]:
                G['dict'+str(count)]={}
                tem['target']="%s:%s"%(G['dict'+str(i)]['pid'],G['dict'+str(i)]['name'])
                tem['source']="%s:%s"%(G['dict'+str(j)]['pid'],G['dict'+str(j)]['name'])
                tem['target_group']=G['dict'+str(i)]['group']
                tem['source_group']=G['dict'+str(j)]['group']
                #tem['value']=1
                #tem['count']=count
                G['dict'+str(count)]=tem.copy()
                links.append(G['dict'+str(count)])
                count=count+1
    for i in range(dlls_start,dlls_end+1):
        for j in range(dllsnode_start,dllsnode_end+1):
            if count_dict[j]==count_dict[i]:
                G['dict'+str(count)]={}
                tem['target']="%s:%s"%(G['dict'+str(i)]['pid'],G['dict'+str(i)]['name'])
                tem['source']="%s:%s"%(G['dict'+str(j)]['pid'],G['dict'+str(j)]['name'])
                tem['target_group']=G['dict'+str(i)]['group']
                tem['source_group']=G['dict'+str(j)]['group']
                #tem['value']=1
                #tem['count']=count
                G['dict'+str(count)]=tem.copy()
                links.append(G['dict'+str(count)])
                count=count+1

    #mutants_MutantSet
    for i in range(mutanode_start,mutanode_end+1):
        for j in range(proc_count+1):
            if count_dict[j]==count_dict[i]:
                G['dict'+str(count)]={}
                tem['target']="%s:%s"%(G['dict'+str(i)]['pid'],G['dict'+str(i)]['name'])
                tem['source']="%s:%s"%(G['dict'+str(j)]['pid'],G['dict'+str(j)]['name'])
                tem['target_group']=G['dict'+str(i)]['group']
                tem['source_group']=G['dict'+str(j)]['group']
                #tem['value']=1
                #tem['count']=count
                G['dict'+str(count)]=tem.copy()
                links.append(G['dict'+str(count)])
                count=count+1
    for i in range(muta_start,muta_end+1):
        for j in range(mutanode_start,mutanode_end+1):
            if count_dict[j]==count_dict[i]:
                G['dict'+str(count)]={}
                tem['target']="%s:%s"%(G['dict'+str(i)]['pid'],G['dict'+str(i)]['name'])
                tem['source']="%s:%s"%(G['dict'+str(j)]['pid'],G['dict'+str(j)]['name'])
                tem['target_group']=G['dict'+str(i)]['group']
                tem['source_group']=G['dict'+str(j)]['group']
                #tem['value']=1
                #tem['count']=count
                G['dict'+str(count)]=tem.copy()
                links.append(G['dict'+str(count)])
                count=count+1
    '''
    
    graph={'links':links}
    f.write(json.dumps(graph))
    f.close()
