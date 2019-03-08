import libdamm.memory_object as memobj


def getPluginObject(vol):
    return VADSet(vol)


def getFields():
    return VAD().get_field_keys()

class VADSet(memobj.MemObjectSet):
    '''
    Parses VAD info from Windows memory dumps.
    '''
    def __init__(self, vol=None):
        memobj.MemObjectSet.__init__(self, vol)


    def get_alloc(self, addr_space):
        '''
        Call volatility vadinfo plugin
        '''
        import volatility.plugins.vadinfo as vadinfo
        
        for task in vadinfo.VADInfo(self.vol.config).calculate():
            for vad in task.VadRoot.traverse():
                if vad != None:    
                    #Init vad control and ext variables 
                    controlAreaAddr = 0
                    segmentAddr = 0
                    numberOfSectionReferences = -1
                    numberOfPfnReferences = -1
                    numberOfMappedViews = -1
                    numberOfUserReferences = -1
                    controlFlags = ""
                    fileObjectAddr = 0
                    fileNameWithDevice = ""
                    firstPrototypePteAddr = 0
                    lastContiguousPteAddr = 0
                    flags2 = ""
                    vadType = ""
                    
                    protection = PROTECT_FLAGS.get(vad.VadFlags.Protection.v(), hex(vad.VadFlags.Protection))

                    # translate the vad type if its available (> XP)
                    if hasattr(vad.VadFlags, "VadType"):
                        vadType = MI_VAD_TYPE.get(vad.VadFlags.VadType.v(), hex(vad.VadFlags.VadType))

                    try:
                        control_area = vad.ControlArea
                        # even if the ControlArea is not NULL, it is only meaningful 
                        # for shared (non private) memory sections. 
                        if vad.VadFlags.PrivateMemory != 1 and control_area:                
                            if control_area:        
                                controlAreaAddr = control_area.dereference().obj_offset
                                segmentAddr = control_area.Segment
                                numberOfSectionReferences = control_area.NumberOfSectionReferences
                                numberOfPfnReferences = control_area.NumberOfPfnReferences
                                numberOfMappedViews = control_area.NumberOfMappedViews
                                numberOfUserReferences = control_area.NumberOfUserReferences
                                controlFlags = control_area.u.Flags 
                                file_object = vad.FileObject

                                if file_object:
                                    fileObjectAddr = file_object.obj_offset
                                    fileNameWithDevice = file_object.file_name_with_device()
                    except AttributeError:
                        pass
                    try:
                        firstPrototypePteAddr = vad.FirstPrototypePte
                        lastContiguousPteAddr = vad.LastContiguousPte
                        flags2 = str(vad.u2.VadFlags2)
                    except AttributeError:
                        pass
                    
                    yield VAD(task, vad, protection, vadType, controlAreaAddr, segmentAddr, numberOfSectionReferences, numberOfPfnReferences, numberOfMappedViews, numberOfUserReferences, controlFlags, fileObjectAddr, fileNameWithDevice, firstPrototypePteAddr, lastContiguousPteAddr, flags2)

    def get_child(self):
        return VAD()
    

    def get_unique_id(self, vad):
        '''
        @return: the default unique id for VADs memobjs
        '''
        return None


class VAD(memobj.MemObject):

    def __init__(self, task=None, vad=None):
        memobj.MemObject.__init__(self, offset)

        del(self.fields['offset'])

        self.fields["pid"] = str(task.UniqueProcessId) if task else ''

        self.fields["vad"] = str(vad.obj_offset) if task else ''
        self.fields["start"] = str(vad.Start) if task else ''
        self.fields["end"] = str(vad.End) if task else ''
        self.fields["VadTag"] = str(vad.Tag) if task else ''
        self.fields["flags"] = str(vad.VadFlags) if task else ''

        self.fields["protection"] = str(protection) if task else ''
        self.fields["VadType"] = str(vadType) if task else ''
        self.fields["ControlArea"] = str(controlAreaAddr) if task else ''
        self.fields["segment"] = str(segmentAddr) if task else ''
        self.fields["NumberOfSectionReferences"] = str(numberOfSectionReferences) if task else ''
        self.fields["NumberOfPfnReferences"] = str(numberOfPfnReferences) if task else ''
        self.fields["NumberOfMappedViews"] = str(numberOfMappedViews) if task else ''
        self.fields["NumberOfUserReferences"] = str(numberOfUserReferences) if task else ''
        self.fields["ControlFlags"] = str(controlFlags) if task else ''
        self.fields["FileObject"] = str(fileObjectAddr) if task else ''
        self.fields["FileName"] = str(fileNameWithDevice) if task else ''
        self.fields["FirstprototypePTE"] = str(firstPrototypePteAddr) if task else ''
        self.fields["LastcontiguousPTE"] = str(lastContiguousPteAddr) if task else ''
        self.fields["Flags2"] = str(flags2) if task else ''
