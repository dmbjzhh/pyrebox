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


    def get_all(self):
        '''
        Call volatility vadinfo plugin
        '''
        import volatility.plugins.vadinfo as vadinfo
        for pid, vad, start, end, VadTag, 


    def get_child(self):
        return VAD()
    

    def get_unique_id(self, vad):
        '''
        @return: the default unique id for VADs memobjs
        '''
        pass


class VAD(memobj.MemObject):

    def __init__(self, vad=None, offset=None):
        memobj.MemObject.__init__(self, offset)

        self.fields["pid"]
        self.fields["vad"]
        self.fields["start"]
        self.fields["end"]
        self.fields["VadTag"]
        self.fields["flags"]
        self.fields["protection"]
        self.fields["VadType"]
        self.fields["ControlArea"]
        self.fields["segment"]
        self.fields["NumberOfSectionReferences"]
        self.fields["NumberOfPfnReferences"]
        self.fields["NumberOfMappedViews"]
        self.fields["NumberOfUserReferences"]
        self.fields["ControlFlags"]
        self.fields["FileObject"]
        self.fields["FileName"]
        self.fields["FirstprototypePTE"]
        self.fields["LastcontiguousPTE"]
        self.fields["Flags2"]
