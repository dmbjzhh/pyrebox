import libdamm.memory_object as memobj


def getPluginObject(vol):
    return VADSet(vol)


def getFields():
    return VAD().get_field_keys()

class VADSet(memobj.MemObjectSet):
    '''
    Parses VAD info from Windows memory dumps.
    '''
    @staticmethod
    def get_field_typedefs():
        defs = {}
        defs['pid']
