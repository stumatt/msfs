from fuse import FUSE, FuseOSError, Operations

class MixSliceFS(Operations):
    def __init__(self, root, mountpoint, masterpassword):

FUSE(MixSliceFS(root,mountpoint,masterpassword), mountpoint, nothreads=True, foreground=True) 