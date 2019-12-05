from fuse import FUSE, FuseOSError, Operations

class Passthrough(Operations):
    def __init__(self, root, mountpoint, mp):

FUSE(Passthrough(root,mountpoint,masterpassword), mountpoint, nothreads=True, foreground=True) 