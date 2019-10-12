from Passthrough import Passthrough
import os
import tempfile
import subprocess

class tests(Passthrough):
    def __init__(self,root):
        super().__init__(root)


fs = tests("/")
temporary = tempfile.NamedTemporaryFile(delete=False)
data = subprocess.run(["mixslice","decrypt","/mnt/MP/cavia.txt.enc"])
print(temporary.name)
temporary.close()



#tmp = tempfile.SpooledTemporaryFile(max_size=0, mode="w+b", dir="/mnt/MP")
#tmp.write(b"HEllo")