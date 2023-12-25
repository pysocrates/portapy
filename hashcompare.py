# this script will hash a file and compare it to the verfied hash

import hashlib
import os
import sys

# get the file name from the command line
filename = sys.argv[1]

# create a new sha256 hash object
hash = hashlib.sha256()

# open the file for reading in binary mode
with open(filename, 'rb') as f:
    # read the contents of the file in chunks
    while True:
        # read 4096 bytes at a time
        data = f.read(4096)
        # if the data is empty, we have reached the end of the file
        if not data:
            break
        # hash the data
        hash.update(data)

# print the hex representation of the hash
print(hash.hexdigest())