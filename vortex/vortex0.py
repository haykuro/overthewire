#!/usr/bin/env python

import socket

s = socket(AF_INET, SOCK_STREAM)
s.connect(("vortex.labs.overthewire.org" , 5842))

sum = 0;
#print ' '.join(["%02X"%ord(x) for x in s.recv(32)])

for i in range(4):
    data = s.recv(4)
    sum += unpack("<I", data)[0]

s.send(pack("<I",(sum & 0xFFFFFFFF)))
print s.recv(1024)
s.close ()
