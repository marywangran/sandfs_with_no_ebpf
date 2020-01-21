import os
import socket
import struct

NETLINK_FSHOOK = 31

SANDFS_LOOKUP = 0
SANDFS_OPEN = 1
SANDFS_CLOSE = 2
SANDFS_READ = 3
SANDFS_WRITE = 4

# TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO

sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_FSHOOK)
sock.bind((os.getpid(), RTMGRP_LINK))

name = bytes('test1'.encode('utf-8'))
opt = 'A'
hooknum = SANDFS_READ
uid = 1000
path = bytes('N/A'.encode('utf-8'))
pos = -1
count = 10
buf = bytes('N/A'.encode('utf-8'))

data = struct.pack("@32sBII32sII32s", name, opt, hooknum, uid, path, pos, count, buf);
sock.sendto(data, (0, 0))

