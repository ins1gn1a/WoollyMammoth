# WoollyMammoth

## Features
* Basic network service fuzzer
* EIP offset pattern creator
* Offset pattern detector
* Vanilla EIP overwrite exploiter
* Shellcode carver (egghunters, larger payloads, anything!)

## Installation
```
git clone https://github.com/ins1gn1a/WoollyMammoth
cd WoollyMammoth
pip3 install -r requirements.txt
```

## Overview

```bash
woollymammoth.py --help
usage: woollymammoth.py [-h] {fuzz,offset,badchars,eip,exploit,carve} ...

Woolly Mammoth Fuzzing and Exploitation Toolkit

positional arguments:
  {fuzz,offset,badchars,eip,exploit,carve}
    fuzz                Socket-based fuzzer that allows command prefix
                        (optional)
    offset              Sending unique string pattern to identify EIP offset
                        in a debugger.
    badchars            Toolset to help identify bad character usage in target
                        applications.
    eip                 Enter the offset pattern hex string to identify the
                        offset value.
    exploit             Create buffer-overflow exploit on the command line
                        with optional prefix.
    carve               Stack manipulation carving (egghunters, shellcode,
                        etc)

optional arguments:
  -h, --help            show this help message and exit

```

## Fuzzing
```bash
./woollymammoth.py fuzz -h
usage: woollymammoth.py fuzz [-h] --target TARGET --port PORT
                             [--prefix PREFIX]

optional arguments:
  -h, --help            show this help message and exit
  --prefix PREFIX       (Optional) Enter the prefix for the command.

Required Arguments:
  --target TARGET, -t TARGET
                        Enter the target host IP address.
  --port PORT, -p PORT  Enter the target port number.
```

## Offset
```bash
./woollymammoth.py offset -h
usage: woollymammoth.py offset [-h] --target TARGET --port PORT
                               [--prefix PREFIX]

optional arguments:
  -h, --help            show this help message and exit
  --prefix PREFIX       (Optional) Enter the prefix for the command.

Required Arguments:
  --target TARGET, -t TARGET
                        Enter the target host IP address.
  --port PORT, -p PORT  Enter the target port number.
```
## Bad Chars
```bash
woollymammoth.py badchars --help
usage: woollymammoth.py badchars [-h] --target TARGET --port PORT --buffer
                                 BUFFER [--offset OFFSET] [--prefix PREFIX]
                                 [--alpha] [--non-alpha]

optional arguments:
  -h, --help            show this help message and exit
  --offset OFFSET, -o OFFSET
                        Specify the buffer offset to prefix 'A' characters
                        before the bad characters (if not specified then bad
                        chars will be sent at the start of the payload)
  --prefix PREFIX       (Optional) Enter the prefix for the command.
  --alpha, -a           Only send alpha-characters
  --non-alpha, -n       Only send non-alpha characters

Required Arguments:
  --target TARGET, -t TARGET
                        Enter the target host IP address.
  --port PORT, -p PORT  Enter the target port number.
  --buffer BUFFER, -b BUFFER
                        Specify the buffer size
```

## EIP
```bash
./woollymammoth.py eip -h
usage: woollymammoth.py eip [-h] --eip EIP

optional arguments:
  -h, --help         show this help message and exit

Required Arguments:
  --eip EIP, -e EIP  Enter the EIP value to identify offset code.
```

## Exploit
```bash
./woollymammoth.py exploit -h
usage: woollymammoth.py exploit [-h] --target TARGET --port PORT --eip EIP
                                --offset OFFSET --shellcode SHELLCODE
                                [--prefix PREFIX] [--nops NOPS]

optional arguments:
  -h, --help            show this help message and exit
  --prefix PREFIX       (Optional) Enter the prefix for the command.
  --nops NOPS, -n NOPS  Enter the number of NOPs to send as an integer
                        (default: 10).

Required Arguments:
  --target TARGET, -t TARGET
                        Enter the target host IP address.
  --port PORT, -p PORT  Enter the target port number.
  --eip EIP, -e EIP     Enter the EIP JMP/PUSH;RET address as assembly
                        shellcode.
  --offset OFFSET, -o OFFSET
                        Enter the EIP offset value as an integer.
  --shellcode SHELLCODE, -s SHELLCODE
                        Enter the shellcode for the exploit.
```

## Carve
```bash
./woollymammoth.py carve -h
usage: woollymammoth.py carve [-h] --shellcode EGGHUNTER [--esp CURR_ESP]
                              [--dest-esp DEST_ESP]

optional arguments:
  -h, --help            show this help message and exit
  --esp CURR_ESP, -e CURR_ESP
                        Enter the ESP value at the start of the carved
                        shellcode
  --dest-esp DEST_ESP, -d DEST_ESP
                        Enter the address that should contain the carved
                        shellcode

Required Arguments:
  --shellcode EGGHUNTER, -s EGGHUNTER
                        Enter the shellcode to be converted (e.g. an
                        egghunter)
```
