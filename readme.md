# WoollyMammoth

## Installation
```
git clone https://github.com/ins1gn1a/WoollyMammoth
cd WoollyMammoth
pip3 install -r requirements.txt
```

## Overview

```
./woollymammoth.py -h
usage: woollymammoth.py [-h] {fuzz,offset,eip,exploit,carve} ...

Woolly Mammoth Socket Fuzzer

positional arguments:
  {fuzz,offset,eip,exploit,carve}
    fuzz                Socket-based fuzzer that allows command prefix
                        (optional)
    offset              Sending unique string pattern to identify EIP offset
                        in a debugger.
    eip                 Enter the offset pattern hex string to identify the
                        offset value.
    exploit             Create buffer-overflow exploit on the command line
                        with optional prefix.
    carve               Stack manipulation carving

optional arguments:
  -h, --help            show this help message and exit
```

## Fuzzing

```
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
```
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

## EIP
```
./woollymammoth.py eip -h
usage: woollymammoth.py eip [-h] --eip EIP

optional arguments:
  -h, --help         show this help message and exit

Required Arguments:
  --eip EIP, -e EIP  Enter the EIP value to identify offset code.
```

## Exploit
```
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
```
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
