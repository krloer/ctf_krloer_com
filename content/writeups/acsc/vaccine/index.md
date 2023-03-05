---
title: "Vaccine Ret2Libc"
date: 2023-03-05T02:53:20-08:00
tags: ["pwn", "scanf", "overflow"]
---

### Ret2libc with unknown libc
#### ACSC Pwn Vaccine challenge

Showing how a vulnerable call to scanf can be used to overflow the stack.
 <!--more-->

This was the first pwn challenge of the Asia Cyber Security Challenge. The challenge files provided were a dockerfile, some server scripts and the ELF executable.

{{%attachments title="Related files" /%}}

When running the executable it asks us for a vaccine and rejects our response.
![running the elf](./images/first.png "running the elf")

The next step is to open it in ghidra. The only intersting function is main, and after renaming some variables it looks like this:
```c
undefined8 main(void)

{
  int check;
  size_t input_length;
  ulong iterator;
  char secret [112];
  char input [112];
  char rna [104];
  FILE *fd_secret;
  FILE *fd_rna;
  int i;

  fd_rna = fopen("RNA.txt","r");
  fgets(rna,100,fd_rna);
  printf("Give me vaccine: ");
  fflush(stdout);
  __isoc99_scanf(&DAT_00402024,input);
  i = 0;
  while( true ) {
    iterator = (ulong)i;
    input_length = strlen(input);
    if (input_length <= iterator) {
      check = strcmp(rna,input);
      if (check == 0) {
        puts("Congrats! You give the correct vaccine!");
        fd_secret = fopen("secret.txt","r");
        fgets(secret,100,fd_secret);
        printf("Here is your reward: %s\n",secret);
        return 0;
      }
      puts("Oops.. Try again later");
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    if ((((input[i] != 'A') && (input[i] != 'C')) && (input[i] != 'G')) && (input[i] != 'T')) break;
    i = i + 1;
  }
  puts("Only DNA codes allowed!");
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```
