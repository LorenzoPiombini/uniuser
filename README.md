# small user library for linux OS

this small library will give you the function add_user(char \*username, char \*password)
so you can add user programmatically in a C program without exposing the shell, and avoiding 
dangerous system call like system() or running command with popen() or the exec family functions.

## Get started

to use the library you have to clone this repo:

```plaintext
$ git clone https://github.com/LorenzoPiombini/libuser.git
```

then change into the cloned directory, and execute the configure script and the make build rule:

```plaintext
$ cd libuser
libuser/$ ./configure
libuser/$ sudo make build
```

## Use it in your code
now you have a small program to test this library called user_manager 
and the library is installed on your machine, so you can just use this in your C
projects:

```c
#include "user_create.h"

int main(void)
{
    /*your code*/
    
    if(add_user(username,password) < 1000 ) {
        /*handle error*/
    }

    /*your code*/
    return 0;
}
```

## Test the behaviour
you can use the small program as a test tool to see the program behaviour, it works similar to an
utility program, try this in your terminal, you have to have root privilegies:

```plain text
libuser/$ sudo ./user_manager Lorenzo Piombini
```
write here for bugs: lorenzopiombini3@gmail.com

