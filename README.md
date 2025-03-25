<p>
  <img src="./logo.png" width="200">
</p>

# Uniuser A Small User Management Library for Linux

`uniuser` is a lightweight C library designed to programmatically manage users on a Linux operating system. It provides a simple function, `add_user(char *username, char *password, char *gecos)`,  
allowing you to create users securely without relying on shell exposure or risky system calls like `system()`, `popen()`, or the `exec` family.

## Features
- Add users programmatically with `add_user()`.
- Avoids unsafe shell interactions for better security.
- Includes additional utilities like `del_user()`, `create_group()`, and `edit_group_user()` (see [main.c] for examples).

[main.c]: src/main.c 

the library provides a command-line tool program `userctl` *(as user control)*, to demonstrate functionality.


## API endpoint

```c
int crypt_pswd(char *paswd, char **hash, char* salt);
int add_user(char *username, char *paswd, char *gecos);
int edit_user(char *username, int *uid, int element_to_change,int n_elem, ...);
int login(char *username, char *passwd, int mod);
int get_user_info(char *username, struct user_info *ui);
int del_user(char *username, int mod);
int create_group(char* group_name);
int del_group(char *group_name);
int edit_group_user(char *username, char *group_name, int mod);
int paswd_chk(char *passwrd,int rules);
int list_group(char *username, char **list);
```
---

## Prerequisites
- A Linux-based operating system.
- Root privileges (`sudo`) for building and testing.
- GCC and standard C development tools (`make`, `git`, etc.).
- lcrypt

## Getting Started

### Clone the Repository
To get started, clone the repository from GitHub:

```bash
$ git clone https://github.com/LorenzoPiombini/uniuser.git
```


## Build and Install

Navigate to the cloned directory and run the following commands to configure and build the library:

```bash
$ cd uniuser
$ ./configure
$ sudo make build
```

This will compile the library and install it on your system, along with a test program called `test`.
the small routine will be located inside of uniuser direcotry. `./test` will behave in a similar fashion as `useradd` does.   
You can use it to test some of the library feature, for example, you can run 

```bash
$ sudo ./test -u User67 -p pass67
```

this will create an user called User67 with the password pass67, if you want to create a new group you
simply run :

```bash
$ sudo ./test -g aNewGroup 
```

if you want to assign this group to an user, you can achive that by doing:

```bash
$ sudo ./test -eg aNewGroup -u User67
```

if you want to remove this user from the group:

```bash
$ sudo ./test -edg aNewGroup -u User67 
```

you got the idea, keep in mind that `sudo make build` is the Makefile rule taht I used to test this code on my machine.
During testing I often use the flag -fsanitize=address to compile the objects.   
That is because sometimes is hard to catch certain type of memory leaks with other tools, so in other words,  
the binary is compiled with the asan library adding quite an overhead to the program and the uniuser libray that you might want to use in your programs.  
For your production envirorment you might want to get rid of the asan lib, the Makefile already has a rule for you  
to build the user library and the utility program without this overhead, also if you are using other sharing library
and they don't have asan lib you will get compiler errors, so to solve all this, you have to use this rule:  

```bash
$ sudo make build_prod
```
this will install the library on your machine, and the test program will be called `userctl` istead of test, and it will be installed 
on your computer too, meaning you can run it from everywhere in your envirorment like `useradd`.  
Both `uniuser.so` and `userctl` will be asan lib free.
 
---
## FULL LIST COMMAND-LINE TOOL OPTIONS

# (if you build with `sudo make build_prod`, program will be called userctl)

```plain text
$ sudo ./test <username>  /*add user <username>*/
$ sudo ./test -eu <username> -p <password> /*add a password <password> to <username>*/
$ sudo ./test -du <username>  /*delete user  <username>*/
$ sudo ./test -g <groupname>  /*create a group called <groupname> */
$ sudo ./test -eg <groupname> -u <username>  /*assign <groupname> to user <username>*/



```

---


## Using the Library in Your Code

Once installed, you can include the library in your C projects. Below is a basic example:

```c    
#include "uniuser.h"

int main(void) {
    char *username = "testuser";
    char *password = "securepassword";

    if (add_user(username, password,NULL) < 1000) {
        fprintf(stderr, "Error: Failed to add user '%s'\n", username);
        return 1;
    }

    printf("User '%s' added successfully!\n", username);
    return 0;
}
```
---
## Return Values

These are the errors that endpoints can return:
```plain text
#define EMAX_G 9        /*exeed the maximum gid number*/
#define EMAX_U 10       /*exeed the maximum user number*/
#define EALRDY_U 11     /*user already exist*/
#define ESGID 12        /*SUB_GID_MAX overflowed */
#define ESUID 13        /*SUB_UID_MAX overflowed */
#define ECHAR 14        /* passowrd contain KILL or ERASE system char */
#define ENONE_U 15      /* user does not exist */
#define EALRDY_GU 16    /*group already added to user*/
#define ERR_GU 17       /*error in delating the group*/
#define ENONE_GU 18     /*the user is not assign to this group */
#define EALRDY_G 19     /*group already exist*/
#define ENONE_G 20      /*the group  does not exist*/
#define NO_IDs 21       /*no reusalble GIds*/
#define EROOT 22        /*try to change or delete ROOT*/
#define EGECOS 23       /*edit user  GECOS faield*/

```

all the fucntions might return a generic error -1,and a message will be display to the console.

`add_user()` returns a value ≥ 1000 on success (UID).
values < 1000 indicate an error wich will be one of the follwing:
- `EMAX_U`
- `EALRDY_U`
- `ESGID`
- `ESUID`


`del_user` returns 0 on success.
erros :
- `ENONE_U`
- `EROOT`

`del_group()` returns 0 on success.
erros :
- `ENONE_G`

`edit_group_user()` returns 0 on success.
erros :
- `ENONE_G`
- `ENONE_U`

`create_group()` returns 0 on success.
erros :
- `EALRDY_G`
- `EMAX_G`

## Security

the library comes with builtin checks for the password, by default the password provided won't be checked  
against any of this criteria, you can use the `pswd_chk()` like this: 

```c
	int p_chk = paswd_chk(paswd,RULE_ON);
	if(p_chk == 0 || p_chk == -1) {
		fprintf(stderr,"password does not meet security criteria.\n");
		return -1;	
	} else if (p_chk == ECHAR) {
		fprintf(stderr,"password contains invalid characters.\n");
		return -1;
	}

```

the code snipped checks for a password that must meet the following:   
- 8 character long
- one capital letter
- one special character (like @)
- contain a number

the function checks also if the password contains kill or erase chars  
you can turn off this security criteria by passing to the `paswd_chk()` endpoint the parameter RULE_OFF  
this way the program will check only for kill char `^U` or erase char `^?` which they might create problems if you
decide to echo passwords, or in some embedded systems.  


