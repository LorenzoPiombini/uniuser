<p>
  <img src="./logo.png" width="200">
</p>

# Uniuser A Small User Management Library for Linux

`uniuser` is a lightweight C library designed to programmatically manage users on a Linux operating system. It provides a simple function, `add_user(char *username, char *password)`,  
allowing you to create users securely without relying on shell exposure or risky system calls like `system()`, `popen()`, or the `exec` family.

## Features
- Add users programmatically with `add_user()`.
- Avoids unsafe shell interactions for better security.
- Includes additional utilities like `del_user()`, `create_group()`, and `edit_group_user()` (see [main.c] for examples).

[main.c]: src/main.c 
- Comes with a test program, `user_manager`, to demonstrate functionality.


## API exposed endpoint

```c
int crypt_pswd(char *paswd, char **hash);
int add_user(char *username, char *paswd);
int login(char *username, char *passwd);
int get_user_info(char *username, char **home_pth, int *uid);
int del_user(char *username, int mod);
int create_group(char* group_name);
int del_group(char *group_name);
int edit_group_user(char *username, char *group_name, int mod);
int paswd_chk(char *passwrd,int rules);
```

## Prerequisites
- A Linux-based operating system.
- Root privileges (`sudo`) for building and testing.
- GCC and standard C development tools (`make`, `git`, etc.).

## Getting Started

### Clone the Repository
To get started, clone the repository from GitHub:

```bash
$ git clone https://github.com/LorenzoPiombini/uniuser.git
```


##Build and Install

Navigate to the cloned directory and run the following commands to configure and build the library:

```bash
$ cd uniuser
$ ./configure
$ sudo make build
```

This will compile the library and install it on your system, along with a test program called `user_manager`.

## Using the Library in Your Code

Once installed, you can include the library in your C projects. Below is a basic example:

```c    
#include "uniuser.h"

int main(void) {
    char *username = "testuser";
    char *password = "securepassword";

    if (add_user(username, password) < 1000) {
        fprintf(stderr, "Error: Failed to add user '%s'\n", username);
        return 1;
    }

    printf("User '%s' added successfully!\n", username);
    return 0;
}
```

## Return Values

`add_user()` returns a value ≥ 1000 on success (UID).

Values < 1000 indicate an error.

## Security

the library comes with builtin checks for the password, by default the password provided won't be checked  
against any of this criteria, you can use the `paswd_chk()` like this: 

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
    - 8 charatter long
    - one capital letter
    - one special charatter(like @)
    - contain a number

the function checks also if you have the password contains kill or erase chars  
you can turn off this security criteria by passing to the `paswd_chk()` endpoint the parameter RULE_OFF  
this way the program will check only for kill char `^U` or erase char `^?` which they might create problems if you
decide to echo passwords, or in some embended systems.  

