# uniuser - A Small User Management Library for Linux

`libuser` is a lightweight C library designed to programmatically manage users on a Linux operating system. It provides a simple function, `add_user(char *username, char *password)`,  
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
```

## Prerequisites
- A Linux-based operating system.
- Root privileges (`sudo`) for building and testing.
- GCC and standard C development tools (`make`, `git`, etc.).

## Getting Started

### Clone the Repository
To get started, clone the repository from GitHub:

```bash
$ git clone https://github.com/LorenzoPiombini/libuser.git
```


##Build and Install

Navigate to the cloned directory and run the following commands to configure and build the library:

```bash
$ cd libuser
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


