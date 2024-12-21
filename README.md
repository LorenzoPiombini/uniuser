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

now you have a small program to test this library called user_manager 

