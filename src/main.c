#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <pwd.h>
#include <errno.h>
#include "user_create.h"

int main(int arg, char** argv)
{
    char Prog[] = "user_manager";
    if(arg < 3 || arg > 3) {
        fprintf(stderr,
                "Usage: ./%s [username] [password]",
                Prog);
        return EXIT_FAILURE;
    }

    char* username = argv[1];
    char* password = argv[2];

	int ret = add_user(username,password);
	if(ret < 1001) {
		fprintf(stderr,
                "%s: adding user failed!\n",
                Prog);
		return EXIT_FAILURE;
	}

	fprintf(stdin,"user %s, added.\n",username);
	return EXIT_SUCCESS;
}
