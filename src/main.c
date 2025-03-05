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
                "Usage: ./%s [username] [password]\n",
                Prog);
        return EXIT_FAILURE;
    }

    char* username = argv[1];
    char* password = argv[2];

	int ret = add_user(username,password);
	if(ret < 1000) {
		fprintf(stderr,
                "%s: adding user failed!\n",
                Prog);
		return EXIT_FAILURE;
	}

	fprintf(stdout,"user %s, added.\n",username);

	if(del_user(username) == -1){
		fprintf(stdout,"del_user() failed.\n");
		return EXIT_FAILURE;
	}

	if(create_group("isThisAGroup?") == -1){
		fprintf(stderr,"can't add group.\n");
	}else {
		fprintf(stderr,"group added!\n");
	}

	if(add_group_to_user("Kings","isThisAGroup?") == -1){
		printf("add user to group failed.\n");
	} else {
		printf("group added to user!");
	}
	fprintf(stdout,"user %s, deleted.\n",username);
	return EXIT_SUCCESS;
}
