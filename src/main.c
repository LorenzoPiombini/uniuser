#include <stdio.h>
#include <stdlib.h>
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
	}else{
		fprintf(stdout,"user %s, deleted.\n",username);
	}

	if(create_group("isThisAGroup?") == -1){
		fprintf(stderr,"can't add group.\n");
	}else {
		fprintf(stderr,"group added!\n");
	}

	int err = 0;
	if((err = edit_group_user("Kings","isThisAGroup?",DEL_GU)) != 0){
		printf("add user to group failed with error %d.\n",err);
	} else {
		printf("group deleted from user!");
	}

	return EXIT_SUCCESS;
}
