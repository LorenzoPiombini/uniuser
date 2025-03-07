#include <stdio.h>
#include <stdlib.h>
#include "uniuser.h"

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
		switch(ret) {
		case EMAX_U:  
			fprintf(stderr,"exeed the maximum user number.\n");
			break;
		case EALRDY_U: 
			fprintf(stderr,"user already exist.\n");
		        break;
		case ESGID: 
			fprintf(stderr,"SUB_GID_MAX overflowed.\n");
			break;
		case ESUID: 
			fprintf(stderr,"SUB_UID_MAX overflowed.\n");
			break;
		case ECHAR: 
			fprintf(stderr,"passowrd contain KILL or ERASE system char.\n");
			break;
		default:
			break;
		}
		fprintf(stderr,"%s: adding user failed!\n",Prog);
		return EXIT_FAILURE;
	}

	fprintf(stdout,"%s: user %s, added.\n",Prog,username);
	ret = 0;
	if((ret = del_user(username,DEL_SAFE)) != 0){
		switch(ret){
		case ENONE_U: 
			fprintf(stderr,"user does not exist.\n");
			break;
		default:
			break;
		}
		fprintf(stdout,"%s: del_user() failed.\n",Prog);
		return EXIT_FAILURE;
	}else{
		fprintf(stdout,"user %s, deleted.\n",username);
	}

	ret = 0;
	char *group_name = "isThisANEWnewGroup?";
	if((ret = create_group(group_name)) != 0){
		switch(ret) {
		case EALRDY_G: 
			fprintf(stderr,"group already exist\n");
			break;
		default:
			break;
		}
	}else {
		fprintf(stderr,"group added!\n");
	}

	ret = 0;
	if((ret = edit_group_user(username,group_name,DEL_GU)) != 0){
		switch(ret) {
		case ENONE_U:
			fprintf(stderr,"user does not exist.\n");
			break;
		case ERR_GU:
			fprintf(stderr,"DEL_GU failed.\n");
			break;
		case ENONE_GU:
			fprintf(stderr,"%s user %s not assaign to group %s.\n",Prog,username,group_name);
			break;
		case ENONE_G:
			fprintf(stderr,"%s: group %s does not exist.\n",Prog,group_name);
			break;
		default:
			break;
		}
	} else {
		printf("group deleted from user!");
	}

	return EXIT_SUCCESS;
}
