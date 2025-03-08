#include <stdio.h>
#include <stdlib.h>
#include "uniuser.h"

int main(int arg, char** argv)
{
    char Prog[] = "user_manager";
    if(arg < 3 || arg > 4) {
        fprintf(stderr,
                "Usage: ./%s [username] [password] (full name)\nfull name is optional,\n",Prog);
        return EXIT_FAILURE;
    }

    char* username = argv[1];
    char* password = argv[2];
    char* full_name = NULL;

    if(arg == 4)
	    full_name = argv[3];

	if(login("test1","pass1",STD) == -1)
		printf("login failed\n");
	else
		printf("login succes\n");

	return 0;

	
	int ret = 0; 
	ret = add_user(username,password,full_name);
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
	


	char *test = "test1";
	char *testG = "thisIsAGroup";
	int mod = ADD_GU;
	ret = edit_group_user(test,testG,mod);
	if(ret != 0){
		switch(ret) {
		case ENONE_U:
			fprintf(stderr,"user does not exist.\n");
			break;
		case ERR_GU:
			fprintf(stderr,"DEL_GU failed.\n");
			break;
		case ENONE_GU:
			fprintf(stderr,"%s user %s not assaign to group %s.\n",Prog,test,testG);
			break;
		case ENONE_G:
			fprintf(stderr,"%s: group %s does not exist.\n",Prog,testG);
			break;
		default:
			break;
		}
	}
	
	test = "test2";
	testG = "thisIsAGroup";
	ret = edit_group_user(test,testG,mod);
	if(ret != 0){
		switch(ret) {
		case ENONE_U:
			fprintf(stderr,"user does not exist.\n");
			break;
		case ERR_GU:
			fprintf(stderr,"DEL_GU failed.\n");
			break;
		case ENONE_GU:
			fprintf(stderr,"%s user %s not assaign to group %s.\n",Prog,test,testG);
			break;
		case ENONE_G:
			fprintf(stderr,"%s: group %s does not exist.\n",Prog,testG);
			break;
		default:
			break;
		}

	}

	test = "test3";
	testG = "thisIsAGroup";
	ret = edit_group_user(test,testG,mod);
	if(ret != 0){
		switch(ret) {
		case ENONE_U:
			fprintf(stderr,"user does not exist.\n");
			break;
		case ERR_GU:
			fprintf(stderr,"DEL_GU failed.\n");
			break;
		case ENONE_GU:
			fprintf(stderr,"%s user %s not assaign to group %s.\n",Prog,test,testG);
			break;
		case ENONE_G:
			fprintf(stderr,"%s: group %s does not exist.\n",Prog,testG);
			break;
		default:
			break;
		}

	}

	return 0;
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

	if((ret = edit_group_user(username,group_name,ADD_GU)) != 0){
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
		printf("group added to user %s!\n",username);
	}

	char *list = NULL;
	if(list_group(username, &list) == -1 ){
		fprintf(stderr,"no groups for user %s\n",username);
	
	}

	fprintf(stdout,"group list for %s: %s\n",username,list);
	/*YOU HAVE TO FREE LIST*/
	free(list);

	/*GET USER INFO */
	/* if you need only the home path*/
	char *home_dir = NULL;
	if(get_user_info(username,&home_dir, NULL,NULL) == -1){
		fprintf(stderr,"%s: can't get info for user %s username",Prog,username);
	}

	fprintf(stdout,"user %s's home path %s.\n",username,home_dir);
	/*YOU HAVE TO FREE THE home_dir char* */
	free(home_dir);

	/*check if the user has admin privilege */
	int is_admin = 0;
	if(get_user_info(username,NULL, NULL,&is_admin) == -1){
		fprintf(stderr,"%s: can't get info for user %s username",Prog,username);
	}
	
	char *admin = is_admin ? "has admin privileged" : " has not admin priviledge";
	fprintf(stdout,"user %s %s.\n",username,admin);


	int uid = 0;
	if(get_user_info(username,NULL, &uid,NULL) == -1){
                fprintf(stderr,"%s: can't get info for user %s username",Prog,username);
        }                                                                                                          
        
	fprintf(stdout,"user %s's uid is %d.\n",username,uid);

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

	ret = 0;
	if((ret = del_group(group_name)) != 0){
		switch(ret){
		case ENONE_G:	
			fprintf(stderr,"%s: group %s does not exist.\n",Prog,group_name);
			break;
		default:
			fprintf(stderr,"%s: can't delete group %s.\n",Prog,group_name);
			break;
		}
	} else {
		fprintf(stdout,"Group %s deleted.\n",group_name);
	}
	return EXIT_SUCCESS;
}
