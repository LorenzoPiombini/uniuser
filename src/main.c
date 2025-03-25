#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "uniuser.h"

#define MAX_LENGTH 600

int main(int argc, char** argv)
{
	char Prog[] = "userctl";
	if(argc < 2) {
		fprintf(stderr,"Usage: ./%s [username] \nUsage: ./%s -OPTIONS\n",Prog,Prog);
		return -1;
	}

	int ret = 0;
	int opt = 0;
	unsigned char operation = 0;
	char username[MAX_LENGTH] = {0};
	char password[MAX_LENGTH] = {0};
	char group_name[MAX_LENGTH]= {0};
	char changes[MAX_LENGTH] = {0};
	
	while((opt = getopt(argc,argv,"u:dg:p:eG:c:")) != -1){
		switch(opt){
		case 'u':
			operation = operation | USER;
			strncpy(username,optarg,strlen(optarg)+1);
			break;
		case 'd': 
			operation = operation | DEL;
			break;
		case 'g':
			operation = operation | GROUP;
			strncpy(group_name,optarg,strlen(optarg)+1);
			break;
		case 'p':
			operation = operation | PWD;
			strncpy(password,optarg,strlen(optarg)+1);	
			break;
	        case 'e':
			operation = operation | EDIT;
			break;
		case 'G':
			operation = operation | GECOS;
			strncpy(changes,optarg,strlen(optarg)+1);
			break;
		case 'c':
			strncpy(changes,optarg,strlen(optarg)+1);
			break;
		default:
			break;
		}	
	}
	
	
	if(optind == 1){
		strncpy(username,argv[1],strlen(argv[1])+1);
		ret = add_user(username,NULL,NULL);
		switch(ret) {
		case EMAX_U:  
			fprintf(stderr,"(%s): exceeded the maximum user number.\n\
					(%s): user '%s' not added.\n",Prog,Prog,username);
			return -1;
		case EALRDY_U: 
			fprintf(stderr,"(%s): user '%s' already exist.\n",Prog,username);
			return -1;
		case ESGID: 
			fprintf(stderr,"(%s): SUB_GID_MAX overflowed.\n",Prog);
			return -1;
		case ESUID: 
			fprintf(stderr,"(%s): SUB_UID_MAX overflowed.\n",Prog);
			return -1;
		case -1:
			fprintf(stderr,"(%s): adding user '%s' failed!\n",Prog,username);
			return -1;
		default:
			fprintf(stdout,"(%s): user '%s', added.\n",Prog,username);
			return 0;
		}
	}
	
	switch(operation){
	case DEL_USER:
		ret = del_user(username,DEL_SAFE);
		switch(ret){
		case ENONE_U: 
			fprintf(stderr,"(%s): user '%s' does not exist.\n",Prog,username);
			break;
		case EROOT: 
			fprintf(stderr,"(%s): user '%s' can't be deleted or changed.\n",Prog,username);
			break;
		case -1:
			fprintf(stdout,"(%s): can't delete user '%s'.\n",Prog,username);
			return -1;
		default:
			fprintf(stdout,"(%s): user '%s', deleted.\n",Prog, username);
			break;
		}
		break;
	case GROUP:
		ret = create_group(group_name);
		switch(ret) {
		case EALRDY_G: 
			fprintf(stderr,"(%s): group '%s' already exist\n",Prog,group_name);
			break;
		case -1:
			fprintf(stderr,"(%s): can't create group '%s'.\n",Prog,group_name);
			break;
		default:
			fprintf(stderr,"(%s): group '%s' created.\n",Prog,group_name);
			break;
		}
		break;
	case USER_AND_PSWD:
		ret = add_user(username,password,NULL);
		switch(ret) {
		case EMAX_U:  
			fprintf(stderr,"(%s): exceeded the maximum user number.\n\
					(%s): user '%s' not added.\n",Prog,Prog,username);
			return -1;
		case EALRDY_U: 
			fprintf(stderr,"(%s): user '%s' already exist.\n",Prog,username);
			break;
		case ESGID: 
			fprintf(stderr,"(%s): SUB_GID_MAX overflowed.\n",Prog);
			return -1;
		case ESUID: 
			fprintf(stderr,"(%s): SUB_UID_MAX overflowed.\n",Prog);
			return -1;
		case -1:	
			fprintf(stderr,"(%s): adding user '%s' failed.\n",Prog,username);
			return -1;
		default:
			fprintf(stdout,"(%s): user %s, added.\n",Prog,username);
			break;
		}
		break;
	case USER_AND_PSWD_AND_GECOS:
		ret = add_user(username,password,changes);
		switch(ret) {
		case EMAX_U:  
			fprintf(stderr,"(%s): exceeded the maximum user number.\n\
					(%s): user '%s' not added.\n",Prog,Prog,username);
			return -1;
		case EALRDY_U: 
			fprintf(stderr,"(%s): user '%s' already exist.\n",Prog,username);
			break;
		case ESGID: 
			fprintf(stderr,"(%s): SUB_GID_MAX overflowed.\n",Prog);
			return -1;
		case ESUID: 
			fprintf(stderr,"(%s): SUB_UID_MAX overflowed.\n",Prog);
			return -1;
		case -1:	
			fprintf(stderr,"(%s): adding user '%s' failed.\n",Prog,username);
			return -1;
		default:
			fprintf(stdout,"(%s): user %s, added.\n",Prog,username);
			break;
		}
		break;
	case USER_AND_GECOS:
		ret = add_user(username,NULL,changes);
		switch(ret) {
		case EMAX_U:  
			fprintf(stderr,"(%s): exceeded the maximum user number.\n\
					(%s): user '%s' not added.\n",Prog,Prog,username);
			return -1;
		case EALRDY_U: 
			fprintf(stderr,"(%s): user '%s' already exist.\n",Prog,username);
			break;
		case ESGID: 
			fprintf(stderr,"(%s): SUB_GID_MAX overflowed.\n",Prog);
			return -1;
		case ESUID: 
			fprintf(stderr,"(%s): SUB_UID_MAX overflowed.\n",Prog);
			return -1;
		case -1:	
			fprintf(stderr,"(%s): adding user '%s' failed.\n",Prog,username);
			return -1;
		default:
			fprintf(stdout,"(%s): user %s, added.\n",Prog,username);
			break;
		}
		break;
	case DEL_GROUP:
		ret = del_group(group_name);
		switch(ret){
		case ENONE_G:	
			fprintf(stderr,"(%s): group '%s' does not exist.\n",Prog,group_name);
			break;
		case -1:
			fprintf(stderr,"(%s): can't delete group '%s'.\n",Prog,group_name);
		default:
			fprintf(stdout,"(%s): group '%s' deleted.\n",Prog,group_name);
			break;
		}
		break;
	case ADD_GROUP_TO_USER:
		ret = edit_group_user(username,group_name,ADD_GU);
		switch(ret) {
			case ENONE_U:
				fprintf(stderr,"(%s): user '%s' does not exist.\n",Prog, username);
				break;
			case ENONE_G:
				fprintf(stderr,"(%s): group '%s' does not exist.\n",Prog,group_name);
				break;
			case -1:
				fprintf(stderr,"(%s): can't add user '%s' to group '%s'.\n",Prog,username,group_name);
				break;
			default:
				fprintf(stderr,"(%s): user '%s' added to group '%s'.\n",Prog,username,group_name);
				break;
		}
		break;
	case DEL_GROUP_FROM_USER :
		ret = edit_group_user(username,group_name,DEL_GU);
		switch(ret) {
		case ENONE_U:
			fprintf(stderr,"(%s): user '%s' does not exist.\n",Prog, username);
			break;
		case ERR_GU:
			fprintf(stderr,"(%s)can't remove user '%s' form group '%s'.\n",Prog,username,group_name);
			break;
		case ENONE_GU:
			fprintf(stderr,"(%s): user '%s' not assigned to group '%s'.\n",Prog,username,group_name);
			break;
		case ENONE_G:
			fprintf(stderr,"(%s): group '%s' does not exist.\n",Prog,group_name);
			break;
		case -1:
			fprintf(stderr,"(%s): can't remove user '%s' from group '%s'.\n",Prog,username,group_name);
			break;
		default:
			fprintf(stdout,"(%s): user '%s' removed from group '%s'.\n",Prog,username,group_name);
			break;
		}
		break;
	case EDIT_PASWD:
		ret = edit_user(username,NULL,operation,1,password);
		switch(ret){
		case -1:
			fprintf(stdout,"(%s): can't change password fpr user '%s'.\n",Prog,username);
			break;
		default:
			fprintf(stdout,"(%s): pasword changed for user '%s'.\n",Prog,username);
			break;
		}
		break;
	case EDIT_GECOS:
		if(changes[0] == '\0'){
			fprintf(stderr,"(%s): gecos parameter missing.\n",Prog);
			break;
		}

		ret = edit_user(username,NULL,operation,1,changes);
		switch(ret){
		case -1:
		case EGECOS:
			fprintf(stdout,"(%s): can't change gecos for user '%s'.\n",Prog,username);
			break;
		case ENONE_U:
			fprintf(stderr,"(%s): user '%s' does not exist.\n",Prog, username);
			break;
		default:
			fprintf(stdout,"(%s): gecos changed for user '%s'.\n",Prog,username);
			break;
		}
		break;
	case EDIT_USER:
		if(changes[0] == '\0'){
			fprintf(stderr,"(%s): new username missing.\n",Prog);
			break;
		}

		ret = edit_user(username,NULL,operation,1,changes);
		switch(ret){
		case -1:
		case EUSRNAME:
			fprintf(stdout,"(%s): can't change username for user '%s'.\n",Prog,username);
			break;
		case EUSRSAME:
			fprintf(stdout,"(%s): username is already '%s'.\n",Prog,changes);
			break;
		case ENONE_U:
			fprintf(stderr,"(%s): user '%s' does not exist.\n",Prog, username);
			break;
		default:
			fprintf(stdout,"(%s): username '%s' changed to '%s'.\n",Prog,username,changes);
			break;
		}
		break;


	default:
		fprintf(stderr,"(%s): invalid options or operation not allowed.\n",Prog);
		return -1;
	}
		
	return 0;
}
