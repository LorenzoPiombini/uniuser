#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "uniuser.h"

#define MAX_LENGTH 600

int main(int argc, char** argv)
{
	char Prog[] = "userctl";
	if(argc < 2) {
		fprintf(stderr,"Usage: ./%s [username] \n\
				Usage: ./%s -OPTIONS\n",Prog,Prog);
		return -1;
	}

	int ret = 0;
	int opt = 0;
	unsigned char operation = 0;
	char username[MAX_LENGTH];
	char password[MAX_LENGTH];
	char full_name[MAX_LENGTH];
	char group_name[MAX_LENGTH];
	memset(username,0,MAX_LENGTH);
	memset(password,0,MAX_LENGTH);
	memset(full_name,0,MAX_LENGTH);
	memset(group_name,0,MAX_LENGTH);

	
	while((opt = getopt(argc,argv,"u:dg:p:e")) != -1){
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
			operation = operation | EDIT_GROUP_USER;
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
			fprintf(stderr,"(%s): user '%s' removed from group '%s'.\n",Prog,username,group_name);
			break;
		}
		break;
	default:
		fprintf(stderr,"(%s): invalid options or operation not allowed.\n",Prog);
		return -1;
	}
		
	return 0;
}
