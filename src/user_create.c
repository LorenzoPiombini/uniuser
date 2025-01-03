#include "config.h"

#if HAVE_STR_OP_H
#include "str_op.h"
#endif /* HAVE_STR_OP_H*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <pwd.h>
#include <crypt.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ctype.h>
#include <termios.h>
#include <dirent.h>
#include "user_create.h"
/*
 *  modify this files to create a new user 
 *	etc/group
	/etc/subgid
	/etc/subuid
	/etc/gshadow
	/etc/passwd
	/etc/shadow
	/etc/subuid
*/



/* local function prototype */
static int get_sys_param(struct sys_param *param);
static int last_UID();
static unsigned char user_already_exist(char *username);
static unsigned int gen_SUB_GID(int uid, struct sys_param *param);
static unsigned int gen_SUB_UID(int uid, struct sys_param *param);
static unsigned char gen_random_bytes(char *buffer,int length);
static int crypt_pswd(char *paswd, char **hash);
static int lock_file(char *file_name);
static int lock_files();
static int unlock_file(char *file_name);
static int unlock_files();
static int write_file(char *file_name, char *entry, size_t entry_size, char *username);
static int shdw_write(char *username, char *hash, struct sys_param *param);
static int psdw_write(char *username, int uid);
static int group_write(char *username, int uid);
static int gshdw_write(char *username);
static int subuid_write(char *username, unsigned int sub_uid, int count);
static int subgid_write(char *username, unsigned int sub_gid, int count);
static int clean_up_file(char *username, char* file_name);
static int cpy_skel(char *home_path, int home_path_length,int uid);
static int cpy_file(FILE *src, FILE *dest);
static int paswd_chk(char *passwrd);
static int get_linux_distro();
static int clean_home_dir(char *hm_path);
static int get_save_pswd(char *username, char* hash);

#if !HAVE_LIBSTROP
static size_t number_of_digit(int n);
#endif /*HAVE_LIBSTROP*/


/* default values if there's no SYS_PARAM file*/
static const int UID_MAX = 60000;
static const int SUB_UID_MIN = 100000;
static const unsigned int SUB_UID_MAX = 600100000;
static const int GID_MAX = 60000;
static const int SUB_GID_MIN = 100000;
static const unsigned int SUB_GID_MAX = 600100000;
static const int SUB_GID_COUNT = 65536;
static const int PASS_MAX_DAYS = 99999;
static const int PASS_MIN_DAYS = 0;
static const int PASS_WARN_AGE = 7;
static const char *ENCRYPT_METHOD = "SHA512";

/* constants */
static const char *hm = "/home";
static const char *bsh = "/bin/bash";

static const char randombytes[] = { 'c','&','d','"','o','6','@','^',
			'f','a','1','!','~','`','%','*',
			'k','l','o','p','6','7','(',')',
			'Z','x','c','O','{','[','+','0',
			':','\'','>','<','?','M','n','5',
			'U','H','v','b','L','X','+','-',
			'c','v','~','#','$','%','0','8',
			'v','c','j','K','G','h','S','P',};

int login(char *username, char *passwd)
{
        struct passwd *pw = getpwnam(username);
        if(!pw) {
                fprintf(stderr,"user does't exist");
                return -1;    
        }
        
        
	/*
         * if the user exist
         * encrtypt the password and compare it 
         * with the password in the database.
         * */
	char *hash = NULL;
	if(crypt_pswd(passwd,&hash) == -1) {
		fprintf(stderr,
				"paswd encryption failed. %s:%d.\n",
				__FILE__,__LINE__-1);
                return -1;
        } 
	
	/*
	 * get the passwd from SHADOW file,
	 * and compare it to the saved password
	 * */
	if(get_save_pswd(username,hash) == -1) {
                fprintf(stderr,"wrong password or username.\n");
                free(hash);
		return -1;
	}

        free(hash);
        return EXIT_SUCCESS;
}

static int get_save_pswd(char *username, char *hash)
{
	FILE *fp;

	do
	{
		fp = fopen(SHADOW,"r");
	}while(fp == NULL);
	
	int columns = 200;
	char line[columns];
	memset(line,0,columns);

	while(fgets(line,columns,fp)) {
		char *t = strtok(line,":");
		if(strlen(username) != strlen(t))
			continue;

		char *old_pswd = strtok(NULL,":");
		if(strncmp(old_pswd,hash,strlen(old_pswd)) == 0)
			return 0;

	}

	return -1;

}
int add_user(char *username, char *paswd)
{
	if(user_already_exist(username)) {
		printf("user already exist.\n");
		return EALRDY_U;	
	}

	int p_chk = paswd_chk(paswd);

	if(p_chk == 0 || p_chk == -1) {
		fprintf(stderr,"password does not meet security criteria.\n");
		return -1;	
	} else if (p_chk == ECHAR) {
		fprintf(stderr,"password contains invalid characters.\n");
		return -1;
	}

	int status = EXIT_SUCCESS;
	int err = -1;
	unsigned char lock = 0;
	/*
	 * this has to be here to avoid goto warning/error
	 * +2 (1 for '\0' 1 for '/')
	 * */
	size_t hm_l = strlen(username) + strlen(hm) +2;
	char hm_path[hm_l];
	memset(hm_path,0,hm_l);

	struct sys_param param = {0};
	int ret = get_sys_param(&param);
	if( ret == -1)
	{
		printf("get_sys_param() failed.\n");
		status =  err;
		goto clean_on_exit;
	}else if(ret == ENOENT) {
		/*set default value*/
		param.UID_MAX = UID_MAX;
		param.SUB_UID_MIN = SUB_UID_MIN;
		param.SUB_UID_MAX = SUB_UID_MAX;
		param.GID_MAX = GID_MAX;
		param.SUB_GID_MIN = SUB_GID_MIN;
		param.SUB_GID_MAX = SUB_GID_MAX;
		param.SUB_GID_COUNT = SUB_GID_COUNT;
		param.PASS_MAX_DAYS = PASS_MAX_DAYS;
		param.PASS_MIN_DAYS = PASS_MIN_DAYS;
		param.PASS_WARN_AGE = PASS_WARN_AGE;
		param.ENCRYPT_METHOD = strdup(ENCRYPT_METHOD);
		if(!param.ENCRYPT_METHOD) {
			printf("strdupfaild");
			status = err;
			goto clean_on_exit;
		}
	}

	int uid = last_UID();

	if(uid == param.UID_MAX) {
		status = EMAX_U;
		goto clean_on_exit;
	}
    	
	/* compute SUB_UID and SUB_GID */
	unsigned int sub_gid = gen_SUB_GID(uid,&param);
	if(sub_gid == 0 || sub_gid == -1) {
		fprintf(stderr,
				"gen_SUB_GID() failed, %s:%d.\n",
				__FILE__,__LINE__-2);
		status = err;
		goto clean_on_exit;
	} else if(sub_gid == ESGID) {
		printf("maximum nr of sub groubs id reached.\n");
		status = err;
		goto clean_on_exit;
	}	

	unsigned int sub_uid = gen_SUB_UID(uid,&param);
	if(sub_uid == 0 || sub_uid == -1) {
		fprintf(stderr,
				"gen_SUB_UID() failed, %s:%d.\n",
				__FILE__,__LINE__-2);
		status = err;
		goto clean_on_exit;
	}else if(sub_uid == ESUID) {
		printf("maximum nr of sub user id reached.\n");
		status = err;
		goto clean_on_exit;
	}
	
	/*encrtypt the password */
	char *hash = NULL;
	if(crypt_pswd(paswd,&hash) == -1) {
		fprintf(stderr,
				"paswd encryption failed. %s:%d.\n",
				__FILE__,__LINE__-1);
		status = EXIT_FAILURE;
		goto clean_on_exit;
	}

	/*
	 * write the data to the files to add the user
	 * @@@@@@@ ACQUIRE LOCKS TO BE SURE THIS PROGRAM IS THE ONLY ONE ADDING USERS!!!! @@@@ 
	 * */
    
    /* 
     * changing to root user, if the program is not run by root 
     * or with root privilegies the function will fail
     * */

	if(setuid(0) == -1) {
		status = err;
		free(hash);
		fprintf(stderr,"permission denied.\n");
		goto clean_on_exit;
	}

	
	if(lock_files() == -1) {
		/*cannot lock the file*/
		status = err;
		fprintf(stderr,"cannot acquire lock on users db files.\n");
		free(hash);
		goto clean_on_exit;
	}
	
	lock = 1;

	/* write to the files creating the user */		
	if(!shdw_write(username,hash,&param)) {
		status = err;
		printf("writing shadows files failed.\n");
		free(hash);
		goto clean_on_exit;
	}

	free(hash);
	
	uid++; /*incrementing the last user id by one to make the new user id */

    /*
     *  if one of this if test fails the program will clean the files 
     *  already written to avoid partial users data and to ensure
     *  data consistency
     * */
	if(!psdw_write(username,uid)) {
		fprintf(stderr,
				"psdw_write() failed, %s:%d.\n",
				__FILE__,__LINE__-3);
		status = err;
		if(clean_up_file(username,SHADOW) == -1) {
			fprintf(stderr,
					"clean up files failed. %s:%d.\n",
					__FILE__,__LINE__);
		}
		goto clean_on_exit;
	}

	if(!group_write(username,uid)) {
		fprintf(stderr,
				"group_write() failed, %s:%d.\n",
				__FILE__,__LINE__-3);
		status = err;
		if(clean_up_file(username,SHADOW) == -1   ||
		   clean_up_file(username,PASSWD) == -1 ) {
			fprintf(stderr,
					"clean up files failed. %s:%d.\n",
					__FILE__,__LINE__-4);
		}
		goto clean_on_exit;
	
	}

	if(!gshdw_write(username)) {
		fprintf(stderr,
				"gshdw_write() failed, %s:%d.\n",
				__FILE__,__LINE__-3);
		status = err;
		if(clean_up_file(username,SHADOW) == -1 ||
		   clean_up_file(username,PASSWD) == -1 ||
		   clean_up_file(username,GP) == -1) {
			fprintf(stderr,
					"clean up files failed. %s:%d.\n",
					__FILE__,__LINE__-5);
		}
		goto clean_on_exit;
	}

	if(!subuid_write(username, sub_uid, param.SUB_UID_COUNT)) {
		fprintf(stderr,
				"subuid_write() failed, %s:%d.\n",
				__FILE__,__LINE__-3);
		status = err;
		if(clean_up_file(username,SHADOW) == -1 ||
		   clean_up_file(username,PASSWD) == -1 ||
		   clean_up_file(username,GP) == -1 ||
		   clean_up_file(username,G_SHADOW) == -1) {
			fprintf(stderr,
					"clean up files failed. %s:%d.\n",
					__FILE__,__LINE__-6);
		}
		goto clean_on_exit;
	}

	if(!subgid_write(username, sub_gid, param.SUB_GID_COUNT)) {
		fprintf(stderr,
				"subgid_write() failed, %s:%d.\n",
				__FILE__,__LINE__-3);
		status = err;
		if(clean_up_file(username,SHADOW) == -1 ||
		   clean_up_file(username,PASSWD) == -1 ||
		   clean_up_file(username,GP) == -1 ||
		   clean_up_file(username,G_SHADOW) == -1 ||
		   clean_up_file(username,SUB_UID) == -1) {
			fprintf(stderr,
					"clean up files failed. %s:%d.\n",
					__FILE__,__LINE__-7);
		}
		goto clean_on_exit;
	}

	/* unlock the files*/
	if(unlock_files() == -1) {
		status = err;
		if(clean_up_file(username,SHADOW) == -1 ||
		   clean_up_file(username,PASSWD) == -1 ||
		   clean_up_file(username,GP) == -1 ||
		   clean_up_file(username,G_SHADOW) == -1 ||
		   clean_up_file(username,SUB_UID) == -1 ||
		   clean_up_file(username,SUB_GID) == -1 ) {
			fprintf(stderr,
					"clean up files failed. %s:%d.\n",
					__FILE__,__LINE__-7);
		}
		goto clean_on_exit;
	}
	
	lock = 0;

	/*create home dir for the user*/
	if(snprintf(hm_path,hm_l,"%s/%s",hm,username) < 0) {
		if(clean_up_file(username,SHADOW) == -1 ||
		   clean_up_file(username,PASSWD) == -1 ||
		   clean_up_file(username,GP) == -1 ||
		   clean_up_file(username,G_SHADOW) == -1 ||
		   clean_up_file(username,SUB_UID) == -1 ||
		   clean_up_file(username,SUB_GID) == -1 ) {
			fprintf(stderr,
					"clean up files failed. %s:%d.\n",
					__FILE__,__LINE__-7);
		}
		fprintf(stderr,
				"snprintf() failed, %s:%d.\n",
				__FILE__,__LINE__-3);
		status = err;
		goto clean_on_exit;
	}
	
	if(mkdir(hm_path, S_IRWXU) != 0) {
		if(clean_up_file(username,SHADOW) == -1 ||
		   clean_up_file(username,PASSWD) == -1 ||
		   clean_up_file(username,GP) == -1 ||
		   clean_up_file(username,G_SHADOW) == -1 ||
		   clean_up_file(username,SUB_UID) == -1 ||
		   clean_up_file(username,SUB_GID) == -1 ) {
			fprintf(stderr,
					"clean up files failed. %s:%d.\n",
					__FILE__,__LINE__-7);
			}

		fprintf(stderr,
				"mkdir() failed, %s:%d.\n",
				__FILE__,__LINE__-3);
		status = err;
		goto clean_on_exit;
	}
	
	if(chown(hm_path,uid,uid) == -1) {
		fprintf(stderr,"can't change ownership.\n");
		if(clean_up_file(username,SHADOW) == -1 ||
		   clean_up_file(username,PASSWD) == -1 ||
		   clean_up_file(username,GP) == -1 ||
		   clean_up_file(username,G_SHADOW) == -1 ||
		   clean_up_file(username,SUB_UID) == -1 ||
		   clean_up_file(username,SUB_GID) == -1 ) {
			fprintf(stderr,
					"clean up files failed. %s:%d.\n",
					__FILE__,__LINE__-7);
		}
        /* remove the empty directory */
        if(rmdir(hm_path) == -1)
            fprintf(stderr,"can't remove %s\n",hm_path);

		status = err;
		goto clean_on_exit;
	}

	/*copy files from SKEL to home_path */
	if(cpy_skel(hm_path,hm_l,uid) == -1) {		
		fprintf(stderr,"permission denied.\n");
		if(clean_up_file(username,SHADOW) == -1 ||
		   clean_up_file(username,PASSWD) == -1 ||
		   clean_up_file(username,GP) == -1 ||
		   clean_up_file(username,G_SHADOW) == -1 ||
		   clean_up_file(username,SUB_UID) == -1 ||
		   clean_up_file(username,SUB_GID) == -1 ) {
			fprintf(stderr,
					"clean up files failed. %s:%d.\n",
					__FILE__,__LINE__-7);
		}

        if(clean_home_dir(hm_path) == -1)
            fprintf(stderr,"can't remove %s\n",hm_path);

		status = err;
		goto clean_on_exit;
	}
    
    /*return the user id on success*/
    status = uid;

clean_on_exit:
	if(param.ENCRYPT_METHOD)
		free(param.ENCRYPT_METHOD);

	if(lock)
		unlock_files();
			
	return status;
}

static int get_sys_param(struct sys_param *param)
{
	/* 
	 * open file login.defs
	 *	get PASS_MAX_DAYS, PASS_MIN_DAYS, PASS_WARN_AGE 
	 *		UID_MAX, 
	 *		SUB_UID_MIN, SUB_UID_MAX, SUB_UID_COUNT  
	 *		GID_MAX
	 *		SUB_GID_MIN, SUB_GID_MAX, SUB_GID_COUNT
	 *		ENCRYPT_METHOD
	 * */

	FILE* fp = fopen(SYS_PARAM,"r");
	if(!fp)
	{
		if(errno == ENOENT)
			return ENOENT;

		printf("can't open the file");
		return EXIT_FAILURE;
	}
	
	int status = EXIT_SUCCESS;
	unsigned char file_column = 100;
	char buffer[file_column];

	char key[50];
	char value [50];

	memset(buffer,0,file_column);
	char *endptr;
	while(fgets(buffer,file_column,fp))
	{
		if(buffer[0] == '#') {
			memset(buffer,0,file_column);
			continue;
		}

		if(strstr(buffer,"PASS_MAX_DAYS")) {
			if(sscanf(buffer,"%s %s",key,value) == 2){
				unsigned int num = (unsigned int)strtol(value,&endptr,10);
				if(*endptr == '\0') {
					(*param).PASS_MAX_DAYS = num;
					memset(buffer,0,file_column);
					memset(key,0,50);
					memset(value,0,50);
					continue;
				}else {
					status = EXIT_FAILURE;
					goto clean_on_exit;
				}	
			}
		}

		if(strstr(buffer,"PASS_MIN_DAYS")) {
			if(sscanf(buffer,"%s %s",key,value) == 2){
				unsigned int num = (unsigned int)strtol(value,&endptr,10);
				if(*endptr == '\0') {
					(*param).PASS_MIN_DAYS = num;
					memset(buffer,0,file_column);
					continue;
				}else {
					status = EXIT_FAILURE;
					goto clean_on_exit;
				}	
			}

		}

		if(strstr(buffer,"PASS_WARN_AGE")) {
			if(sscanf(buffer,"%s %s",key,value) == 2){
				unsigned int num = (unsigned int)strtol(value,&endptr,10);
				if(*endptr == '\0') {
					(*param).PASS_WARN_AGE = num;
					memset(buffer,0,file_column);
					continue;
				}else {
					status = EXIT_FAILURE;
					goto clean_on_exit;
				}	
			}

		}

		if(strstr(buffer,"UID_MAX")) {
			if(sscanf(buffer,"%s %s",key,value) == 2){
				if(strlen(key) == strlen("UID_MAX")) {
					unsigned int num = (unsigned int)strtol(value,&endptr,10);
					if(*endptr == '\0') {
						(*param).UID_MAX = num;
						memset(buffer,0,file_column);
						continue;
					}else {
						status = EXIT_FAILURE;
						goto clean_on_exit;
					}
				}	
			}

		}

		if(strstr(buffer,"SUB_UID_MIN")) {
			if(sscanf(buffer,"%s %s",key,value) == 2){
				unsigned int num = (unsigned int)strtol(value,&endptr,10);
				if(*endptr == '\0') {
					(*param).SUB_UID_MIN = num;
					memset(buffer,0,file_column);
					continue;
				}else {
					status = EXIT_FAILURE;
					goto clean_on_exit;
				}	
			}

		}

		if(strstr(buffer,"SUB_UID_MAX")) {
			if(sscanf(buffer,"%s %s",key,value) == 2){
				unsigned int num = (unsigned int)strtol(value,&endptr,10);
				if(*endptr == '\0') {
					(*param).SUB_UID_MAX = num;
					memset(buffer,0,file_column);
					continue;
				}else {
					status = EXIT_FAILURE;
					goto clean_on_exit;
				}	
			}

		}

		if(strstr(buffer,"SUB_UID_COUNT")) {
			if(sscanf(buffer,"%s %s",key,value) == 2){
				unsigned int num = (unsigned int)strtol(value,&endptr,10);
				if(*endptr == '\0') {
					(*param).SUB_UID_COUNT = num;
					memset(buffer,0,file_column);
					continue;
				}else {
					status = EXIT_FAILURE;
					goto clean_on_exit;
				}	
			}

		}

		if(strstr(buffer,"SUB_GID_MIN")) {
			if(sscanf(buffer,"%s %s",key,value) == 2){
				unsigned int num = (unsigned int)strtol(value,&endptr,10);
				if(*endptr == '\0') {
					(*param).SUB_GID_MIN = num;
					memset(buffer,0,file_column);
					continue;
				}else {
					status = EXIT_FAILURE;
					goto clean_on_exit;
				}	
			}

		}

		if(strstr(buffer,"SUB_GID_MAX")) {
			if(sscanf(buffer,"%s %s",key,value) == 2){
				unsigned int num = (unsigned int)strtol(value,&endptr,10);
				if(*endptr == '\0') {
					(*param).SUB_GID_MAX = num;
					memset(buffer,0,file_column);
					continue;
				}else {
					status = EXIT_FAILURE;
					goto clean_on_exit;
				}	
			}

		}

		if(strstr(buffer,"SUB_GID_COUNT")) {
			if(sscanf(buffer,"%s %s",key,value) == 2){
				unsigned int num = (unsigned int)strtol(value,&endptr,10);
				if(*endptr == '\0') {
					(*param).SUB_GID_COUNT = num;
					memset(buffer,0,file_column);
					continue;
				}else {
					status = EXIT_FAILURE;
					goto clean_on_exit;
				}	
			}

		}

		if(strstr(buffer,"GID_MAX")) {
			if(sscanf(buffer,"%s %s",key,value) == 2){
				unsigned int num = (unsigned int)strtol(value,&endptr,10);
				if(*endptr == '\0') {
					(*param).GID_MAX = num;
					memset(buffer,0,file_column);
					continue;
				}else {
					status = EXIT_FAILURE;
					goto clean_on_exit;
				}	
			}

		}

		if(strstr(buffer,"ENCRYPT_METHOD")) {
			if(sscanf(buffer,"%s %s",key,value) == 2){
				(*param).ENCRYPT_METHOD = strdup(value);
				if(!(*param).ENCRYPT_METHOD) {
					status = EXIT_FAILURE;
					goto clean_on_exit;
				}	
				memset(buffer,0,file_column);
				continue;
			}
		}
		
	}
	
clean_on_exit:
	fclose(fp);
	if(status == EXIT_FAILURE)
		if((*param).ENCRYPT_METHOD)
			free((*param).ENCRYPT_METHOD);

	return status;	

}

static int last_UID()
{
	FILE *fp = fopen(GP,"r");
	if(!fp)
	{
		fprintf(stderr,"can't open %s.\n",GP);
		return EXIT_FAILURE;
	}

	int columns = 80;
	char line[columns];
	memset(line,0,columns);
	int max = 0;
    int uid = 0;
	while(fgets(line,columns,fp)) {
		strtok(line,":");
		strtok(NULL,":");
        char *t = strtok(NULL,":");
        if(!t)
            continue;

		char *endptr;
		uid = (int) strtol(t,&endptr,10);
		if(*endptr == '\0') {
			if(uid > UID_MAX) {
				memset(line,0,columns);
			       	continue;
			}

			if(uid > max)
				max = uid;

			memset(line,0,columns);
		} else {
			printf("strtol failed. %s:%d.\n",__FILE__,__LINE__-8);
			fclose(fp);
			return EXIT_FAILURE;
		}
	}
	
	fclose(fp);
    if(max < 1000) {
        return 999 ; /*the last uid if there is no regular user but only root*/
    }

	return max; /*the last UID*/
}

static unsigned int gen_SUB_GID(int uid, struct sys_param *param)
{
	unsigned int sub_gid = 0;
    if(uid == 999) {
        sub_gid = 100000;    
	    return sub_gid;
    }

	int columns = 80;
	char line[columns];
	memset(line,0,columns);

	FILE *fp = fopen(SUB_GID,"r");
	if(!fp) {
		printf("can't open %s.\n",SUB_GID);
		return -1;
	}

	/* get the username based on the uid*/
	struct passwd *pw = getpwuid(uid);
	if(!pw) {
		printf("user not found.\n");
		return -1;
	}		


	while(fgets(line,columns,fp)) {
		if(strstr(line,pw->pw_name) == NULL) {
			memset(line,0,columns);
			continue;	
		}
		
		strtok(line,":");
		char* endptr;
		sub_gid = (unsigned int) strtol(strtok(NULL,":"),&endptr,10);
		if(*endptr == '\0') {
			sub_gid += (*param).SUB_GID_COUNT;
			break;
		}
	}

	if(sub_gid > (*param).SUB_GID_MAX)
		sub_gid = ESGID;

	fclose(fp);
	return sub_gid;
}

static unsigned int gen_SUB_UID(int uid, struct sys_param *param)
{
	unsigned int sub_uid = 0;
    if(uid == 999) {
        sub_uid = 100000;    
	    return sub_uid;
    }

	FILE *fp = fopen(SUB_UID,"r");
	if(!fp) {
		fprintf(stderr,"can't open %s.\n",SUB_UID);
		return EXIT_FAILURE;
	}


	/* get the username based on the uid*/
	struct passwd *pw = getpwuid(uid);
	if(!pw) {
		fprintf(stderr,"user not found.\n");
		return EXIT_FAILURE;
	}		

	int columns = 80;
	char line[columns];
	memset(line,0,columns);

	while(fgets(line,columns,fp)) {
		if(strstr(line,pw->pw_name) == NULL) {
			memset(line,0,columns);
			continue;	
		}
		
		strtok(line,":");
		char* endptr;
		sub_uid = (unsigned int) strtol(strtok(NULL,":"),&endptr,10);
		if(*endptr == '\0') {
			sub_uid += (*param).SUB_UID_COUNT;
			break;
		}
	}

	if(sub_uid > (*param).SUB_UID_MAX)
		sub_uid = ESUID;

	fclose(fp);
	return sub_uid;

}

static unsigned char user_already_exist(char *username)
{
	FILE *fp = fopen(GP,"r");
	if(!fp) {
		fprintf(stderr,"can't open %s.\n",GP);
		return 0;
	}

	int columns = 80;
	char line[columns];
	memset(line,0,columns);
	size_t un_l = strlen(username);

	while(fgets(line,columns,fp)) {
		char* t = strtok(line,":");
		if(strlen(t) == un_l) {
			if(strncmp(t,username,un_l) == 0) {
				fclose(fp);
				return 1;
			}
		}
		memset(line,0,columns);
	}

	fclose(fp);
	return 0;
}

static unsigned char gen_random_bytes(char *buffer,int length)
{
	FILE *fp = fopen(RAN_DEV,"rb");
	if(!fp) {
		printf("can't open %s.\n",RAN_DEV);
		return 0;
	}

	if(fread(buffer,1,length,fp) != length) {
		printf("fread failed, %s:%d.\n",__FILE__,__LINE__-1);
		fclose(fp);
		return 0;
	}

	fclose(fp);
	return 1;

}
static int crypt_pswd(char *paswd, char **hash)
{

	size_t l = strlen(paswd);
	if(l > CRYPT_MAX_PASSPHRASE_SIZE) {
		fprintf(stderr,"password too long.\n");
		return EXIT_FAILURE;
	}

	struct crypt_data data = {0};
	for(int i = 0; i < l; i++ ) {
		data.input[i] = paswd[i];
	}
	
	/*
	 * gerating random byte it is not racommended,
	 * the hash will always be different and login will fail
	 * */

	/*
	char random_bytes[64];
	memset(random_bytes,0,64);

	if(!gen_random_bytes(random_bytes,64)) { 
		fprintf(stderr,
				"gen_random_bytes() failed. %s:%d.\n",
				__FILE__,__LINE__-1);
		return EXIT_FAILURE;
	}
	*/

	char const *prefix = "$y$10$";
	char *salt = crypt_gensalt(prefix, 0, randombytes, 64);
	if(!salt) {
		fprintf(stderr,
				"crypt_gensalt() failed. %s:%d.\n",
				__FILE__,__LINE__-2);
		return EXIT_FAILURE;
	}
		
	crypt_r(data.input,salt,&data);
	if(data.output[0] == '\0') {
		fprintf(stderr,
				"crypt_r() failed. %s:%d.\n",
				__FILE__,__LINE__-2);
		return EXIT_FAILURE;
	}

	*hash = strdup(data.output);
        if(!(*hash)) {
		fprintf(stderr,
				"strdup failed %s:%d.\n",
				__FILE__,__LINE__-2);
		return EXIT_FAILURE;
	}	

	return EXIT_SUCCESS;
}

static int lock_file(char *file_name)
{

	int fd = open(file_name, O_RDONLY);
	if(fd == -1) {
		fd = open(file_name, O_CREAT | O_RDWR, S_IRWXU);
		if(fd == -1) {
			perror("open:");
			fprintf(stderr,"error to acquire lock on %s.\n",
					file_name);
			return EXIT_FAILURE; 
		}

		pid_t p = getpid();
		uint32_t pton = htonl(p);
		if(write(fd,&pton,sizeof(pton)) == -1) {
			perror("write");
			close(fd);
			unlink(file_name);
			return EXIT_FAILURE; 
		}	
		close(fd);
		return EXIT_SUCCESS;	/*lock acquired*/
	}
	
	close(fd);
	return EXIT_FAILURE; /*file lock exist so it is locked already */	
}

static int unlock_file(char *file_name)
{
	int fd = open(file_name, O_RDONLY);
	if(fd == -1) {
		fprintf(stderr,"no lock are present.\n");
		return EXIT_FAILURE;
	}
	
	close(fd);
	unlink(file_name);
	return EXIT_SUCCESS;
}

static int shdw_write(char *username, char *hash, struct sys_param *param)
{
	time_t seconds = time(NULL);
	long days_nr = (long) seconds / DSEC;

	/* length of the shadow string entry.
	 * 8 is the number of colons,
     * 1 is for '\n'
	 * 1 is for '\0'
	 * */
	size_t entry_length = strlen(username) + strlen(hash) +\
			      number_of_digit(days_nr) +\
			      number_of_digit((*param).PASS_MIN_DAYS) +\
			      number_of_digit((*param).PASS_MAX_DAYS) +\
			      number_of_digit((*param).PASS_WARN_AGE) +\
			      8 + 1 + 1;
	
	char buffer[entry_length];
	memset(buffer,0,entry_length);

	if(snprintf(buffer,entry_length,"%s:%s:%ld:%d:%d:%d:::\n",
				username,hash,days_nr,
				(*param).PASS_MIN_DAYS,
				(*param).PASS_MAX_DAYS,
				(*param).PASS_WARN_AGE) < 0) {
		fprintf(stderr,
				"snprintf() failed, %s:%d.\n",
				__FILE__,__LINE__-5);
		return 0;
	}

	if(!write_file(SHADOW, buffer,
				entry_length,username)) {
		fprintf(stderr,
				"write_file failed, %s:%d.\n",
				__FILE__,__LINE__-4);
		return 0;
	}

	return 1;
}

static int psdw_write(char *username, int uid)
{	
	size_t hm_pth_l = strlen(hm) + strlen(username) + 2;
	char home_path[hm_pth_l];
	memset(home_path,0,hm_pth_l);
	
	if(snprintf(home_path,hm_pth_l,"%s/%s",hm,username) < 0) {
		fprintf(stderr,
				"snprintf() failed , %s:%d.\n",
				__FILE__,__LINE__-3);
		return 0;
	}

	/*
	 * 6 number of colons
	 * 1 for the x in password field
     * 1 for '\n'
	 * 1 for '\0'
	 **/
	size_t passwd_entry_length = strlen(username) + hm_pth_l +	\
				    (number_of_digit(uid)*2) + strlen(bsh)+\
				    6 + 1 + 1 + 1;
	
	char passwd_entry[passwd_entry_length];
	memset(passwd_entry,0,passwd_entry_length);

	if(snprintf(passwd_entry,passwd_entry_length,
				"%s:x:%d:%d::%s:%s\n",
				username,uid,uid,home_path,bsh) < 0) {
		fprintf(stderr,
				"snprintf() failed , %s:%d.\n",
				__FILE__,__LINE__-5);
		return 0;
	}

	/*open files and write entries */
	if(!write_file(PASSWD,passwd_entry,
				passwd_entry_length,username)) {
		fprintf(stderr,
				"write_file failed, %s:%d.\n",
				__FILE__,__LINE__-4);
		return 0;
	}
	return 1;
}
/*
 * function to clean files 
 * if something goes wrong between writes
 * or to erase an user from the system
 * */
static int clean_up_file(char *username,char *file_name) {
	FILE *fp = fopen(file_name,"r");
	if(!fp) {
		fprintf(stderr,"can't open %s", file_name);
		return -1;
	}
	char *tmp_file = "/etc/tmp.clean";
	FILE *tmp = fopen(tmp_file,"w");
	if(!tmp) {
		fprintf(stderr,"can't open %s", file_name);
		fclose(fp);
		return -1;
	}

	int buf_size = 5000;
	char buffer[buf_size]; 
	memset(buffer,0,buf_size);
	
	while(fgets(buffer,buf_size,fp)) {
		if(strstr(buffer,username) == NULL) {
			fputs(buffer,tmp);
			memset(buffer,0,buf_size);
		}
		memset(buffer,0,buf_size);
	}

	fclose(tmp);
	fclose(fp);
	
	if(remove(file_name) != 0) {
		fprintf(stderr,"can't delete %s", file_name);
		return -1;
	}
	
	if(rename(tmp_file,file_name) != 0) {
		fprintf(stderr,"can't rename file %s.\n",tmp_file);
		return -1;
	}

	return 0; /* success*/ 
}

static int write_file(char *file_name, char *entry, size_t entry_size, char *username)
{	
	FILE *fp_main = fopen(file_name, "a");
	if(!fp_main) {
		fprintf(stderr,
				"%s() failed, %s:%d.\n",
				__func__,__FILE__,__LINE__-4);
		return 0;
	}

    if(fprintf(fp_main,"%s",entry) < 0) {
		fclose(fp_main);
		fprintf(stderr,
				"%s() failed, %s:%d.\n",
				__func__,__FILE__,__LINE__-5);
		return 0;
	}

	fclose(fp_main);
	return 1;

}

static int group_write(char *username, int uid) 
{
	/*
	 * 3 number of colons
     * 1 for 'x'
     * 1 for '\n'
	 * 1 for '\0' 
	 **/
	size_t entry_length = strlen(username) + number_of_digit(uid) + 3 + 1 + 1 + 1;
	
	char entry[entry_length];
	memset(entry,0,entry_length);

	if(snprintf(entry,entry_length,"%s:x:%d:\n",username,uid) < 0) {
		fprintf(stderr,
				"snprintf() failed, %s:%d.\n",
				__FILE__,__LINE__-3);
		return 0;
	}

	if(!write_file(GP,entry,entry_length,username)) {
		fprintf(stderr,
				"write_file() failed, %s:%d.\n",
				__FILE__,__LINE__-3);
		return 0;
	}
	
	return 1;
}

static int gshdw_write(char *username)
{
	/*
	 * 3 number of columns
	 * 1 space for '!'
     * 1 for '\n'
	 * 1 for '\0' 
	 **/
	size_t entry_length = strlen(username) + 3 + 1 + 1 + 1;
	char entry[entry_length];
	memset(entry,0,entry_length);

	if(snprintf(entry,entry_length,"%s:!::\n",username) < 0) {
		fprintf(stderr,
				"snprintf() failed, %s:%d.\n",
				__FILE__,__LINE__-3);
		return 0;
	}

	if(!write_file(G_SHADOW,entry,entry_length,username)) {
		fprintf(stderr,
				"write_file() failed, %s:%d.\n",
				__FILE__,__LINE__-3);
		return 0;
	}

	return 1;
}

static int subuid_write(char *username, unsigned int sub_uid, int count)
{
	/*
	 * 2 number of colons
	 * 1 for '\0'
     * 1 for '\n'
	 **/
	size_t entry_length = strlen(username) +\
			      number_of_digit(sub_uid) +\
			      number_of_digit(count) + 2 + 1 + 1;
	char entry[entry_length];
	memset(entry,0,entry_length);

	if(snprintf(entry,entry_length,"%s:%d:%d\n",username,sub_uid,count) < 0) {
		fprintf(stderr,
				"snprintf() failed, %s:%d.\n",
				__FILE__,__LINE__-3);
		return 0;
	}

	if(!write_file(SUB_UID,entry,entry_length,username)) {
		fprintf(stderr,
				"write_file() failed, %s:%d.\n",
				__FILE__,__LINE__-3);
		return 0;
	}

	return 1;

}

static int subgid_write(char *username, unsigned int sub_gid, int count)
{
	/*
	 * 2 number of colons
     * 1 for '\n'
	 * 1 for '\0'
	 **/
	size_t entry_length = strlen(username) +\
			      number_of_digit(sub_gid) +\
			      number_of_digit(count) + 2 + 1 + 1;

	char entry[entry_length];
	memset(entry,0,entry_length);

	if(snprintf(entry,entry_length,"%s:%d:%d\n",username,sub_gid,count) < 0) {
		fprintf(stderr,
				"snprintf() failed, %s:%d.\n",
				__FILE__,__LINE__-3);
		return 0;
	}

	if(!write_file(SUB_GID,entry,entry_length,username)) {
		fprintf(stderr,
				"write_file() failed, %s:%d.\n",
				__FILE__,__LINE__-3);
		return 0;
	}

	return 1;
}

static int cpy_skel(char *home_path, int home_path_length, int uid)
{
	
	FILE *fp_profile = NULL;
	FILE *fp_hm_profile = NULL;
	FILE *fp_bashrc = NULL;
	FILE *fp_hm_bashrc = NULL;
	FILE *fp_bash_lgo = NULL;
	FILE *fp_hm_bash_lgo = NULL;
    FILE *fp_mozzilla = NULL;
    FILE *fp_hm_mozzilla = NULL;
	size_t hm_profile_pth_l = 0; 
	size_t hm_bashrc_path_l = 0; 
	size_t hm_bash_lgo_path_l = 0;
    size_t hm_mozzilla_pth_l = 0; 
	size_t profile_pth_l = 0;
    size_t mozzilla_pth_l = 0;
	int status = 0;
	int err = -1;

    int distro = get_linux_distro();
    
    if(distro == -1) {
        fprintf(stderr, "can't read %s.\n",DISTRO);
        return - 1;
    } else if(distro == DEB) {
        hm_profile_pth_l = strlen(U_PROFILE) + home_path_length + 2;
	    profile_pth_l = strlen(U_PROFILE) + strlen(SKEL) + 2;
    } else if(distro == RHEL) {
        hm_profile_pth_l = strlen(FC_PROFILE) + home_path_length + 2;
        hm_mozzilla_pth_l = strlen(FC_MOZZILA) + home_path_length + 2;
	    profile_pth_l = strlen(FC_PROFILE) + strlen(SKEL) + 2;
        mozzilla_pth_l = strlen(FC_MOZZILA) +strlen(SKEL) +2;
    }

	hm_bashrc_path_l = strlen(BASH_RC) + home_path_length + 2;
	hm_bash_lgo_path_l = strlen(BASH_LGO) + home_path_length +2;
	
	size_t bashrc_pth_l = strlen(BASH_RC) + strlen(SKEL) + 2;
	size_t bash_lgo_pth_l = strlen(BASH_LGO) + strlen(SKEL) + 2;

	char profile_pth[profile_pth_l];
	char bashrc_pth[bashrc_pth_l];
	char bash_lgo_pth[bash_lgo_pth_l];

	char hm_profile_pth[hm_profile_pth_l];
	char hm_bashrc_pth[hm_bashrc_path_l];
	char hm_bash_lgo_pth[hm_bash_lgo_path_l];

	memset(profile_pth,0,profile_pth_l);
	memset(bashrc_pth,0,bashrc_pth_l);
	memset(bash_lgo_pth,0,bash_lgo_pth_l);
	memset(hm_profile_pth,0,hm_profile_pth_l);
	memset(hm_bashrc_pth,0,hm_bashrc_path_l);
	memset(hm_bash_lgo_pth,0,hm_bash_lgo_path_l);

    if(mozzilla_pth_l > 0) {
        char hm_mozzilla_pth[hm_mozzilla_pth_l];
        char mozzilla_pth[mozzilla_pth_l];
        memset(mozzilla_pth,0,mozzilla_pth_l);
        memset(hm_mozzilla_pth,0,hm_mozzilla_pth_l);

        if(snprintf(mozzilla_pth,mozzilla_pth_l,
                    "%s/%s",SKEL,FC_MOZZILA) < 0) {
		    fprintf(stderr,
				"snprintf() failed, %s:%d.\n",
				__FILE__,__LINE__-2);
	    	return -1;
        }
    
        if(snprintf(hm_mozzilla_pth,hm_mozzilla_pth_l,
                    "%s/%s",home_path,FC_MOZZILA) < 0) {
		    fprintf(stderr,
				"snprintf() failed, %s:%d.\n",
				__FILE__,__LINE__-2);
	    	return -1;
        }

    	if(snprintf(profile_pth,profile_pth_l,
	    			"%s/%s",SKEL,FC_PROFILE) < 0) {
	    	fprintf(stderr,
				"snprintf() failed, %s:%d.\n",
				__FILE__,__LINE__-2);
	    	return -1;
	    }

    	if(snprintf(hm_profile_pth,hm_profile_pth_l,
	    			"%s/%s",home_path,FC_PROFILE) < 0) {
	    	fprintf(stderr,
				"snprintf() failed, %s:%d.\n",
				__FILE__,__LINE__-2);
	    	return -1;
	    }

        fp_mozzilla = fopen(mozzilla_pth,"r");
        if(!fp_mozzilla) {
		    fprintf(stderr,"can't open %s.\n",mozzilla_pth);
		    status = err;
		    goto clean_on_exit;
        }

        fp_hm_mozzilla = fopen(hm_mozzilla_pth,"w");
        if(!fp_hm_mozzilla) {
		    fprintf(stderr,"can't open %s.\n",hm_mozzilla_pth);
		    status = err;
		    goto clean_on_exit;
        }

    	if(cpy_file(fp_mozzilla,fp_hm_mozzilla) == -1) {
    		fprintf(stderr,
	    			"copy file %s failed.\n",
		    		mozzilla_pth);
		    status = err;
		    goto clean_on_exit;
	    }

        if(chown(hm_mozzilla_pth,uid,uid) != 0) {
            fprintf(stderr,
                    "can't change %s ownership.\n",hm_mozzilla_pth);
		    status = err;
	    	goto clean_on_exit;
        }

    } else {

    	if(snprintf(profile_pth,profile_pth_l,
				"%s/%s",SKEL,U_PROFILE) < 0) {
	    	fprintf(stderr,
				"snprintf() failed, %s:%d.\n",
				__FILE__,__LINE__-2);
		    return -1;
	    }

	    if(snprintf(hm_profile_pth,hm_profile_pth_l,
				"%s/%s",home_path,U_PROFILE) < 0) {
	    	fprintf(stderr,
				"snprintf() failed, %s:%d.\n",
				__FILE__,__LINE__-2);
		    return -1;
	    }

    }

	if(snprintf(bashrc_pth,bashrc_pth_l,
				"%s/%s",SKEL,BASH_RC) < 0) {
		fprintf(stderr,
				"snprintf() failed, %s:%d.\n",
				__FILE__,__LINE__-2);
		return -1;
	}

	if(snprintf(hm_bashrc_pth,hm_bashrc_path_l,
				"%s/%s",home_path,BASH_RC) < 0) {
		fprintf(stderr,
				"snprintf() failed, %s:%d.\n",
				__FILE__,__LINE__-2);
		return -1;
	}

	if(snprintf(bash_lgo_pth,bash_lgo_pth_l,
				"%s/%s",SKEL,BASH_LGO) < 0) {
		fprintf(stderr,
				"snprintf() failed, %s:%d.\n",
				__FILE__,__LINE__-2);
		return -1;
	}

	if(snprintf(hm_bash_lgo_pth,hm_bash_lgo_path_l,
				"%s/%s",home_path,BASH_LGO) < 0) {
		fprintf(stderr,
				"snprintf() failed, %s:%d.\n",
				__FILE__,__LINE__-2);
		return -1;
	}



	fp_profile = fopen(profile_pth,"r");
	if(!fp_profile) {
		fprintf(stderr,"can't open %s.\n",profile_pth);
		status = err;
		goto clean_on_exit;
	}

	fp_hm_profile = fopen(hm_profile_pth,"w");
	if(!fp_profile) {
		fprintf(stderr,"can't open %s.\n",profile_pth);
		status = err;
		goto clean_on_exit;
	}

	
	fp_bashrc = fopen(bashrc_pth,"r");
	if(!fp_bashrc) {
		fprintf(stderr,"can't open %s.\n",profile_pth);
		status = err;
		goto clean_on_exit;
	}
	
	fp_hm_bashrc = fopen(hm_bashrc_pth,"w");
	if(!fp_hm_bashrc) {
		fprintf(stderr,"can't open %s.\n",profile_pth);
		status = err;
		goto clean_on_exit;
	}

	fp_bash_lgo = fopen(bash_lgo_pth,"r");
	if(!fp_bash_lgo) {
		fprintf(stderr,"can't open %s.\n",profile_pth);
		status = err;
		goto clean_on_exit;
	}

 	fp_hm_bash_lgo = fopen(hm_bash_lgo_pth,"w");
	if(!fp_hm_bash_lgo) {
		fprintf(stderr,"can't open %s.\n",profile_pth);
		status = err;
		goto clean_on_exit;
	}

	if(cpy_file(fp_profile,fp_hm_profile) == -1) {
		fprintf(stderr,
				"copy file %s failed.\n",
				profile_pth);
		status = err;
		goto clean_on_exit;
	}

	if(cpy_file(fp_bashrc,fp_hm_bashrc) == -1) {
		fprintf(stderr,
				"copy file %s failed.\n",
				bashrc_pth);
		status = err;
		goto clean_on_exit;
	}

	if(cpy_file(fp_bash_lgo,fp_hm_bash_lgo) == -1) {
		fprintf(stderr,
				"copy file %s failed.\n",
				bash_lgo_pth);
		status = err;
		goto clean_on_exit;
	}

	if((chown(hm_profile_pth,uid,uid) != 0) ||
	   (chown(hm_bashrc_pth,uid,uid) != 0) ||
	   (chown(hm_bash_lgo_pth,uid,uid) != 0))
	       fprintf(stderr,"can't change files ownership");	

clean_on_exit:
	if(fp_profile) {
		fclose(fp_profile);
    }
	if(fp_hm_profile){
		fclose(fp_hm_profile);
    }
	if(fp_bashrc) {
		fclose(fp_bashrc);
    }
	if(fp_hm_bashrc){
		fclose(fp_hm_bashrc);
    }
	if(fp_bash_lgo) {
		fclose(fp_bash_lgo);
    }
	if(fp_hm_bash_lgo) {
        fclose(fp_hm_bash_lgo);
    }
    if(fp_hm_mozzilla) {
        fclose(fp_hm_mozzilla);
    }


	return status;
}

static int cpy_file(FILE *src, FILE *dest)
{
	
	if(!src || !dest) {
		fprintf(stderr,"can't copy files.\n");
		return -1;
	}

	int columns = 90;
	char line[columns];
	memset(line,0,columns);

	while(fgets(line,columns,src)) {
		fputs(line,dest);
		memset(line,0,columns);
	}

	return 0;
}
static int lock_files()
{
	int i;
	for(i = 0; i < 15; i++) {
		if((lock_file(SHADOW_LCK) == -1) 	||
		   (lock_file(GP_LCK) == -1) 		||
		   (lock_file(G_SHADOW_LCK) == -1) 	||
		   (lock_file(PASSWD_LCK) == -1) 	||
		   (lock_file(SUB_GID_LCK) == -1) 	||
		   (lock_file(SUB_UID_LCK) == -1)) { 
		
			sleep(1);
			continue;
		} else {
			break;
		}
	}

	if(i == 15) {
		/*cannot lock the file*/
		fprintf(stderr,"cannot acquire lock on users db files.\n");
		return -1;
	}

	return 0;
}
static int unlock_files()
{
	if(
	   (unlock_file(SHADOW_LCK) == -1)	||
	   (unlock_file(GP_LCK) == -1)		||
	   (unlock_file(G_SHADOW_LCK) == -1)	||
	   (unlock_file(PASSWD_LCK) == -1)	||
	   (unlock_file(SUB_GID_LCK) == -1)	||
	   (unlock_file(SUB_UID_LCK) == -1)) {
		fprintf(stderr,"error unlocking the user db files.\n");
		return -1;
	}

	return 0;

}

/*
 * paswd_chk return a bool value (0 : false 1: true)
 * 	if 0 is returned the password soeas not match security policies
 *	and the creation of the user will failed.
 *
 *	ECHAR might be returned if the passowrd contain the system KILL or 
 *	ERASE char
 *
 * */
static int paswd_chk(char *passwrd)
{
	unsigned char upper = 0;
	unsigned char lower = 0;
	unsigned char punct = 0;
	unsigned char num = 0;

	size_t pswd_len = strlen(passwrd);
	if(pswd_len < PWD_L) return -1;

	struct termios t;
	if(tcgetattr(STDIN_FILENO,&t) == -1) {
		fprintf(stderr,"can't check password against special char.\n");
		return -1;
	}


	char kill = t.c_cc[VKILL];
	char erase = t.c_cc[VERASE];

	for(int i = 0; i < pswd_len; i++) {
		if(passwrd[i] == kill || passwrd[i] == erase)
			return ECHAR;

		if(isdigit(passwrd[i])) num = 1;
		if(isupper(passwrd[i])) upper = 1;
		if(islower(passwrd[i])) lower = 1;
		if(ispunct(passwrd[i])) punct = 1;
	}
	
	return num & upper & lower & punct;

}
/*
 * get_linux_distro() return a positive number on success and -1 if it fails
 *  return values are
 *          DEB for debian like distros
 *          RHEL for red hat like distros like fedora centOS
 * */

static int get_linux_distro()
{
    FILE *fp;
    int status = 0;
    int err = -1;
    int columns = 80;
    char line[columns];
    memset(line,0,columns);

    fp = fopen(DISTRO,"r");
    if(!fp) {
        status = err;
        goto clean_on_exit;
    }

    while(fgets(line,columns,fp)) {
        if(strstr(line,"ID")) {
            if(strstr(line,"fedora") ||
                    strstr(line,"centos")) {
                status = RHEL;
                break;
            } else if(strstr(line,"debian")) {
                status = DEB;
                break;
            }

            memset(line,0,columns);
            continue;
        }
    }

clean_on_exit:
    if(fp)
        fclose(fp);

    return status;

}


#if !HAVE_LIBSTROP
static size_t number_of_digit(int n)
{
	if(n < 10) {
		return 1;
	}else if(n >= 10 && n < 100) {
		return 2;
	}else if(n >= 100 && n < 1000) {
		return 3;
	}else if(n >= 1000 && n < 10000) {
		return 4;
	}else if(n >= 10000 && n < 100000) {
		return 5;
	}else if(n >= 100000 && n < 1000000) {
		return 6;
	}else if(n >= 1000000 && n < 1000000000) {
		return 7;
	}else if(n >= 1000000000) {
		return 10;
	}

	return -1;	
}
#endif /*HAVE_LIBSTROP*/

/*
 * clean_home_dir() check if the directory hm_path contains files,
 * if so, it deletes them and remove the directory.
 * return 0 on success and -1 on failure.
 *
 * this is used in case of error in the copying of
 * skeletal files to the new user home directory
 **/

static int clean_home_dir(char *hm_path)
{
    DIR *dir = opendir(hm_path);
    struct dirent *ent = {0};

    if(!dir) {
        if(errno == ENOENT) {
           fprintf(stderr,
                   "%s: no such a file or directory.\n",
                   hm_path);
           return -1;
        }
        fprintf(stderr,
                "can't open %s.\n",
                hm_path);
        return -1;
    } 

    while((ent = readdir(dir))){
        if(ent->d_type == DT_REG)
            unlink(ent->d_name);
    }

    closedir(dir);
    if(rmdir(hm_path) == -1) {
       if(errno == ENOENT) {
          fprintf(stderr,
                        "%s: No such a file or direcotry.\n",
                        hm_path);
         return -1;
       }
       fprintf(stderr,"can't open %s.\n",hm_path);
    } 

    return 0;
}


int get_user_info(char *username, char **home_pth, int *uid)
{
	struct passwd *pw = getpwnam(username);
	if(!pw) {
		fprintf(stderr,"%s() failed, %s:%d\n",
		__func__,__FILE__,__LINE__);
		return -1;
	}

	(*home_pth) = strdup(pw->pw_dir);
	*uid = pw->pw_uid;
	return 0;
}
