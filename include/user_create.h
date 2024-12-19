#ifndef _USER_CREATE_H_
#define _USER_CREATE_H_


/* files to open and to files acquire lock */
#define SYS_PARAM "/etc/login.defs"
#define GP "/etc/group"
#define GP_LCK "/etc/group.lock"
#define SUB_GID "/etc/subgid"
#define SUB_GID_LCK "/etc/subgid.lock"
#define	SUB_UID "/etc/subuid"
#define	SUB_UID_LCK "/etc/subuid.lock"
#define G_SHADOW "/etc/gshadow"
#define G_SHADOW_LCK "/etc/gshadow.lock"
#define PASSWD "/etc/passwd"
#define PASSWD_LCK "/etc/passwd.lock"
#define SHADOW "/etc/shadow"
#define SHADOW_LCK "/etc/shadow.lock"
#define SKEL "/etc/skel"

/* used for randomization in password hashing*/
#define RAN_DEV "/dev/urandom"

/*files in SKEL*/
#define PROFILE ".profile"
#define BASH_RC ".bashrc"
#define BASH_LGO ".bash_logout"

/*password security length*/
#define PWD_L 8 

/* errors */
#define EMAX_U 10 /*exeed the maximum user number*/
#define EALRDY_U 11 /*user already exist*/
#define ESGID 12 /*SUB_GID_MAX overflowed */
#define ESUID 13 /*SUB_UID_MAX overflowed */
#define ECHAR 13 /* passowrd contain KILL or ERASE system char */

/*used to calculate the password day creation*/
#define DSEC (60*60*24) /* seconds in a day*/

struct sys_param {
	unsigned int PASS_MAX_DAYS;
	unsigned int PASS_MIN_DAYS;
	unsigned int PASS_WARN_AGE;
	unsigned int UID_MAX;
	unsigned int SUB_UID_MIN;
	unsigned int SUB_UID_MAX;
	unsigned int SUB_UID_COUNT;
	unsigned int GID_MAX;
	unsigned int SUB_GID_MIN;
	unsigned int SUB_GID_MAX;
	unsigned int SUB_GID_COUNT;
	char *ENCRYPT_METHOD;
};





int add_user(char *username, char *paswd);
unsigned char create_user(char* username, char* paswd);
unsigned char create_paswd(char *username, char *pswd);

#endif /* user_create.h */
