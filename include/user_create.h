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

/*file to understand distro, used for skelatal files
 * RHEL :- rhel distors like CentOS, Fedora, Red Hat
 * DEB :- debian distros like Debian, Ubuntu, Kali Linux 
 **/
#define DISTRO "/etc/os-release"
#define RHEL 1 
#define DEB 2
/*
 * files in SKEL, FC means Fedora and Centos distros
 * U means ubuntu
 **/
#define U_PROFILE ".profile"
#define FC_PROFILE ".bash_profile"
#define FC_MOZZILA ".mozilla"
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

char randombytes[] = { 'c','&','d','"','o','6','@','^',
			'f','a','1','!','~','`','%','*',
			'k','l','o','p','6','7','(',')',
			'Z','x','c','O','{','[','+','0',
			':','\'','>','<','?','M','n','5',
			'U','H','v','b','L','X','+','-',
			'c','v','~','#','$','%','0','8',
			'v','c','j','K','G','h','S','P',};



int add_user(char *username, char *paswd);
int login(char *username, char *passwd);

#endif /* user_create.h */
