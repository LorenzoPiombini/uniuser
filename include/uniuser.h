#ifndef _UNIUSER_H_
#define _UNIUSER_H_

/*Safe directory to keep data of deleted users*/
#define USER_DEL_DIR "/home/users_del" 



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

/*password security rules switch*/
#define RULE_ON 1
#define RULE_OFF 0

/* errors */
#define EMAX_U 10 /*exeed the maximum user number*/
#define EALRDY_U 11 /*user already exist*/
#define ESGID 12 /*SUB_GID_MAX overflowed */
#define ESUID 13 /*SUB_UID_MAX overflowed */
#define ECHAR 14 /* passowrd contain KILL or ERASE system char */
#define ENONE_U 15  /* user does not exist */
#define EALRDY_GU 16 /*group already added to user*/
#define ERR_GU 17 /*error in delating the group*/
#define ENONE_GU 18 /*the user is not assign to this group */
#define EALRDY_G 19 /*group already exist*/
#define ENONE_G 20 /*the group  does not exist*/

/*used to calculate the password day creation*/
#define DSEC (60*60*24) /* seconds in a day*/



/*mode: ADD or DELETE group from USERS*/
#define ADD_GU 0
#define DEL_GU 1
/* 
 * mode: DEL_FULL DELL_SAFE 
 * DEL_FULL delete everything from the user 
 * DEL_SAFE will delate the user but not the home directory.
 *
 * */ 
#define DEL_FULL 2
#define DEL_SAFE 3

#define ADMIN "root"
#define SUDO "sudo"



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

/* the API available with this library*/
int crypt_pswd(char *paswd, char **hash);
int add_user(char *username, char *paswd, char *full_name);
int login(char *username, char *passwd);
int get_user_info(char *username, char **home_pth, int *uid, int *is_admin);
int del_user(char *username, int mod);
int create_group(char* group_name);
int del_group(char *group_name);
int edit_group_user(char *username, char *group_name, int mod);
int paswd_chk(char *passwrd,int rules);
int list_group(char *username, char **list);



#endif /* uniuser.h */
