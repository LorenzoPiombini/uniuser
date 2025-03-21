#ifndef _UNIUSER_H_
#define _UNIUSER_H_

/*Safe directory to keep data of deleted users*/
#define USER_DEL_DIR "/home/users_del" 

/*configuration file*/
#define CONF "/etc/uniuser/uniuser.conf"
#define rUID "/etc/uniuser/UIDs"
#define rGID "/etc/uniuser/GIDs"
#define REAL_GIDs "/etc/uniuser/real_GIDs"
#define REAL_UIDs "/etc/uniuser/real_UIDs"
#define TEMP_CNFL "/etc/uniuser/temp"

#define REUSE 0
#define REUSE_UID_GID 69

/* files to open and  files acquire lock */
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
#define EMAX_G 9 /*exeed the maximum gid number*/
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
#define NO_IDs 21 /*no reusalble GIds*/
#define EROOT 22 /*try to change or delete ROOT*/
#define EGECOS 23 /*edit user  GECOS faield*/

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

/*Login constants*/
#define NOT_STD 0
#define STD 1
#define clean_path "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin"



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
	char ENCRYPT_METHOD[300];
};


#define MAX_STRING_SIZE 2048
struct user_info{
	char username[MAX_STRING_SIZE];
	char full_name[MAX_STRING_SIZE];
	char dir[MAX_STRING_SIZE];
	char group_list[MAX_STRING_SIZE];
	int uid;
	int gid;
	int is_admin;	
};

/*MASK value operation */
#define USER 32		/*0010 0000*/
#define DEL_F 64	/*0100 0000*/
#define DEL 128		/*1000 0000*/
#define GROUP 10	/*0000 1010*/
#define PWD 11		/*0000 1011*/
#define GECOS 4		/*0000 0100*/
#define EDIT 16		/*0001 0000*/

/*operation*/
/*DO NOT USE 63*/
#define DEL_USER 160		/*1010 0000 */ /* flag -du <username>*/
#define ADD_GROUP_TO_USER 58    /*0010 1010*/  /* flag -g <groupname> -u <username>*/
#define DEL_GROUP 138		/*1000 1010*/  /* flag -dg <groupname> */
#define USER_AND_PSWD 43	/*0010 1011*/  /* falg -u <username> -p <password>*/
#define DEL_GROUP_FROM_USER 186	/*1011 1010*/  /*flag -ed -u <username> -g <groupname>*/
#define EDIT_PASWD 59		/*0011 1011*/ /*flag -eu <username> -p <password> */
#define EDIT_GECOS 52		/*0011 0100*/ /*flag -eu <username> -G <gecos>*/
#define EDIT_USER  48           /*0011 0000*/ /*flag -eu <username> -c <newusername>*/

#define CH_PWD EDIT_PASWD
#define CH_GECOS EDIT_GECOS
#define CH_USRNAME EDIT_USER 


/* the API available with this library*/
int crypt_pswd(char *paswd, char **hash, char* salt);
int add_user(char *username, char *paswd, char *full_name);
int edit_user(char *username, int *uid, int element_to_change,int n_elem, ...);
int login(char *username, char *passwd, int mod);
int get_user_info(char *username, struct user_info *ui);
int del_user(char *username, int mod);
int create_group(char* group_name);
int del_group(char *group_name);
int edit_group_user(char *username, char *group_name, int mod);
int paswd_chk(char *passwrd,int rules);
int list_group(char *username, char **list);


#endif /* uniuser.h */
