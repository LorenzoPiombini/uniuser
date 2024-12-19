#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <pwd.h>
#include <errno.h>
#include "user_create.h"
#include "str_op.h"
#include "com.h"

int main(void)
{
	int ret = add_user("amerigo","thisisapassphrase^U8");
	if(ret == -1 || ret >= 10) {
		printf("add user failed!\n");
		return EXIT_FAILURE;
	}

	printf("user_add succeed\n");
	return 0;
#if 0
	/*  1 set up unix socket to accept connections */
	int fd_sock = -1;
       	if(!listen_set_up(&fd_sock,AF_UNIX,SOCK_STREAM,0))	
	{
		printf("listen_set_up()  failed, %s:%d.\n",__FILE__,__LINE__-2);
		return EXIT_FAILURE;
	}

	int client_sock = -1;
	char buffer[1000];
	for(;;)
	{
		memset(buffer,0,1000);

		if(!accept_intercom(&fd_sock,&client_sock,buffer,1000))
		{
			printf("accept_intercom() failed, %s:%d.\n",__FILE__,__LINE__-2);
			return EXIT_FAILURE;
		}

		if(strstr(buffer,ID_REQ) == NULL)
			continue;	
	
		/* process the string recived from the main program */
		char *buf_cpy = strdup(buffer);
		if(!buf_cpy) {
			printf("strdup() failed %s:%d.\n",__FILE__,__LINE__-3);
			continue;
		}

		strtok(buf_cpy,":");
		char *username = strdup(strtok(NULL,":"));
		char *passwd = strdup(strtok(NULL,":"));
		
		free(buf_cpy);
		if(!username || !passwd) {
			printf("username or password are invalid.\n");
			if(passwd)
				free(passwd);

			if(username)
				free(username);

			continue;
		}
		
		replace('\n','\0',passwd);	
	}
	
	return 0;
#endif
}
