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

int main(void)
{
	int ret = add_user("amerigo","thisisapassphrase^U8");
	if(ret == -1 || ret >= 10) {
		printf("add user failed!\n");
		return EXIT_FAILURE;
	}

	printf("user_add succeed\n");
	return 0;
}
