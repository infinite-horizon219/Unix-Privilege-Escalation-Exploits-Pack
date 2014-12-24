#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#define	INSMOD_PATH	"/sbin/insmod"
#define	INIT_PRE_CMD	"/sbin/rmmod kernwrite > /dev/null 2>&1"
#define	INIT_POST_CMD	"/bin/chmod go+rx /sys/kernel/debug"


/* helper; initialize the `kernwrite' module */
int
main(int argc, char **argv)
{
	/* exit status */
	int status;


	/* argument validation */
	if (argc <= 1) {
		/* failed */
		fprintf(stderr, "[-] %s <kernwrite.ko>\n", argv[0]);
		goto err;
	}

	/* pre initialization */
	if (system(INIT_PRE_CMD) == -1) {
		/* failed */
		fprintf(stderr, "[-] system() failed -- %s\n",
				strerror(errno));
		goto err;
	}

	/* load the module */
	switch (fork()) {
		case -1:
			/* fork() failed */
			fprintf(stderr, "[-] fork() failed -- %s\n",
					strerror(errno));
			goto err;

			/* not reached */
			break;

		case 0:
			/* child; `insmod' */
			execlp(INSMOD_PATH, INSMOD_PATH, argv[1], NULL);
			
			/* failed */
			fprintf(stderr, "[-] exec() failed -- %s\n",
					strerror(errno));
			
			goto err;

			/* not reached */
			break;

		default:
			/* parent; wait for `insmod' to complete */
			wait(&status);
			
			if (WEXITSTATUS(status) != 0)
				/* child failed */
				goto err;

			/* done */
			break;
	}

	/* post initialization */
	if (system(INIT_POST_CMD) == -1) {
		/* failed */
		fprintf(stderr, "[-] system() failed -- %s\n",
				strerror(errno));
		goto err;
	}

	/* done; return with success */
	return EXIT_SUCCESS;

err:
	/* done; return with an error */
	return EXIT_FAILURE;
}
