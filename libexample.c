#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>


static void __attribute__((constructor)) blah(void)
{
	char cwd[128];
	void *p;
	int i;

	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	printf("[+] in library\n");

	/* getcwd is allowed by seccomp-bpf */
	getcwd(cwd, sizeof(cwd));
	printf("[+] current directory: %s\n", cwd);

	/* trigger memory allocations to get killed thanks to rlimit or
	 * forbidden brk */
	printf("[+] testing allocations...\n");
	for (i = 0; ; i++) {
		p = malloc(1024 * 1024);
		printf("    %03d: %p\n", i, p);
	}
}
