#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/prctl.h>
#include <netinet/tcp.h>
#include <sys/resource.h>
#include <linux/seccomp.h>

#include "memdlopen.h"
#include "seccomp-bpf.h"

#define PORT    	1234
#define MAX_SIZE	65536
#define MAX_CPU_TIME	15
#define MAX_MEMORY	16 * 1024 * 1024


static void readall(int fd, void *buf, size_t len)
{
	unsigned char *p;
	ssize_t n;

	p = buf;
	while (len > 0) {
		n = read(fd, p, len);
		if (n == -1) {
			if (errno != EINTR)
				err(1, "read");
			continue;
		} else if (n == 0) {
			errx(1, "read: end of file");
		}
		len -= n;
		p += n;
	}
}

static void signal_handler(int n)
{
	fprintf(stderr, "got signal %d\n", n);
	_exit(1);
}

static void install_syscall_filter(void)
{
	struct sock_filter filter[] = {
		/* Validate architecture. */
		VALIDATE_ARCHITECTURE,
		/* Grab the system call number. */
		EXAMINE_SYSCALL,
		/* List allowed syscalls. */
		ALLOW_SYSCALL(rt_sigreturn),
		ALLOW_SYSCALL(exit),
		ALLOW_SYSCALL(exit_group),
		ALLOW_SYSCALL(read),
		ALLOW_SYSCALL(write),
		ALLOW_SYSCALL(mmap),
		ALLOW_SYSCALL(mprotect),
		ALLOW_SYSCALL(getcwd),
		KILL_PROCESS,
	};

	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
		err(1, "prctl(NO_NEW_PRIVS)");

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog))
		err(1, "prctl(SECCOMP)");
}

static void receive_and_exec_code(int s)
{
	unsigned int size;
	void (*f)(void);
	int prot;
	char op;
	void *p;

	readall(s, &op, sizeof(op));
	readall(s, &size, sizeof(size));
	if (size > MAX_SIZE)
		errx(1, "size too large: %d", size);

	prot = PROT_READ | PROT_WRITE | PROT_EXEC;
	p = mmap(NULL, size, prot, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (p == MAP_FAILED)
		err(1, "mmap");

	readall(s, p, size);

	switch (op) {
	case '0':
		f = p;
		f();
		break;
	case '1':
		memdlopen(size, p);
		break;
	default:
		break;
	}

	_exit(0);
}

static void child(int s, int c)
{
	struct rlimit rlimit;
        pid_t pid;

        pid = fork();
        if (pid == -1) {
                warn("fork");
                return;
        } else if (pid > 0) {
                close(c);
		return;
	}

        if (prctl(PR_SET_PDEATHSIG, SIGTERM) == -1)
                err(1, "prctl(PR_SET_PDEATHSIG)");

	close(s);

        if (dup2(c, STDIN_FILENO) == -1 ||
	    dup2(c, STDOUT_FILENO) == -1 ||
	    dup2(c, STDERR_FILENO) == -1)
                warn("dup2");

        if (signal(SIGBUS, signal_handler) == SIG_ERR ||
	    signal(SIGSEGV, signal_handler) == SIG_ERR ||
	    signal(SIGTRAP, signal_handler) == SIG_ERR)
                err(1, "signal");

        alarm(MAX_CPU_TIME);

	rlimit.rlim_cur = MAX_MEMORY;
	rlimit.rlim_max = RLIM_INFINITY;
	if (setrlimit(RLIMIT_AS, &rlimit) == -1)
		err(1, "setrlimit");

	install_syscall_filter();

	receive_and_exec_code(c);
}

int main(void)
{
        struct sockaddr_in addr;
        int c, enable, s;
        socklen_t len;

	if (memdlopen_init() != 0)
		exit(1);

        if (signal(SIGCHLD, SIG_IGN) == SIG_ERR)
                err(1, "signal");

        s = socket(AF_INET, SOCK_STREAM, 0);
        if (s == -1)
                err(1, "socket");

	enable = 1;
        if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) == -1)
                err(1, "setsockopt(SO_REUSEADDR)");

        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(PORT);

        if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) == -1)
                err(1, "bind");

	if (listen(s, 1) == -1)
                err(1, "listen");

        len = sizeof(addr);
        while (1) {
                c = accept(s, (struct sockaddr *)&addr, &len);
                if (c == -1) {
                        warn("accept");
                        continue;
                }

		child(s, c);
	}

	close(s);

	return 0;
}
