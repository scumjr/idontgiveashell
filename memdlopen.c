#include <err.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "memdlopen.h"

#define MAGIC_FD	0x66
#define MAGIC_SO	"magic.so"
//#define DEBUG

/* push rbp; mov rbp,rsp; movabs rax,0x0000000000000000; call rax; leave; ret */
#define STUB	"\x55\x48\x89\xe5\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xd0\xc9\xc3"

#ifdef DEBUG
#define log(M, ...) do {						\
	const char *file;						\
	if (strrchr(__FILE__, '/') != NULL)				\
		file = strrchr(__FILE__, '/') + 1;			\
	else								\
		file = __FILE__;					\
	fprintf(stdout, "[%s:%d] " M "\n", file, __LINE__, ##__VA_ARGS__); \
	} while (0)
#else
#define log(M, ...) do {} while (0)
#endif

#define error(M, ...) do {						\
	const char *file;						\
	if (strrchr(__FILE__, '/') != NULL)				\
		file = strrchr(__FILE__, '/') + 1;			\
	else								\
		file = __FILE__;					\
	fprintf(stdout, "[%s:%d] " M "%s\n", file, __LINE__, ##__VA_ARGS__, strerror(errno)); \
	} while (0)

#define MY_FUNCTION(name)	static typeof(*name) my_##name

MY_FUNCTION(open);
MY_FUNCTION(lseek);
MY_FUNCTION(read);
MY_FUNCTION(mmap);
MY_FUNCTION(__fxstat);
MY_FUNCTION(close);

#define STR(s)		#s
#define XSTR(s)		STR(s)
#define PATCH(name)	{		\
	name##_pattern,			\
	sizeof(name##_pattern)-1,	\
	XSTR(name),			\
	(uint64_t)&my_##name		\
}

static struct patch {
	const char *pattern;
	const size_t length;
	const char *symbol;
	uint64_t replacement_addr;
} patches[] = {
	PATCH(read),
	PATCH(mmap),
	PATCH(lseek),
	PATCH(__fxstat),
	PATCH(close),
	PATCH(open),
	{ NULL, 0, NULL, 0 },
};

static struct lib_t {
	void *data;
	size_t size;
	size_t current;
} libdata;

static size_t page_size;


static int my_open(const char *pathname, int flags, ...)
{
	log("in my_open");

	if (strstr(pathname, MAGIC_SO) == NULL)
		return open(pathname, flags);

	log("magic open requested, fd is 0x%x", MAGIC_FD);

	return MAGIC_FD;
}

static off_t my_lseek(int fd, off_t offset, int whence)
{
	log("in my_lseek, fd is 0x%x", fd);

	if (fd != MAGIC_FD)
		return lseek(fd, offset, whence);

	switch (whence) {
	case SEEK_SET:
		libdata.current = offset;
		break;
	case SEEK_CUR:
		libdata.current += offset;
		break;
	case SEEK_END:
		libdata.current = libdata.size + offset;
		break;
	default:
		break;
	}

	log("current offset = %ld", libdata.current);

	return libdata.current;
}

static ssize_t my_read(int fd, void *buf, size_t count)
{
	size_t size;

	log("in my_read, fd is 0x%x", fd);

	if (fd != MAGIC_FD)
		return read(fd, buf, count);

	if (libdata.size - libdata.current >= count)
		size = count;
	else
		size = libdata.size - libdata.current;

	log("magic read, requested size : %ld, i will read %ld", count, size);

	memcpy(buf, libdata.data + libdata.current, size);
	libdata.current += size;

	return size;
}

static void *my_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	int mflags;
	void *p;

	log("in my mmap, fd is 0x%x", fd);

	if (fd != MAGIC_FD)
		return mmap(addr, length, prot, flags, fd, offset);

	log("length is %d / flags = %d", (int)length, flags);
	//  0x802 : MAP_PRIVATE,MAP_DENYWRITE
	//  0x812 : MAP_PRIVATE,MAP_FIXED,MAP_DENYWRITE
	mflags = MAP_PRIVATE | MAP_ANON;
	if (flags & MAP_FIXED)
		mflags |= MAP_FIXED;

	p = mmap(addr, length, PROT_READ|PROT_WRITE|PROT_EXEC, mflags, -1, 0);
	if (p == MAP_FAILED)
		err(1, "mmap");

	memcpy(p, libdata.data, length > libdata.size ? libdata.size : length);

	log("mmap : [0x%lx,0x%lx]", (uint64_t)p, (uint64_t)p+length);

	return p;
}

static int my___fxstat(int stat_ver, int fd, struct stat *buf)
{
	log("in my fstat, fd is 0x%x", fd);

	if (fd != MAGIC_FD)
		return __fxstat(stat_ver, fd, buf);

	log("magic fstat requested");

	memset(buf, 0, sizeof(struct stat));
	buf->st_size = libdata.size;
	buf->st_ino = 0x666;

	return 0;
}

static int my_close(int fd)
{
	log("in my close, fd is 0x%x", fd);

	if (fd != MAGIC_FD)
		return close(fd);

	log("magic close requested");

	return 0;
}

static bool search_and_patch(uint64_t start_addr, uint64_t end_addr, struct patch *patch)
{
	uint64_t addr, symbol_addr;
	size_t stub_length;
	void *page_addr;
	int32_t offset;
	bool found;
	char *code;

	found = false;
	for (addr = start_addr; addr + patch->length < end_addr; addr++) {
		if (memcmp((void *)addr, patch->pattern, patch->length) == 0) {
			log("found %s candidate @ 0x%lx", patch->symbol, addr);
			found = true;
			break;
		}
	}

	if (!found)
		return false;

	offset = *((uint64_t *)(addr + patch->length));
	symbol_addr = addr + patch->length + 4 + offset;

	log("offset is %d, %s addr is 0x%lx", offset, patch->symbol, symbol_addr);
	log("my_%s is @ 0x%lx", patch->symbol, patch->replacement_addr);

	stub_length = sizeof(STUB)-1;
	code = malloc(stub_length);
	if (code == NULL)
		err(1, "malloc");

	memcpy(code, STUB, stub_length);
	memcpy(code + 6, &patch->replacement_addr, sizeof(uint64_t));

	// changing page protection before writting
	page_addr = (void *)(symbol_addr & ~(page_size - 1));

	if (mprotect(page_addr, page_size, PROT_READ | PROT_WRITE) != 0)
		err(1, "mprotect");

	memcpy((void *)symbol_addr, code, stub_length);

	if (mprotect(page_addr, page_size, PROT_READ | PROT_EXEC) != 0)
		err(1, "mprotect");

	return true;
}

static bool find_ld_in_memory(uint64_t *addr1, uint64_t *addr2)
{
	char *tmp, *start, *end;
	char buffer[1024];
	bool found;
	FILE *f;

	f = fopen("/proc/self/maps", "r");
	if (f == NULL)
		err(1, "fopen(\"/proc/self/maps\")");

	found = false;
	*addr1 = 0;
	*addr2 = 0;
	while (fgets(buffer, sizeof(buffer), f)){
		if (strstr(buffer, "r-xp") == NULL)
			continue;

		if (strstr(buffer, "ld-2.19.so") == NULL)
			continue;

		buffer[strlen(buffer)-1] = 0;
		tmp = strrchr(buffer, ' ');
		if (tmp == NULL || tmp[0] != ' ')
			continue;
		++tmp;

		start = strtok(buffer, "-");
		*addr1 = strtoul(start, NULL, 16);
		end = strtok(NULL, " ");
		*addr2 = strtoul(end, NULL, 16);

		log("found ld : [%lx,%lx]", *addr1, *addr2);
		found = true;
	}

	fclose(f);

	return found;
}

int memdlopen_init(void)
{
	uint64_t end, start;
	struct patch *p;

	page_size = sysconf(_SC_PAGESIZE);

	log("starting (pid=%d)", getpid());

	if (!find_ld_in_memory(&start, &end)) {
		error("failed to find ld in memory");
		return 2;
	}

	for (p = patches; p->pattern != NULL; p++) {
		if (!search_and_patch(start, end, p)) {
			warnx("failed to patch %s", p->symbol);
			return 3;
		}
	}

	return 0;
}

void memdlopen(size_t size, void *data)
{
	libdata.size = size;
	libdata.data = data;
	libdata.current = 0;

	log("dlopen adress is @ 0x%lx", (uint64_t)dlopen);
	if (dlopen("./" MAGIC_SO, RTLD_LAZY) == NULL) {
		error("[-] failed to dlopen : %s", dlerror());
		exit(1);
	}
}
