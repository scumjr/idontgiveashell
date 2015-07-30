CFLAGS := -W -Wall -Wextra -Wfatal-errors -O3
LDFLAGS := -ldl
EXEC := idontgiveashell libexample.so

all: $(EXEC)

idontgiveashell: idontgiveashell.o memdlopen.o
	$(CC) -o $@ $^ $(LDFLAGS)

libexample.so: libexample.c
	$(CC) -o $@ $< -shared -fPIC

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

clean:
	rm -f $(EXEC) *.o
