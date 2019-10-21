all: ../server

../server: server.c
	${CC} -lseccomp -o $@ $<

clean:
	rm -f server server.o
