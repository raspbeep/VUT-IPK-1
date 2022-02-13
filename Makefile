CC = gcc
CFLAGS = -std=c99 -Werror -Wall -Wextra -pedantic
EXEC = hinfosvc
TARGETS = Makefile errno.h hinfosvc.c Readme.md
PACK = xkrato61

all:
	$(CC) hinfosvc.c -o $(EXEC) -Wall -Wextra -pedantic -Werror

pack:
	zip $(PACK) $(TARGETS)

clean:
	rm -rf hinfosvc $(PACK).zip $(PACK)