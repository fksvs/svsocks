CC = gcc
CFLAGS = -Wall -Werror -Wpedantic -lpthread

svsocks : svsocks.c
	$(CC) $(CFLAGS) -o svsocks svsocks.c

.PHONY : clean
clean :
	rm -f svsocks
