CC = gcc
CFLAGS = -Wall -lpthread

svsocks : svsocks.c
	$(CC) $(CFLAGS) -o svsocks svsocks.c

.PHONY : clean
clean :
	rm -f svsocks
