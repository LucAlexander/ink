debug:
	gcc -o ink main.c kickstart.c -g -Wall

build:
	gcc -o ink main.c kickstart.c

clean:
	rm *.ink.c
	rm *.ink.h
