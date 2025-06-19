debug:
	gcc -o ink main.c kickstart.c -g -Wall

build:
	gcc -o ink main.c kickstart.c

test:
	./ink -o memory memory.ink
