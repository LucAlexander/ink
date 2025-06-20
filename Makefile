debug:
	gcc -o ink main.c kickstart.c -g -Wall

build:
	gcc -o ink main.c kickstart.c

test:
	./ink -o funret funret.ink
	#./ink -o funarg funarg.ink
	#./ink -o partial partial.ink
	#./ink -o memory memory.ink
	#./ink -o hello hello.ink

clean:
	rm *.ink.c
	rm *.ink.h
