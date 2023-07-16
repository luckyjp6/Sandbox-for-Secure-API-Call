all: sandbox.so
	./launcher ./sandbox.so config.txt python3 -c 'import os;os.system("wget http://www.google.com -q -t 1")'
sandbox.so: sandbox.c
	gcc -o sandbox.so -shared -fPIC sandbox.c -ldl
test:
	gcc sandbox.c -o sandbox -g
	./sandbox
pwn:
	. ~/pwntools/bin/activate

testc:
	gcc test.c -o test
	./test
clean:
	rm *.log
	rm *.html*