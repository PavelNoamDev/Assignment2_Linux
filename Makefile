obj-m += KBlocker.o

all: KBlockerUM
	make -C /lib/modules/`uname -r`/build M=$(PWD) modules

KBlockerUM: KBlockerUM.c
	gcc -o KBlockerUM KBlockerUM.c

clean:
	make -C /lib/modules/`uname -r`/build M=$(PWD) clean
	rm KBlockerUM