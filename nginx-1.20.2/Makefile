
default:	build

clean:
	rm -rf Makefile objs

.PHONY:	default clean

build:
	$(MAKE) -f objs/Makefile

install:
	$(MAKE) -f objs/Makefile install

modules:
	$(MAKE) -f objs/Makefile modules

upgrade:
	/usr/local/nginx/sbin/nginx -t

	kill -USR2 `cat /home/zzxy1999/nginx/nginx.pid`
	sleep 1
	test -f /home/zzxy1999/nginx/nginx.pid.oldbin

	kill -QUIT `cat /home/zzxy1999/nginx/nginx.pid.oldbin`

.PHONY:	build install modules upgrade
