CLANG    	:= clang
CC       	:= gcc
CFLAGS   	:= -O2 -g
KVER 	 	:= $(shell uname -r)
KBASE 	 	:= $(shell echo $(KVER) | sed 's/-generic//')
BPF_CFLAGS 	:= -O2 -g -target bpf -D__TARGET_ARCH_x86 \
              -I/usr/src/linux-headers-$(KVER)/include \
              -I/usr/src/linux-headers-$(KBASE)/include \
              -I/usr/include \
              -I/usr/include/x86_64-linux-gnu
NIC 		:= enp0s3      

all: cms_kern.o cms_user

cms_kern.o: cms_kern.c cms.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

cms_user: cms_user.c cms.h
	$(CC) $(CFLAGS) $< -o $@ -lbpf -lelf -lz

clean:
	rm -f cms_kern.o cms_user

load: cms_kern.o cms_user
	sudo ./cms_user ${NIC}

.PHONY: all clean load