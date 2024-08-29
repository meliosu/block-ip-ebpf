all: firewall

firewall: firewall.bpf.o firewall.skel.h
	clang -O2 -g -o firewall firewall.c -lbpf -lxdp

firewall.skel.h: firewall.bpf.o
	bpftool gen skeleton firewall.bpf.o > firewall.skel.h

firewall.bpf.o:
	clang -O2 -g -target bpf -c firewall.bpf.c


clean:
	rm firewall firewall.bpf.o firewall.skel.h
