# 编译 BPF 程序
clang -O2 -target bpf -g   -c kernel/main.c -o build/test.o
# 编译用户空间程序
gcc -o build/build user/main.c user/proxy.c -lbpf 

sudo ./build/build