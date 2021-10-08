all:
	${CC} -L/usr/local/lib/ -o dasm dasm.c -lkeystone 

static:
	${CXX} -L/usr/local/lib/ -o dasm dasm.c -lkeystone --static

clean:
	rm -rf *.o dasm 
