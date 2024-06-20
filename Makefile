proxybind: setup
	$(CC) -o build/proxybind src/*.c
	$(CC) -o build/dummyclient tests/dummyclient.c

setup:
	mkdir -p build
