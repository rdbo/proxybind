proxybind: setup
	$(CC) -o build/proxybind src/proxybind.c
	$(CC) -o build/dummyclient tests/dummyclient.c

setup:
	mkdir -p build
