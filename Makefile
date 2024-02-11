proxybind: setup
	$(CC) -o build/proxybind src/proxybind.c

setup:
	mkdir -p build
