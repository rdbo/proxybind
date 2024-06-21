proxybind: setup
	$(CXX) -o build/proxybind src/*.cpp
	$(CC) -o build/dummyclient tests/dummyclient.c

setup:
	mkdir -p build
