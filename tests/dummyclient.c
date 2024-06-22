#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

void die(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

int
main()
{
	int sockfd;
	struct sockaddr_in server;
	char buf[5] = { 0 };
	ssize_t nbytes;
	pid_t pid;

	/* Fork in order to test proxybind's capabilities of intercepting sub-child processes */
	pid = fork();
	if (pid == -1)
		die("failed to fork");
	else if (pid != 0)
		return 0;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		die("failed to create socket");
	}

	printf("client socket fd: %d\n", sockfd);

	server.sin_addr.s_addr = inet_addr("127.0.0.1");
	server.sin_family = AF_INET;
	server.sin_port = htons(1337);

	if (connect(sockfd, (struct sockaddr *)&server, sizeof(server))) {
		printf("client socket port after connect: %d\n", server.sin_port);
		die("failed to connect to server");
	}

	if ((nbytes = send(sockfd, "ping", 4, 0)) == -1) {
		die("failed to send message to the server");
	}
	printf("sent '%zd' bytes to the server (expected: 4)\n", nbytes);

	if (recv(sockfd, buf, sizeof(buf) - sizeof(buf[0]), 0) <= 0) {
		die("failed to receive message from the server");
	}
	printf("%s\n", buf);

	close(sockfd);
}
