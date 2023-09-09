#include <ctime>
#include<chrono>
#include <errno.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include <thread>

// #include "../uapi_linux_dcpim.h"
#include "test_utils.h"
#ifndef ETH_MAX_MTU
#define ETH_MAX_MTU	0xFFFFU
#endif

#ifndef UDP_SEGMENT
#define UDP_SEGMENT		103
#endif

/* Determines message size in bytes for tests. */
int length = 1000000;

/* How many iterations to perform for the test. */
int count = 100;

/* Used to generate "somewhat random but predictable" contents for buffers. */
int seed = 12345;

/**
 * close_fd() - Helper method for "close" test: sleeps a while, then closes
 * an fd
 * @fd:   Open file descriptor to close.
 */
void close_fd(int fd)
{
	// sleep(1);
	if (close(fd) >= 0) {
		printf("Closed fd %d\n", fd);
	} else {
		printf("Close failed on fd %d: %s\n", fd, strerror(errno));
	}
}

/**
 * print_help() - Print out usage information for this program.
 * @name:   Name of the program (argv[0])
 */
void print_help(const char *name)
{
	printf("Usage: %s host:port [options] op op ...\n\n"
		"host:port describes a server to communicate with, and each op\n"
		"selects a particular test to run (see the code for available\n"
		"tests). The following options are supported:\n\n"
		"--count      Number of times to repeat a test (default: 1000)\n"
		"--length     Size of messages, in bytes (default: 100)\n"
		"--sp       src port of connection \n"
		"--seed       Used to compute message contents (default: 12345)\n",
		name);
}

void test_dcpimping(int fd, struct sockaddr *dest, char* buffer)
{
	// struct sockaddr_in* in = (struct sockaddr_in*) dest;
	uint32_t buffer_size = 62580;
	// uint32_t flow_size = 3000000000;
	uint32_t write_len = 0;
	uint64_t start, end;
	uint64_t cycles_per_sec = get_cycles_per_sec();
		if (connect(fd, dest, sizeof(struct sockaddr_in)) == -1) {
			printf("Couldn't connect to dest %s\n", strerror(errno));
			exit(1);
		}
		start = rdtsc();
	    // for (int i = 0; i < count * 100; i++) {
		while(1) {
			int result = write(fd, buffer, buffer_size);
			if( result < 0 ) {
				printf("result:%d\n", result);
				break;
			} else {
				write_len += result;
			}
			end = rdtsc();
			if(end - start > cycles_per_sec * 120)
				break;
		}

}

void test_dcpim_tx_messages(int fd, struct sockaddr *dest, char* buffer)
{
	// struct sockaddr_in* in = (struct sockaddr_in*) dest;
	uint32_t buffer_size = 64;
	// uint32_t flow_size = 3000000000;
	uint32_t write_len = 0;
	uint64_t start, end;
	uint64_t cycles_per_sec = get_cycles_per_sec();
  	int priority = 7;
	int flag = 1;
  	if(setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority)) < 0){
		printf("set priority failed\n");
	}
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int));
	setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &flag, sizeof(int));

	if (connect(fd, dest, sizeof(struct sockaddr_in)) == -1) {
		printf("Couldn't connect to dest %s\n", strerror(errno));
		exit(1);
	}
	printf("connect done\n");
	start = rdtsc();

	while(1) {
		int result = write(fd, buffer, buffer_size);
		if( result < 0 ) {
			break;
		} else {
			write_len += result;
		}
		end = rdtsc();
		if(end - start > cycles_per_sec * 120)
			break;
	}
	sleep(100);
}

int main(int argc, char** argv)
{
	int port, nextArg, tempArg;
	struct sockaddr_in addr_in;
	struct addrinfo *matching_addresses;
	struct sockaddr *dest;
	struct addrinfo hints;
	char *host, *port_name;
	char buffer[1000000] = "abcdefgh\n";
	// int cpu_list[15] = {0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56};
	bool pin = false;
	buffer[63999] = 'H';
	int status;
	int fd;
	int i;
	int srcPort = 0;
	if ((argc >= 2) && (strcmp(argv[1], "--help") == 0)) {
		print_help(argv[0]);
		exit(0);
	}
	
	if (argc < 3) {
		printf("Usage: %s host:port [options] op op ...\n", argv[0]);
		exit(1);
	}
	host = argv[1];
	port_name = strchr(argv[1], ':');
	if (port_name == NULL) {
		printf("Bad server spec %s: must be 'host:port'\n", argv[1]);
		exit(1);
	}
	*port_name = 0;
	port_name++;
	port = get_int(port_name,
			"Bad port number %s; must be positive integer\n");
	for (nextArg = 2; (nextArg < argc) && (*argv[nextArg] == '-');
			nextArg += 1) {
		if (strcmp(argv[nextArg], "--help") == 0) {
			print_help(argv[0]);
			exit(0);
		} else if (strcmp(argv[nextArg], "--pin") == 0) {
			pin = true;
        } else if (strcmp(argv[nextArg], "--count") == 0) {
			if (nextArg == (argc-1)) {
				printf("No value provided for %s option\n",
					argv[nextArg]);
				exit(1);
			}
			nextArg++;
			count = get_int(argv[nextArg],
					"Bad count %s; must be positive integer\n");
		} else if (strcmp(argv[nextArg], "--length") == 0) {
			if (nextArg == (argc-1)) {
				printf("No value provided for %s option\n",
					argv[nextArg]);
				exit(1);
			}
			nextArg++;
			length = get_int(argv[nextArg],
				"Bad message length %s; must be positive "
				"integer\n");
			if (length > 1000000) {
				length = 1000000;
				printf("Reducing message length to %d\n", length);
			}
		} else if (strcmp(argv[nextArg], "--sp") == 0) {
			if (nextArg == (argc-1)) {
				printf("No value provided for %s option\n",
					argv[nextArg]);
				exit(1);
			}
			nextArg++;
			srcPort = get_int(argv[nextArg],
				"Bad srcPort %s; must be positive integer\n");
		} else {
			printf("Unknown option %s; type '%s --help' for help\n",
				argv[nextArg], argv[0]);
			exit(1);
		}
	}
	if(pin) {
			cpu_set_t cpuset;
			pthread_t current_thread = pthread_self();
			CPU_ZERO(&cpuset);
			CPU_SET(srcPort % 16 * 4, &cpuset);
			pthread_setaffinity_np(current_thread, sizeof(cpu_set_t), &cpuset);
	}
	// get destination address
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	status = getaddrinfo(host, "80", &hints, &matching_addresses);
	if (status != 0) {
		printf("Couldn't look up address for %s: %s\n",
				host, gai_strerror(status));
		exit(1);
	}
	dest = matching_addresses->ai_addr;
	((struct sockaddr_in *) dest)->sin_port = htons(port);
	// int *ibuf = reinterpret_cast<int *>(buffer);
	// ibuf[0] = ibuf[1] = length;
	// seed_buffer(&ibuf[2], sizeof32(buffer) - 2*sizeof32(int), seed);
	tempArg = nextArg;
	for(i = 0; i < count; i++) {
		nextArg = tempArg;

		printf("nextArg:%d\n", nextArg);
		fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_DCPIM);
		if (fd < 0) {
			printf("Couldn't open DCPIM socket: %s\n", strerror(errno));
		}
		// int option = 1;
		// if (setsockopt(fd, SOL_DCPIM, SO_NO_CHECK, (void*)&option, sizeof(option))) {
		// 	return -1;
		// }
		memset(&addr_in, 0, sizeof(addr_in));
		addr_in.sin_family = AF_INET;
		addr_in.sin_port = htons(srcPort + i);
		addr_in.sin_addr.s_addr = inet_addr("192.168.11.124");

		for ( ; nextArg < argc; nextArg++) {
			 if (strcmp(argv[nextArg], "dcpimping") == 0) {
				printf("call dcpimping\n");
				if (bind(fd, (struct sockaddr *) &addr_in, sizeof(addr_in)) != 0) {
					printf("Couldn't bind socket to DCPIM port %d: %s\n", srcPort,
							strerror(errno));
					return -1;
				}
				test_dcpimping(fd, dest, buffer);
			} else if (strcmp(argv[nextArg], "dcpimpingmsg") == 0) {
				printf("call dcpimmsg\n");
				if (bind(fd, (struct sockaddr *) &addr_in, sizeof(addr_in)) != 0) {
					printf("Couldn't bind socket to DCPIM port %d: %s\n", srcPort,
							strerror(errno));
					return -1;
				}
				test_dcpim_tx_messages(fd, dest, buffer);
			} else if (strcmp(argv[nextArg], "tcpping") == 0) {
				int reuse = 1;
                fd = socket(AF_INET, SOCK_STREAM, 0);
				if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0)
   					perror("setsockopt(SO_REUSEADDR) failed");
				if (bind(fd, (struct sockaddr *) &addr_in, sizeof(addr_in)) != 0) {
					printf("Couldn't bind socket to TCP port %d: %s\n", srcPort,
							strerror(errno));
					return -1;
				}
				printf("call tcpping\n");
            	test_dcpimping(fd, dest, buffer);
            }
			 else {
				printf("Unknown operation '%s'\n", argv[nextArg]);
				exit(1);
			}
		}
		close(fd);
	}

	exit(0);
}

