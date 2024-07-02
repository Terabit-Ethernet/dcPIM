// This file contains a collection of tests for the Linux implementation
// of dcPIM
//
#include <cassert>
#include <ctime>
#include<chrono>
#include <errno.h>
#include <iostream>
#include <fstream>
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
#include <sys/syscall.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <inttypes.h>
#include <vector>
#include <queue>
#include <thread>
#include <list>
#include <mutex>          // std::mutex
#include <condition_variable> // std::condition_variable
#include <sched.h>
//#include "../uapi_linux_nd.h"
#include "test_utils.h"
// #include "../uapi_linux_dcpim.h"
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

// std::queue<uint64_t> time_q;
std::mutex mtx;           // mutex for critical section
std::condition_variable cv;
// bool queue_available() {return time_q.size() < (long unsigned int)limit;}
volatile int stop_count;
std::string protocol = "dcpim";
/**
 * close_fd() - Helper method for "close" test: sleeps a while, then closes
 * an fd
 * @fd:   Open file descriptor to close.
 */
void close_fd(int fd)
{
	// sleep(1);
	if (close(fd) >= 0) {
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


void test_ping_send(struct sockaddr *dest, int id, int io_depth, int flow_size, int src_port)
{

	std::queue<uint64_t> time_q;
	char *buffer = (char*)malloc(1000000);
	int fd;
	unsigned int cpu, node;
	// uint64_t flow_size = 10000000000000;
	// int times = 100;
	int flag = 0;
	std::vector<double> latency;
	uint64_t write_len = 0;
	uint64_t start_time = rdtsc();
	uint64_t end = rdtsc();
	uint64_t sent_bytes = 0;
	uint64_t max_size = 10000000;
	std::ofstream lfile, tfile;
	pid_t pid = syscall(__NR_gettid);
	struct sockaddr_in client;
	socklen_t clientsz = sizeof(client);
  	int priority = 7;
	client.sin_family = AF_INET;
	client.sin_port = htons(src_port);
	client.sin_addr.s_addr = INADDR_ANY;
//  	struct sched_param param;
// 	param.sched_priority = 99;
// 	sched_setscheduler(pid, SCHED_RR, &param);
	lfile.open("temp/netperf-" + std::to_string(id)+".log");
	tfile.open("temp/netperf-" + std::to_string(id)+"_thpt.log");
	//int q_depth = 64, count = 0;
	    // for (int i = 0; i < count * 100; i++) {
		/* init burst io_depth packet */
	if(protocol == "dcpim") {
		fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_DCPIM);
		/* set packet priority */
		if(setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority)) < 0){
			printf("set priority failed\n");
		}
	}
	else 
		fd = socket(AF_INET, SOCK_STREAM, 0);
	if (bind(fd, reinterpret_cast<sockaddr *>(&client), sizeof(client))
			== -1) {
		printf("Couldn't bind to port %d: %s\n", src_port, strerror(errno));
		exit(1);
	}
	if (connect(fd, dest, sizeof(struct sockaddr_in)) == -1) {
		printf("Couldn't connect to dest %s\n", strerror(errno));
		exit(1);
	}
	getsockname(fd, (struct sockaddr *) &client, &clientsz);
	getcpu(&cpu, &node);
	printf("cpu: %d pid: %d client port: %d\n", cpu, pid, ntohs(client.sin_port));
	int total = 0;
	int burst = io_depth;
	while(burst > 0) {
		total = 0;
		time_q.push(rdtsc());
		while(total < flow_size) {
			// if (burst == 1)
			// 	flag = MSG_EOR;
			// else
			// 	flag = MSG_MORE;
		//	printf("send time:%f\n", to_seconds(rdtsc()));
			int result = send(fd, buffer + total, flow_size - total, flag);
			if( result <= 0 ) {
				if(errno == EMSGSIZE) {
					printf("Socket write failed: %s %d\n", strerror(errno), result);
				}
				printf("send: %d\n", result);
				break;
			} else {
				write_len += result;
				total += result;
				sent_bytes += result;	

			}
		}
		burst--;
	}
	while(1) {
		end = rdtsc();
		/* receive one response */
		total = 0;
		while(total < flow_size) {
			int result = read(fd, buffer + total, flow_size - total);	
			if( result <= 0 ) {
				if(errno == EMSGSIZE) {
					printf("Socket write failed: %s %d\n", strerror(errno), result);
				}
				printf("read: %d\n", result);
				break;
			} else {
				total += result;
			}
			if(total == flow_size) {
				uint64_t start = time_q.front();
				end = rdtsc();
				latency.push_back(to_seconds(end - start));
				time_q.pop();
			}
		}
		/* send out one request */
		total = 0;
		time_q.push(rdtsc());
		total = 0;
		while(total < flow_size) {
			int result = send(fd, buffer + total, flow_size - total, flag);
			if( result <= 0 ) {
				if(errno == EMSGSIZE) {
					printf("Socket write failed: %s %d\n", strerror(errno), result);
				}
				printf("send: %d\n", result);
				break;
			} else {
				write_len += result;
				total += result;
				sent_bytes += result;	
			}
		}
		// time_q.push(end);
		if(stop_count == 1)
			break;
	
	}
	tfile <<   pid << " " << ntohs(client.sin_port) << " " << sent_bytes  / to_seconds(end - start_time) / flow_size  << std::endl;
	max_size = (latency.size() > max_size) ? max_size : latency.size();
	for(uint32_t i = 0; i < max_size; i++) {
		lfile << "finish time: " << latency[i] << "\n"; 
		// std::cout << "finish time: " << latency[i] << "\n"; 
	}
	lfile.close();
	tfile.close();
	close(fd);
}

void test_ping_oneside_send(struct sockaddr *dest, int id, int io_depth, int flow_size, int src_port)
{

	std::queue<uint64_t> time_q;
	char *buffer = (char*)malloc(1000000);
	int fd;
	unsigned int cpu, node;
	// uint64_t flow_size = 10000000000000;
	// int times = 100;
	int flag = 0;
	std::vector<double> latency;
	uint64_t write_len = 0;
	uint64_t start_time = rdtsc();
	uint64_t end = rdtsc();
	uint64_t sent_bytes = 0;
	uint64_t max_size = 1000000;
	std::ofstream lfile, tfile;
	pid_t pid = syscall(__NR_gettid);
	struct sockaddr_in client;
	socklen_t clientsz = sizeof(client);
  	int priority = 7;
	int total = 0;
	struct timespec current_time;
	client.sin_family = AF_INET;
	client.sin_port = htons(src_port);
	client.sin_addr.s_addr = INADDR_ANY;
	long long nanoseconds = 0;
//  	struct sched_param param;
// 	param.sched_priority = 99;
// 	sched_setscheduler(pid, SCHED_RR, &param);
//	lfile.open("temp/netperf-" + std::to_string(id)+".log");
	tfile.open("temp/netperf-" + std::to_string(id)+"_thpt.log");
	//int q_depth = 64, count = 0;
	    // for (int i = 0; i < count * 100; i++) {
		/* init burst io_depth packet */
	if(protocol == "dcpim") {
		fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_DCPIM);
		/* set packet priority */
		if(setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority)) < 0){
			printf("set priority failed\n");
		}
	}
	else {
		fd = socket(AF_INET, SOCK_STREAM, 0);
		flag = 1;
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int));
		setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &flag, sizeof(int));
		flag = 0;
		setsockopt(fd, IPPROTO_TCP, TCP_CORK, &flag, sizeof(int));
		flag = 1;
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(int));
		printf("set nodelay quickack\n");
	}
	if (bind(fd, reinterpret_cast<sockaddr *>(&client), sizeof(client))
			== -1) {
		printf("Client couldn't bind to port %d: %s\n", src_port, strerror(errno));
		exit(1);
	}
	if (connect(fd, dest, sizeof(struct sockaddr_in)) == -1) {
		printf("Couldn't connect to dest %s\n", strerror(errno));
		exit(1);
	}
	getsockname(fd, (struct sockaddr *) &client, &clientsz);
	getcpu(&cpu, &node);
	printf("cpu: %d pid: %d client port: %d\n", cpu, pid, ntohs(client.sin_port));
	// sleep(0.05);

	while(1) {
		end = rdtsc();
		/* receive one response */
		total = 0;
		// sleep(0.05);
		/* Read the current time from CLOCK_REALTIME */
    	if (clock_gettime(CLOCK_REALTIME, &current_time) != 0) {
        	perror("clock_gettime");
        	break;
   		}
		flag = 0;
		nanoseconds = (long long)current_time.tv_sec * 1000000000 + (long long)current_time.tv_nsec;
		*(long long*)buffer = nanoseconds;
		while(total < flow_size) {
			int result = send(fd, buffer + total, flow_size - total, flag);
			if( result <= 0 ) {
				if(errno == EMSGSIZE) {
					printf("Socket write failed: %s %d\n", strerror(errno), result);
				}
				printf("send: %d %d \n", result, errno);
				break;
			} else {
				write_len += result;
				total += result;
				sent_bytes += result;	
			}
		}
		// time_q.push(end);
		if(stop_count == 1) {
			printf("stop count is 1\n");
			break;
		}

	}
	tfile <<   pid << " " << ntohs(client.sin_port) << " " << sent_bytes  / to_seconds(end - start_time) / flow_size  << std::endl;
	max_size = (latency.size() > max_size) ? max_size : latency.size();
//	for(uint32_t i = 0; i < max_size; i++) {
//		lfile << "finish time: " << latency[i] << "\n"; 
		// std::cout << "finish time: " << latency[i] << "\n"; 
//	}
//	lfile.close();
	tfile.close();
	close(fd);
	printf("client close socket\n");

}

void tcp_shortflow(struct sockaddr dest, int id, int io_depth, int flow_size, unsigned size_limit)
{

	std::queue<uint64_t> time_q;
	char *buffer = (char*)malloc(1000000);
	int fd;
	// unsigned size_limit = 200;
	// unsigned int cpu, node;
	// uint64_t flow_size = 10000000000000;
	// int times = 100;
	int flag = 0;
	std::list<int> fd_list;
	uint64_t write_len = 0;
	uint64_t start_time = rdtsc();
	uint64_t end = rdtsc();
	uint64_t sent_bytes = 0;
	// uint64_t max_size = 1000000;
	std::ofstream lfile, tfile;
	pid_t pid = syscall(__NR_gettid);
	// struct sockaddr_in client;
	// socklen_t clientsz = sizeof(client);
  	int priority = 7;
    int reuse = 1;
	int total = 0, valread = 0;
	struct timespec current_time;
	long long nanoseconds = 0;
	int i = 0;
//  	struct sched_param param;
// 	param.sched_priority = 99;
// 	sched_setscheduler(pid, SCHED_RR, &param);
//	lfile.open("temp/netperf-" + std::to_string(id)+".log");
	tfile.open("temp/netperf-" + std::to_string(id)+"_thpt.log");
	//int q_depth = 64, count = 0;
	    // for (int i = 0; i < count * 100; i++) {
		/* init burst io_depth packet */
	while(1) {
		if(protocol == "dcpim") {
			fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_DCPIM);
			/* set packet priority */
			if(setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority)) < 0){
				printf("set priority failed\n");
			}
		}
		else {
			fd = socket(AF_INET, SOCK_STREAM, 0);
			flag = 1;
			setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int));
			setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &flag, sizeof(int));
			flag = 0;
			setsockopt(fd, IPPROTO_TCP, TCP_CORK, &flag, sizeof(int));
		}
		// client.sin_family = AF_INET;
		// client.sin_port = htons(src_port + i % size_limit);
		// client.sin_addr.s_addr = INADDR_ANY;
		// printf("called bind port: %d\n", src_port + i % size_limit);
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
			perror("setsockopt(SO_REUSEADDR) failed");
			exit(1);
		}
		// if (bind(fd, reinterpret_cast<sockaddr *>(&client), sizeof(client))
		// 		== -1) {
		// 	printf("Couldn't bind to port %d: %s\n", src_port + i % size_limit, strerror(errno));
		// 	exit(1);
		// }
		/* Read the current time from CLOCK_REALTIME */
		if (clock_gettime(CLOCK_REALTIME, &current_time) != 0) {
			perror("clock_gettime");
			break;
		}
		nanoseconds = (long long)current_time.tv_sec * 1000000000 + (long long)current_time.tv_nsec;
		if (connect(fd, &dest, sizeof(struct sockaddr_in)) == -1) {
			break;
			printf("Couldn't connect to dest %s\n", strerror(errno));
		}
		// sleep(0.05);
		end = rdtsc();
		/* receive one response */
		total = 0;
		// sleep(0.05);
		flag = 0;
		*(long long*)buffer = nanoseconds;
		while(total < flow_size) {
			int result = send(fd, buffer + total, flow_size - total, flag);
			if( result <= 0 ) {
				if(errno == EMSGSIZE) {
					printf("Socket write failed: %s %d\n", strerror(errno), result);
				}
				break;
			} else {
				write_len += result;
				total += result;
				sent_bytes += result;	
			}
		}
		fd_list.push_back(fd);
		// time_q.push(end);
		if(stop_count == 1) {
			break;
		}
		while(fd_list.size() == size_limit) {
			fd = fd_list.front();
			valread = read(fd, buffer, 1);
			if(valread < 1) {
				close(fd);
				fd_list.pop_front();
				// printf("close fd: %d\n", fd);
			}
		}
		i += 1;
	}
	tfile <<   pid << " "  << sent_bytes  / to_seconds(end - start_time) / flow_size  << std::endl;
	while(fd_list.size() > 0) {
		fd = fd_list.front();
		valread = read(fd, buffer, 1);
		if(valread < 1) {
			close(fd);
			fd_list.pop_front();
			// printf("close fd: %d\n", fd);
		}
	}
	// max_size = (latency.size() > max_size) ? max_size : latency.size();
//	for(uint32_t i = 0; i < max_size; i++) {
//		lfile << "finish time: " << latency[i] << "\n"; 
		// std::cout << "finish time: " << latency[i] << "\n"; 
//	}
//	lfile.close();
	tfile.close();
	close(fd);
}
// /**
//  * tcp_pingping() - Handles messages arriving on a given socket.
//  * @fd:           File descriptor for the socket over which messages
//  *                will arrive.
//  * @client_addr:  Information about the client (for messages).
//  */
// void test_tcppingpong(int fd, struct sockaddr *dest, int id)
// {
// 	// int flag = 1;
// 	// int times = 90;
// 	char buffer[5000];
// 	std::ofstream file;
// 	file.open("result_tcp_pingpong_"+ std::to_string(id));
// 	// int cur_length = 0;
// 	// bool streaming = false;
// 	uint64_t count = 0;
// 	// uint64_t total_length = 0;
// 	// uint64_t start_time;
// 	std::vector<double> latency;
// 	printf("reach here1\n");
// 	if (connect(fd, dest, sizeof(struct sockaddr_in)) == -1) {
// 		printf("Couldn't connect to dest %s\n", strerror(errno));
// 		exit(1);
// 	}
// 	// start_time = rdtsc();
// 	while (1) {
// 		int copied = 0;
// 		int rpc_length = 4096;
// 		// times--;
// 		// if(times == 0)
// 		// 	break;
// 		uint64_t start = rdtsc(), end;
// 		while(1) {
// 			int result = write(fd, buffer + copied,
// 				rpc_length);
// 			if (result <= 0) {
// 				printf("goto close\n");
// 					goto close;
// 			}
// 			rpc_length -= result;
// 			copied += result;
// 			if(rpc_length == 0)
// 				break;
// 			// return;
// 		}
// 		copied = 0;
// 		rpc_length = 4096;
// 		while(1) {
// 			int result = read(fd, buffer + copied,
// 				rpc_length);
// 			if (result <= 0) {
// 					printf("goto close2\n");
// 					goto close;
// 			}
// 			// printf("result:%d\n",result);
// 			// printf("receive rpc times:%d \n", times);
// 			rpc_length -= result;
// 			copied += result;
// 			if(rpc_length == 0)
// 				break;
// 			// return;
// 		}
// 		end = rdtsc();
// 		latency.push_back(to_seconds(end-start));
// 		// printf("finsh time: %f cycles:%lu\n",  to_seconds(end-start), end-start);
// 		if(stop_count == 1)
// 			break;
// 	//	if (total_length <= 8000000)
// 	//	 	printf("buffer:%s\n", buffer);
// 		count++;

// 	}
// 		// printf( "total len:%" PRIu64 "\n", total_length);
// 		// printf("done!");
// close:
// 	sleep(10);

// 	for(uint32_t i = 0; i < latency.size(); i++) {
// 		file << "finish time: " << latency[i] << "\n"; 
// 		// std::cout << "finish time: " << latency[i] << "\n"; 
// 	}
// 	file.close();
// 	close(fd);
// 	return;
// }

// /**
//  * nd_pingping() - Handles messages arriving on a given socket.
//  * @fd:           File descriptor for the socket over which messages
//  *                will arrive.
//  * @client_addr:  Information about the client (for messages).
//  */
// void test_ndpingpong(int fd, struct sockaddr *dest, int id)
// {
// 	// int flag = 1;
// 	int times = 90;
// 	// int cur_length = 0;
// 	// bool streaming = false;
// 	uint64_t count = 0;
// 	// uint64_t total_length = 0;
// 	char buffer[5000];
// 	std::ofstream file;
// 	file.open("result_nd_pingpong_"+ std::to_string(id));
// 	uint64_t start_time;
// 	std::vector<double> latency;
// 	printf("reach here1\n");
// 	if (connect(fd, dest, sizeof(struct sockaddr_in)) == -1) {
// 		printf("Couldn't connect to dest %s\n", strerror(errno));
// 		exit(1);
// 	}
// 	start_time = rdtsc();
// 	while (1) {
// 		int copied = 0;
// 		int rpc_length = 4096;
// 		// times--;
// 		// if(times == 0)
// 		// 	break;
// 		uint64_t start = rdtsc(), end;
// 		while(1) {
// 			int result = write(fd, buffer + copied,
// 				rpc_length);
// 			if (result <= 0) {
// 				printf("goto close\n");
// 					goto close;
// 			}
// 			rpc_length -= result;
// 			copied += result;
// 			if(rpc_length == 0)
// 				break;
// 			// return;
// 		}
// 		copied = 0;
// 		rpc_length = 4096;
// 		while(1) {
// 			int result = read(fd, buffer + copied,
// 				rpc_length);
// 			if (result <= 0) {
// 					printf("goto close2\n");
// 					goto close;
// 			}
// 			// printf("result:%d\n",result);
// 			// printf("receive rpc times:%d \n", times);
// 			rpc_length -= result;
// 			copied += result;
// 			if(rpc_length == 0)
// 				break;
// 			// return;
// 		}
// 		end = rdtsc();
// 		latency.push_back(to_seconds(end-start));
// 		// printf("finsh time: %f cycles:%lu\n",  to_seconds(end-start), end-start);
// 		if(to_seconds(end-start_time) > times)
// 			break;
// 	//	if (total_length <= 8000000)
// 	//	 	printf("buffer:%s\n", buffer);
// 		count++;

// 	}
// 		// printf( "total len:%" PRIu64 "\n", total_length);
// 		// printf("done!");
// close:
// 	sleep(10);
// 	for(uint32_t i = 0; i < latency.size(); i++) {
// 		file << "finish time: " << latency[i] << "\n"; 
// 		// std::cout << "finish time: " << latency[i] << "\n"; 
// 	}
// 	file.close();
// 	close(fd);
// 	return;
// }


int main(int argc, char** argv)
{
	int port, nextArg, tempArg;
	// struct sockaddr_in addr_in;
	struct addrinfo *matching_addresses;
	struct sockaddr *dest;
	struct addrinfo hints;
	char *host, *port_name;
 	std::vector<std::thread> workers;
	int cpu_list[16] = {0, 32, 4, 36, 8, 40, 12, 44, 16, 48, 20, 52, 24, 56, 28, 60};
//	int cpu_list[8] = {0, 4, 8, 12, 16, 20, 24, 28};
	// char buffer[8000000] = "abcdefgh\n";
	char *buffer = (char*)malloc(10000000);
	bool pin = false;
	int flow_size = 64;
	// buffer[63999] = 'H';
	int status;
	int i;
	int threads_per_core;
	int src_port = 0;
	int io_depth = 1;
	bool one_side = 0;
	bool shortflow = false;
	unsigned size_limit = 200;
	stop_count = 0;
	if ((argc >= 2) && (strcmp(argv[1], "--help") == 0)) {
		print_help(argv[0]);
		exit(0);
	}
	for (i = 0; i < 8000000; i++)
		buffer[i] = (rand()) % 26 + 'a';
//	printf("buffer:%s\n", buffer);
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
		} else if (strcmp(argv[nextArg], "--tcp") == 0) {
			protocol = "tcp";
		} else if (strcmp(argv[nextArg], "--dcpim") == 0) {
			protocol = "dcpim";
		} else if (strcmp(argv[nextArg], "--count") == 0) {
			if (nextArg == (argc-1)) {
				printf("No value provided for %s option\n",
					argv[nextArg]);
				exit(1);
			}
			nextArg++;
			count = get_int(argv[nextArg],
					"Bad count %s; must be positive integer\n");
		} else if (strcmp(argv[nextArg], "--sp") == 0) {
			if (nextArg == (argc-1)) {
				printf("No value provided for %s option\n",
					argv[nextArg]);
				exit(1);
			}
			nextArg++;
			src_port = get_int(argv[nextArg],
				"Bad srcPort %s; must be positive integer\n");
		} else if (strcmp(argv[nextArg], "--iodepth") == 0) {
			if (nextArg == (argc-1)) {
				printf("No value provided for %s option\n",
					argv[nextArg]);
				exit(1);
			}
			nextArg++;
			io_depth = get_int(argv[nextArg],
				"Bad io_depth %s; must be positive integer\n");
		} else if (strcmp(argv[nextArg], "--flowsize") == 0){
			if (nextArg == (argc-1)) {
				printf("No value provided for %s option\n",
					argv[nextArg]);
				exit(1);
			}
			nextArg++;
			flow_size = get_int(argv[nextArg],
				"Bad flow size %s; must be positive integer\n");
			std::cout << "flow size:" << flow_size << std::endl;
		} else if (strcmp(argv[nextArg], "--oneside") == 0) {
			one_side = true;
		} else if (strcmp(argv[nextArg], "--shortflow") == 0) {
			shortflow = true;
		} else {
			printf("Unknown option %s; type '%s --help' for help\n",
				argv[nextArg], argv[0]);
			exit(1);
		}
	}
	std::cout << "one side: " << one_side << std::endl;
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
	threads_per_core = count / 2;
	for(i = 0; i < count; i++) {
		nextArg = tempArg;
		for ( ; nextArg < argc; nextArg++) {
			if (strcmp(argv[nextArg], "ping") == 0) {
				if(shortflow) {
					workers.push_back(std::thread(tcp_shortflow, *dest, i, io_depth, flow_size, size_limit));
					port += 1;
					((struct sockaddr_in *) dest)->sin_port = htons(port);
				} else {
					if(one_side)
						workers.push_back(std::thread(test_ping_oneside_send, dest, i, io_depth, flow_size, src_port + i));
					else 
						workers.push_back(std::thread(test_ping_send, dest, i, io_depth, flow_size, src_port + i));
				}
				if(pin) {
					cpu_set_t cpuset;
					CPU_ZERO(&cpuset);
					CPU_SET(cpu_list[i / threads_per_core], &cpuset);
					pthread_setaffinity_np(workers[workers.size() - 1].native_handle(), sizeof(cpu_set_t), &cpuset);
				}	
				//workers.push_back(std::thread(test_ndping_recv, fd, dest, srcPort - 10000));
			}
			 else {
				printf("Unknown operation '%s'\n", argv[nextArg]);
				exit(1);
			}
		}
	}
	
    std::this_thread::sleep_for (std::chrono::seconds(140));
	stop_count = 1;
	for(unsigned i = 0; i < workers.size(); i++) {
		workers[i].join();
	}
	free(buffer);
	exit(0);
}

