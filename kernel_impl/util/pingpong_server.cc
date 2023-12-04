#include <arpa/inet.h>
#include <atomic>
#include <chrono>         // std::chrono::seconds

#include <iostream>
#include <fstream>
#include <mutex>
#include <condition_variable>
#include <list>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <inttypes.h>
#include <thread>
#include <vector>
// #include "homa.h"
#include "test_utils.h"
// #include "../uapi_linux_dcpim.h"
#include <sys/resource.h>
//#include "../uapi_linux_nd.h"
/* Log events to standard output. */
bool verbose = false;

/* Port number on which to listen (both for Homa and TCP); if multiple
 * Homa ports are in use, they will be consecutive numbers starting with
 * this. */
int port = 4000;

/* True that a specific format is expected for incoming messages, and we
 * should check that incoming messages conform to it.
 */
bool validate = false;
/* maximum latency will be 100ms */
#define MAX_HIST_VALUE 100000 
/* Count in us-scale */
#define NUM_BINS 100000 

std::vector<std::atomic<long long>> time_hist(MAX_HIST_VALUE);


void local_add_to_timehist(std::vector<long long> &local_time_hist, double latency) {
	// printf("latency: %f\n", latency);
	if(latency > MAX_HIST_VALUE)
		latency = MAX_HIST_VALUE - 1;
	if(latency < 0)
		latency = 0;
	local_time_hist[int(latency)] += 1; 
}

double local_get_mean_timehist(std::vector<long long> &local_time_hist) {
    double mean = 0.0;
	double count = 0;
    for (int i = 0; i < NUM_BINS; i++) {
        mean += static_cast<double>(local_time_hist[i]) * i;
		count += static_cast<double>(local_time_hist[i]);
    }
    mean /= count;
	return mean;
}

// Function to estimate the percentile from the histogram
double local_estimate_percentile(std::vector<long long> &local_time_hist, double percentile) {
    double total = 0;
	double target_value = 0;
    for (int i = 0; i < NUM_BINS; i++) {
        total += local_time_hist[i];
    }
	target_value = percentile * total;
	total = 0;
    for (int i = 0; i < NUM_BINS; i++) {
        total += local_time_hist[i];
        if (total >= target_value) {
            return i;
        }
    }
    return -1; // Percentile estimation failed
}

void add_to_timehist(std::vector<std::atomic<long long>> &local_time_hist, double latency) {
	// printf("latency: %f\n", latency);
	if(latency > MAX_HIST_VALUE)
		latency = MAX_HIST_VALUE;
	local_time_hist[int(latency * NUM_BINS / MAX_HIST_VALUE)].fetch_add(1, std::memory_order_relaxed); 
}

double get_mean_timehist(std::vector<std::atomic<long long>> &local_time_hist) {
    double mean = 0.0;
	double count = 0;
    for (int i = 0; i < NUM_BINS; i++) {
        mean += static_cast<double>(local_time_hist[i].load()) * i;
		count += static_cast<double>(local_time_hist[i].load());
    }
    mean /= count;
	return mean;
}

// Function to estimate the percentile from the histogram
double estimate_percentile(std::vector<std::atomic<long long>> &local_time_hist, double percentile) {
    double total = 0;
	double target_value = 0;
    for (int i = 0; i < NUM_BINS; i++) {
        total += local_time_hist[i].load();
    }
	target_value = percentile * total;
	total = 0;
    for (int i = 0; i < NUM_BINS; i++) {
        total += local_time_hist[i].load();
        if (total >= target_value) {
            return i;
        }
    }
    return -1; // Percentile estimation failed
}



class Conn_Data {
public:
	int fd;
	struct sockaddr_in source;
	int iodepth;
	int flow_size;
	Conn_Data(int fd, struct sockaddr_in source, int iodepth, int flow_size) {
		this->fd = fd;
		this->source = source;
		this->iodepth = iodepth;
		this->flow_size = flow_size;	
	}
	Conn_Data(){}
};
struct Agg_Stats {
	std::atomic<unsigned long> total_bytes;
	std::atomic<unsigned long> interval_bytes;
	uint64_t start_cycle;
	int interval_sec;
};

struct Agg_Stats agg_stats;
void init_agg_stats(struct Agg_Stats* stats, int interval_sec) {
	atomic_store(&stats->total_bytes, (unsigned long)0);
	atomic_store(&stats->interval_bytes, (unsigned long)0);
	stats->start_cycle = rdtsc();
	stats->interval_sec = interval_sec;
}

std::mutex m;
std::condition_variable cv;
std::list<Conn_Data> socklist;

void aggre_thread(struct Agg_Stats *stats) {
	init_agg_stats(stats, 1);
	while(1) {
		uint64_t start_cycle = rdtsc();
		uint64_t end_cycle;
		double rate;
		double bytes;
    	std::this_thread::sleep_for (std::chrono::seconds(stats->interval_sec));
    	end_cycle = rdtsc();
    	bytes = atomic_load(&stats->interval_bytes);
    	rate = (bytes)/ to_seconds(
			end_cycle - start_cycle);
		printf("Throughput: "
		"%.2f Gbps, bytes: %f, time: %f\n", rate * 1e-09 * 8, (double) bytes, to_seconds(
		end_cycle - start_cycle));
    	atomic_store(&stats->interval_bytes, (unsigned long)0);
	}
}

/**
 * nd_pingpong() - Handles messages arriving on a given socket.
 * @fd:           File descriptor for the socket over which messages
 *                will arrive.
 * @client_addr:  Information about the client (for messages).
 */
void nd_pingpong()
{
	// int flag = 1;
	int fd = 0;
	Conn_Data data;
	int optval = 7;
	unsigned optlen = 0;
	char *buffer = (char*)malloc(2359104);
	int flag;
	struct sockaddr_in source;
	// int iodepth;
	int flow_size;
	unsigned int cpu, node;
    std::unique_lock lk(m);
    cv.wait(lk, []{return !socklist.empty();});
	data = socklist.front();
	socklist.pop_front();
    lk.unlock();
	fd = data.fd;
	source = data.source;
	// iodepth = data.iodepth;
	flow_size = data.flow_size;
    // cv.notify_one();

	// int times = 10000;
	// int cur_length = 0;
	// bool streaming = false;
	uint64_t count = 0;
	uint64_t total_length = 0;
	// uint64_t start_cycle = 0, end_cycle = 0;
	struct sockaddr_in sin;
	socklen_t len = sizeof(sin);
	// int which = PRIO_PROCESS;
	pid_t pid = syscall(__NR_gettid);
//	struct sched_param param;
//  	param.sched_priority = 99;
//    	sched_setscheduler(pid, SCHED_RR, &param);
	//ret = setpriority(which, pid, -20);
	//std::cout << "ret "<< ret << std::endl;
	// ret = getpriority(which, pid);
	// int *int_buffer = reinterpret_cast<int*>(buffer);
	if (verbose)
		printf("New ND socket from %s\n", print_address(&source));
	flag = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
	setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &flag, sizeof(flag));
	if (getpeername(fd, (struct sockaddr *)&sin, &len) == -1)
	    perror("getsockname");
	getcpu(&cpu, &node);
	printf("core: %d pid: %d port number: %d\n",cpu,  pid, ntohs(sin.sin_port));
	fflush (stdout);
	// start_cycle = rdtsc();
	setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &optval, unsigned(sizeof(optval)));   
	getsockopt(fd, SOL_SOCKET, SO_PRIORITY, &optval, &optlen);

	// printf("sizeof buffer:%ld\n", sizeof(buffer));
	while (1) {
		int copied = 0;
		int rpc_length = flow_size;
		// times--;
		// int burst = iodepth;
		while(1) {
			int result = read(fd, buffer + copied,
				rpc_length);
			if (result <= 0) {
					goto close;
			}
			rpc_length -= result;
			copied += result;
			// total_length += result;
			if(rpc_length == 0) {
				rpc_length = flow_size;
				copied = 0;
				// burst -= 1;
				break;
			}
			// if(burst == 0)
			// 	break;
			// return;
		}
		copied = 0;
		rpc_length = flow_size;
		// burst = iodepth;
		// if(times == -1)
		// 	break;
		while(1) {
			// if(burst == 1) {
			//	flag = MSG_EOR;
			// } else
			// 	flag = MSG_MORE;
			flag = 0;
			int result = send(fd, buffer + copied,
				rpc_length, flag);

			if (result <= 0) {
					goto close;
			}
			rpc_length -= result;
			copied += result;
			// total_length += result;
			// printf("send rpc\n");
			if(rpc_length == 0) {
				rpc_length = flow_size;
				copied = 0;
				// burst -= 1;
				break;
			}
			// if(burst == 0)
			// 	break;
			// return;
		}
		count++;
	}
		printf( "total len:%" PRIu64 "\n", total_length);
		printf("done!");
	if (verbose)
		printf("Closing TCP socket from %s\n", print_address(&source));
close:
	close(fd);
	free(buffer);
}


std::atomic<int> thread_id(0);

/**
 * nd_pong() - Handles messages arriving on a given socket in pure-receive mode.
 * @fd:           File descriptor for the socket over which messages
 *                will arrive.
 * @client_addr:  Information about the client (for messages).
 */
void nd_pong()
{
	// int flag = 1;
	int fd = 0;
	Conn_Data data;
	int optval = 7;
	unsigned optlen = 0;
	char *buffer = (char*)malloc(2359104);
	int flag;
	struct sockaddr_in source;
	std::vector<long long> local_time_hist(MAX_HIST_VALUE);
	// int iodepth;
	int flow_size;
	unsigned int cpu, node;
	std::vector<double> latency;
	std::ofstream lfile;
	lfile.open("netperf-" + std::to_string(thread_id.fetch_add(1))+".log");
    std::unique_lock lk(m);
    cv.wait(lk, []{return !socklist.empty();});
	data = socklist.front();
	socklist.pop_front();
    lk.unlock();
	fd = data.fd;
	source = data.source;
	// iodepth = data.iodepth;
	flow_size = data.flow_size;
	
    // cv.notify_one();

	// int times = 10000;
	// int cur_length = 0;
	// bool streaming = false;
	uint64_t count = 0;
	// uint64_t total_length = 0;
	// uint64_t start_cycle = 0, end_cycle = 0;
	struct sockaddr_in sin;
	socklen_t len = sizeof(sin);
	long long start_time = 0;
	long long finish_time = 0;
	long long begin_time  = 0;
	struct timespec current_time;
	// int which = PRIO_PROCESS;
	pid_t pid = syscall(__NR_gettid);
	if (verbose)
		printf("New ND socket from %s\n", print_address(&source));
	flag = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
	setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &flag, sizeof(flag));
	if (getpeername(fd, (struct sockaddr *)&sin, &len) == -1)
	    perror("getsockname");
	getcpu(&cpu, &node);
	printf("core: %d pid: %d port number: %d\n",cpu,  pid, ntohs(sin.sin_port));
	fflush (stdout);
	// start_cycle = rdtsc();
	setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &optval, unsigned(sizeof(optval)));   
	getsockopt(fd, SOL_SOCKET, SO_PRIORITY, &optval, &optlen);

	// printf("sizeof buffer:%ld\n", sizeof(buffer));
	while (1) {
		int copied = 0;
		int rpc_length = flow_size;
		// times--;
		// int burst = iodepth;
		while(1) {
			int result = read(fd, buffer + copied,
				rpc_length);
			if (result <= 0) {
					goto close;
			}
			rpc_length -= result;
			copied += result;
			// total_length += result;
			if(rpc_length == 0) {
				rpc_length = flow_size;
				copied = 0;
				// burst -= 1;
				break;
			}
			// if(burst == 0)
			// 	break;
			// return;
		}
		/* Read the current time from CLOCK_REALTIME */
    	if (clock_gettime(CLOCK_REALTIME, &current_time) != 0) {
        	perror("clock_gettime");
        	break;
   		}
		finish_time = (long long)current_time.tv_sec * 1000000000 + (long long)current_time.tv_nsec;
		start_time = *(long long*)buffer;
		if(begin_time == 0) {
			begin_time = finish_time;
		}
		// std::cout << finish_time << " " << start_time << " " << (finish_time - start_time ) << std::endl;
		if(start_time == 0)
			std::cout << "start time is 0" << std::endl;
		// latency.push_back((finish_time - start_time) / 1000000000.0);
		local_add_to_timehist(local_time_hist, (finish_time - start_time) / 1000.0);
		count++;
	}
	if (verbose)
		printf("Closing TCP socket from %s\n", print_address(&source));
close:
	// for(uint32_t i = 0; i < latency.size(); i++) {
	// 	lfile << "finish time: " << latency[i] << "\n"; 
	// 	// std::cout << "finish time: " << latency[i] << "\n"; 
	// }
	printf("end loop\n");
	lfile <<   pid << " " << local_get_mean_timehist(local_time_hist) << " " << local_estimate_percentile(local_time_hist, 0.99) << " " << local_estimate_percentile(local_time_hist, 0.999) << " "
		<< count  / ((finish_time - begin_time) / 1000.0)  << std::endl;
	for(int i = 0; i < NUM_BINS; i++) {
		std::atomic_fetch_add(&time_hist[i], local_time_hist[i]);
	}
	close(fd);
	free(buffer);
	lfile.close();
}

/**
 * tcp_shortflow() - Handles one message per socket;
 */
void tcp_shortflow(int port, int flow_size)
{
	// int flag = 1;
	int fd = 0;
	Conn_Data data;
	char *buffer = (char*)malloc(2359104);
	int listen_fd = socket(PF_INET, SOCK_STREAM, 0);
	std::vector<long long> local_time_hist(MAX_HIST_VALUE);
	// int iodepth;
	std::ofstream lfile;
	lfile.open("netperf-" + std::to_string(thread_id.fetch_add(1))+".log");
	uint64_t count = 0;
	long long start_time = 0;
	long long finish_time = 0;
	long long begin_time  = 0;
	struct timespec current_time;
	// int which = PRIO_PROCESS;
	pid_t pid = syscall(__NR_gettid);
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;

	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if (listen_fd == -1) {
		printf("Couldn't open server socket: %s\n", strerror(errno));
		exit(1);
	}
	int option_value = 1;
	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &option_value,
			sizeof(option_value)) != 0) {
		printf("Couldn't set SO_REUSEADDR on listen socket: %s",
			strerror(errno));
		exit(1);
	}
	if (bind(listen_fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr))
			== -1) {
		printf("Couldn't bind to port %d: %s\n", port, strerror(errno));
		exit(1);
	}
	if (listen(listen_fd, 1000) == -1) {
		printf("Couldn't listen on socket: %s", strerror(errno));
		exit(1);
	}
	while (1) {
		struct sockaddr_in client_addr;
		socklen_t addr_len = sizeof(client_addr);
		int stream = accept(listen_fd,
				reinterpret_cast<sockaddr *>(&client_addr),
				&addr_len);
		if (stream < 0) {
			printf("Couldn't accept incoming connection: %s",
				strerror(errno));
			exit(1);
		}
		while (1) {
			int copied = 0;
			int rpc_length = flow_size;
			while(1) {
				int result = read(stream, buffer + copied,
					rpc_length);
				if (result <= 0) {
						goto close;
				}
				rpc_length -= result;
				copied += result;
				if(rpc_length == 0) {
					rpc_length = flow_size;
					copied = 0;
					break;
				}
			}
			/* Read the current time from CLOCK_REALTIME */
			if (clock_gettime(CLOCK_REALTIME, &current_time) != 0) {
				perror("clock_gettime");
				break;
			}
			finish_time = (long long)current_time.tv_sec * 1000000000 + (long long)current_time.tv_nsec;
			start_time = *(long long*)buffer;
			if(begin_time == 0) {
				begin_time = finish_time;
			}
			local_add_to_timehist(local_time_hist, (finish_time - start_time) / 1000.0);
			count++;
			close(stream);
			break;
		}
		if(finish_time - begin_time > 120000000000) {
			break;
		}
	}
close:
	lfile <<   pid << " " << local_get_mean_timehist(local_time_hist) << " " << local_estimate_percentile(local_time_hist, 0.99) << " " << local_estimate_percentile(local_time_hist, 0.999) << " "
		<< count  / ((finish_time - begin_time) / 1000.0)  << std::endl;
	for(int i = 0; i < NUM_BINS; i++) {
		std::atomic_fetch_add(&time_hist[i], local_time_hist[i]);
	}
	printf("thread finish\n");
	close(fd);
	free(buffer);
	lfile.close();
}

/**
 * homa_server() - Opens a Homa socket and handles all requests arriving on
 * that socket.
 * @port:   Port number to use for the Homa socket.
 */
// void homa_server(std::string ip, int port)
// {
// 	int fd;
// 	struct sockaddr_in addr_in;
// 	int message[1000000];
// 	struct sockaddr_in source;
// 	int length;
// 	uint64_t total_length = 0, count = 0;
// 	uint64_t start_cycle = 0, end_cycle = 0;
// 	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_HOMA);
// 	if (fd < 0) {
// 		printf("Couldn't open Homa socket: %s\n", strerror(errno));
// 		return;
// 	}
	
// 	mem(&addr_in, 0, sizeof(addr_in));
// 	addr_in.sin_family = AF_INET;
// 	addr_in.sin_port = htons(port);
// 	inet_pton(AF_INET, ip.c_str(), &addr_in.sin_addr);
// 	// inet_aton("10.0.0.10", &addr_in.sin_addr);
// 	// addr_in.sin_addr.s_addr = INADDR_ANY;

// 	if (bind(fd, (struct sockaddr *) &addr_in, sizeof(addr_in)) != 0) {
// 		printf("Couldn't bind socket to Homa port %d: %s\n", port,
// 				strerror(errno));
// 		return;
// 	}
// 	if (verbose)
// 		printf("Successfully bound to Homa port %d\n", port);
// 	while (1) {
// 		uint64_t id = 0;
// 		int seed;
// 		// int result;
// 		length = homa_recv(fd, message, sizeof(message),
// 			HOMA_RECV_REQUEST, &id, (struct sockaddr *) &source,
// 			sizeof(source));
// 		if (length < 0) {
// 			printf("homa_recv failed: %s\n", strerror(errno));
// 			continue;
// 		}
// 		if (validate) {
// 			seed = check_buffer(&message[2],
// 				length - 2*sizeof32(int));
// 			if (verbose)
// 				printf("Received message from %s with %d bytes, "
// 					"id %lu, seed %d, response length %d\n",
// 					print_address(&source), length, id,
// 					seed, message[1]);
// 		} else
// 			if (verbose)
// 				printf("Received message from %s with "
// 					"%d bytes, id %lu, response length %d\n",
// 					print_address(&source), length, id,
// 					message[1]);
// 		if(count % 1000 == 0) {
// 			end_cycle = rdtsc();
			
// 			double rate = ((double) total_length)/ to_seconds(
// 				end_cycle - start_cycle);
// 			total_length = 0;

// 			start_cycle = rdtsc();
// 			if(count != 0) {
// 				printf("Homa throughput: "
// 				"%.2f Gbps\n", rate * 1e-09 * 8);
// 			}
// 		}
// 		total_length += length;
// 		count += 1;
// 		/* Second word of the message indicates how large a
// 		 * response to send.
// 		 */
// 		// result = homa_reply(fd, message, 1,
// 		// 	(struct sockaddr *) &source, sizeof(source), id);
// 		// if (result < 0) {
// 		// 	printf("Homa_reply failed: %s\n", strerror(errno));
// 		// }
// 	}
// 	printf("end\n");
// }

/**
 * print_help() - Print out usage information for this program.
 * @name:   Name of the program (argv[0])
 */
void print_help(const char *name)
{
	printf("Usage: %s [options]\n\n"
		"The following options are supported:\n\n"
		"--help       Print this message and exit\n"
		"--port       (First) port number to use (default: 4000)\n"
		"--num_ports  Number of Homa ports to open (default: 1)\n"
		"--validate   Validate contents of incoming messages (default: false\n"
		"--verbose    Log events as they happen (default: false)\n",
		name);
}

/**
 * tcp_connection() - Handles messages arriving on a given socket.
 * @fd:           File descriptor for the socket over which messages
 *                will arrive.
 * @client_addr:  Information about the client (for messages).
 */
void tcp_connection(int fd, struct sockaddr_in source)
{
	int flag = 1;
	char buffer[1000000];
	int cur_length = 0;
	bool streaming = false;
	uint64_t count = 0;
	uint64_t total_length = 0;
	uint64_t start_cycle = 0, end_cycle = 0;
	struct sockaddr_in sin;
	socklen_t len = sizeof(sin);
	int *int_buffer = reinterpret_cast<int*>(buffer);
	if (verbose)
		printf("New TCP socket from %s\n", print_address(&source));
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
	if (getsockname(fd, (struct sockaddr *)&sin, &len) == -1)
	    perror("getsockname");
	else
	    printf("port number %d\n", ntohs(sin.sin_port));
	start_cycle = rdtsc();
	while (1) {
		int result = read(fd, buffer + cur_length,
				sizeof(buffer) - cur_length);
		if (result < 0) {
			if (errno == ECONNRESET)
				break;
			printf("Read error on socket: %s", strerror(errno));
			exit(1);
		}
		total_length += result;
		count++;
		if (result == 0)
			break;
		if(count % 1000 == 0) {
			end_cycle = rdtsc();
			
			double rate = ((double) total_length)/ to_seconds(
				end_cycle - start_cycle);
			total_length = 0;

			start_cycle = rdtsc();
			if(count != 0) {
				printf("TCP throughput: "
				"%.2f Gbps\n", rate * 1e-09 * 8);
			}
		}
		/* The connection can be used in two modes. If the first
		 * word received is -1, then the connection is in streaming
		 * mode: we just read bytes and throw them away. If the
		 * first word isn't -1, then it's in message mode: we read
		 * full messages and respond to them.
		 */
		if (streaming)
			continue;
		if (int_buffer[0] < 0) {
			streaming = true;
			continue;
		}
		cur_length += result;

		/* First word of request contains expected length in bytes. */
		if ((cur_length >= 2*sizeof32(int))
				&& (cur_length >= int_buffer[0])) {
			if (cur_length != int_buffer[0])
				printf("Received %d bytes but buffer[0] = %d, "
					"buffer[1] = %d\n",
					cur_length, int_buffer[0],
					int_buffer[1]);
			if (validate) {
				int seed = check_buffer(&int_buffer[2],
					int_buffer[0] - 2*sizeof32(int));
				if (verbose)
					printf("Received message from %s with "
						"%d bytes, seed %d\n",
						print_address(&source),
						int_buffer[0], seed);
			} else if (verbose)
				printf("Received message from %s with %d "
					"bytes\n",
					print_address(&source), int_buffer[0]);
			cur_length = 0;
			if (int_buffer[1] <= 0)
				continue;
			if (write(fd, buffer, int_buffer[1]) != int_buffer[1]) {
				printf("Socket write failed: %s\n",
						strerror(errno));
				exit(1);
			};
		}
	}
	if (verbose)
		printf("Closing TCP socket from %s\n", print_address(&source));
	close(fd);
}

/**
 * tcp_server() - Opens a TCP socket, accepts connections on that socket
 * (one thread per connection) and processes messages on those connections.
 * @port:  Port number on which to listen.
 */
void tcp_server(int port, int num_threads, int iodepth, int flow_size, bool pin, bool one_side)
{
	int cpu_list[16] = {0, 32, 4, 36, 8, 40, 12, 44, 16, 48, 20, 52, 24, 56, 28, 60};
	int num_conns = 0;
	std::vector<std::thread> workers;
	
	// int cpu_list[2] = {0, 32};
	//int cpu_list[8] = {0, 4, 8, 12, 16, 20, 24, 28};
	int listen_fd = socket(PF_INET, SOCK_STREAM, 0);
 	std::unique_lock<std::mutex> lk(m,  std::defer_lock);
	int i = 0;
	int threads_per_core = num_threads / 2;
	// std::ofstream lfile;
	// lfile.open("latency.log");
	if (listen_fd == -1) {
		printf("Couldn't open server socket: %s\n", strerror(errno));
		exit(1);
	}
	int option_value = 1;
	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &option_value,
			sizeof(option_value)) != 0) {
		printf("Couldn't set SO_REUSEADDR on listen socket: %s",
			strerror(errno));
		exit(1);
	}
	fprintf(stderr, "%d\n", num_threads);
	for (i = 0; i < num_threads; i++) {
		if(one_side) {
			// std::thread thread(nd_pong);
			workers.push_back(std::thread(nd_pong));
			if(pin) {
				cpu_set_t cpuset;
				CPU_ZERO(&cpuset);
				CPU_SET(cpu_list[i / threads_per_core], &cpuset);
				pthread_setaffinity_np(workers[workers.size() - 1].native_handle(), sizeof(cpu_set_t), &cpuset);
			}
			// thread.detach();
		}
		else {
			// std::thread thread(nd_pingpong);
			workers.push_back(std::thread(nd_pingpong));
			if(pin) {
				cpu_set_t cpuset;
				CPU_ZERO(&cpuset);
				CPU_SET(cpu_list[i / threads_per_core], &cpuset);
				pthread_setaffinity_np(workers[workers.size() - 1].native_handle(), sizeof(cpu_set_t), &cpuset);
			}
			// thread.detach();
		}
	}
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if (bind(listen_fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr))
			== -1) {
		printf("Couldn't bind to port %d: %s\n", port, strerror(errno));
		exit(1);
	}
	if (listen(listen_fd, 1000) == -1) {
		printf("Couldn't listen on socket: %s", strerror(errno));
		exit(1);
	}
	while (1) {
		struct sockaddr_in client_addr;
		socklen_t addr_len = sizeof(client_addr);
		int stream = accept(listen_fd,
				reinterpret_cast<sockaddr *>(&client_addr),
				&addr_len);
		lk.lock();
		socklist.push_back(Conn_Data(stream, client_addr, iodepth, flow_size));
		lk.unlock();
		cv.notify_one();
		if (stream < 0) {
			printf("Couldn't accept incoming connection: %s",
				strerror(errno));
			exit(1);
		}
		num_conns++;
		if(num_conns == num_threads)
			break;
		// std::thread thread(nd_pingpong, stream, client_addr, iodepth, flow_size);
		// if(pin) {
		// 	cpu_set_t cpuset;
		// 	CPU_ZERO(&cpuset);
		// 	CPU_SET(cpu_list[(i) % 2], &cpuset);
		// 	pthread_setaffinity_np(thread.native_handle(), sizeof(cpu_set_t), &cpuset);
		// }
	    // thread.detach();
		// i += 1;
	}
	printf("num threads: %lu\n", workers.size());
	for(i = 0; unsigned(i) < workers.size(); i++) {
		workers[i].join();
	}
	// lfile << get_mean_timehist(time_hist) << " " << estimate_percentile(time_hist, 0.99) << " " << estimate_percentile(time_hist, 0.999)  << std::endl; 
	// lfile.close();
}

/**
 * nd_connection() - Handles messages arriving on a given socket.
 * @fd:           File descriptor for the socket over which messages
 *                will arrive.
 * @client_addr:  Information about the client (for messages).
 */
void nd_connection(int fd, struct sockaddr_in source)
{
	// int flag = 1;
	char *buffer = (char*)malloc(2359104);
	// int cur_length = 0;
	// bool streaming = false;
	uint64_t count = 0;
	uint64_t total_length = 0;
	// uint64_t start_cycle = 0, end_cycle = 0;
	struct sockaddr_in sin;
	socklen_t len = sizeof(sin);
	// int *int_buffer = reinterpret_cast<int*>(buffer);
	if (verbose)
		printf("New ND socket from %s\n", print_address(&source));
	// setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
	if (getsockname(fd, (struct sockaddr *)&sin, &len) == -1)
	    perror("getsockname");
	else
	    printf("port number %d\n", ntohs(sin.sin_port));
	// start_cycle = rdtsc();
	printf("start connection\n");
	// printf("sizeof buffer:%ld\n", sizeof(buffer));
	while (1) {
		int result = read(fd, buffer,
				2359104);
		// setbuf(stdout, NULL);
		// printf("result:%d\n", result);
		
		// printf("'%.*s'\n", result, buffer);
		// fflush(stdout);
		// while(1) {
					
		// }
		if (result < 0) {
			// if (errno == ECONNRESET)
				break;
		
			// return;
		}
	//	if (total_length <= 8000000)
	//	 	printf("buffer:%s\n", buffer);
		total_length += result;
		count++;
		if (result == 0)
			break;
		std::atomic_fetch_add(&agg_stats.interval_bytes, (unsigned long)result);
		std::atomic_fetch_add(&agg_stats.total_bytes, (unsigned long)result);

		// if(count % 1000 == 0) {
		// 	end_cycle = rdtsc();
		// 	printf("count:%lu\n", count);
		// 	double rate = ((double) total_length)/ to_seconds(
		// 		end_cycle - start_cycle);
		// 	// if(count != 0) {
		// 	// 	printf("ND throughput: "
		// 	// 	"%.2f Gbps, bytes: %f, time: %f\n", rate * 1e-09 * 8, (double) total_length, to_seconds(
		// 	// 	end_cycle - start_cycle));
		// 	// }
		// 	total_length = 0;

		// 	start_cycle = rdtsc();
		// }
		// /* The connection can be used in two modes. If the first
		//  * word received is -1, then the connection is in streaming
		//  * mode: we just read bytes and throw them away. If the
		//  * first word isn't -1, then it's in message mode: we read
		//  * full messages and respond to them.
		//  */
		// if (streaming)
		// 	continue;
		// if (int_buffer[0] < 0) {
		// 	streaming = true;
		// 	continue;
		// }
		// cur_length += result;

		// /* First word of request contains expected length in bytes. */
		// if ((cur_length >= 2*sizeof32(int))
		// 		&& (cur_length >= int_buffer[0])) {
		// 	if (cur_length != int_buffer[0])
		// 		printf("Received %d bytes but buffer[0] = %d, "
		// 			"buffer[1] = %d\n",
		// 			cur_length, int_buffer[0],
		// 			int_buffer[1]);
		// 	if (validate) {
		// 		int seed = check_buffer(&int_buffer[2],
		// 			int_buffer[0] - 2*sizeof32(int));
		// 		if (verbose)
		// 			printf("Received message from %s with "
		// 				"%d bytes, seed %d\n",
		// 				print_address(&source),
		// 				int_buffer[0], seed);
		// 	} else if (verbose)
		// 		printf("Received message from %s with %d "
		// 			"bytes\n",
		// 			print_address(&source), int_buffer[0]);
		// 	cur_length = 0;
		// 	if (int_buffer[1] <= 0)
		// 		continue;
		// 	if (write(fd, buffer, int_buffer[1]) != int_buffer[1]) {
		// 		printf("Socket write failed: %s\n",
		// 				strerror(errno));
		// 		exit(1);
		// 	};
		// }
	}
		printf( "total len:%" PRIu64 "\n", total_length);
		printf("done!");
	if (verbose)
		printf("Closing TCP socket from %s\n", print_address(&source));
	close(fd);
	free(buffer);
}

/**
 * udp_server()
 *
 */
void udp_server(int port)
{
	char buffer[1000000];
	int result = 0;
	uint64_t start_cycle = 0, end_cycle = 0;
	uint64_t total_length = 0;
	int count = 0;

	int listen_fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (listen_fd == -1) {
		printf("Couldn't open server socket: %s\n", strerror(errno));
		exit(1);
	}
	int option_value = 1;
	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &option_value,
			sizeof(option_value)) != 0) {
		printf("Couldn't set SO_REUSEADDR on listen socket: %s",
			strerror(errno));
		exit(1);
	}
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if (bind(listen_fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr))
			== -1) {
		printf("Couldn't bind to port %d: %s\n", port, strerror(errno));
		exit(1);
	}
	// struct timeval tv;
	// tv.tv_usec = 100 * 1000;
	// if (setsockopt(listen_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)))
	// 	return;
	while (1) {
		struct sockaddr_in client_addr;
		socklen_t addr_len = sizeof(client_addr);

		result = recvfrom(listen_fd, (char *)buffer, sizeof(buffer),  
                MSG_WAITALL, ( struct sockaddr *) &client_addr, 
                &addr_len);
		printf("%s\n", buffer);
		printf("%c\n", buffer[10000]);
		if (result < 0) {
			if (errno == ECONNRESET)
				break;
			printf("Read error on socket: %s", strerror(errno));
			exit(1);
		}
		if (result == 0)
			break;
		if(count % 50000 == 0) {
			end_cycle = rdtsc();
			
			double rate = ((double) total_length)/ to_seconds(
				end_cycle - start_cycle);
			total_length = 0;

			start_cycle = rdtsc();
			if(count != 0) {
				printf("UDP throughput: "
				"%.2f Gbps\n", rate * 1e-09 * 8);
			}
		}
		total_length += result;
		count += 1;
	}

}

/**
 * nd_server()
 *
 */
void dcpim_server(int port, int num_threads, int iodepth, int flow_size, bool pin, bool one_side)
{
	int cpu_list[16] = {0, 32, 4, 36, 8, 40, 12, 44, 16, 48, 20, 52, 24, 56, 28, 60};
	int num_conns = 0;
	std::vector<std::thread> workers;
	
	// int cpu_list[2] = {0, 32};
	//int cpu_list[8] = {0, 4, 8, 12, 16, 20, 24, 28};
	int listen_fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_DCPIM);
 	std::unique_lock<std::mutex> lk(m,  std::defer_lock);
	int i = 0;
	int threads_per_core = num_threads / 2;
	// std::ofstream lfile;
	// lfile.open("latency.log");
	if (listen_fd == -1) {
		printf("Couldn't open server socket: %s\n", strerror(errno));
		exit(1);
	}
	int option_value = 1;
	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &option_value,
			sizeof(option_value)) != 0) {
		printf("Couldn't set SO_REUSEADDR on listen socket: %s",
			strerror(errno));
		exit(1);
	}
	fprintf(stderr, "%d\n", num_threads);
	for (i = 0; i < num_threads; i++) {
		if(one_side) {
			// std::thread thread(nd_pong);
			workers.push_back(std::thread(nd_pong));
			if(pin) {
				cpu_set_t cpuset;
				CPU_ZERO(&cpuset);
				CPU_SET(cpu_list[i / threads_per_core], &cpuset);
				pthread_setaffinity_np(workers[workers.size() - 1].native_handle(), sizeof(cpu_set_t), &cpuset);
			}
			// thread.detach();
		}
		else {
			// std::thread thread(nd_pingpong);
			workers.push_back(std::thread(nd_pingpong));
			if(pin) {
				cpu_set_t cpuset;
				CPU_ZERO(&cpuset);
				CPU_SET(cpu_list[i / threads_per_core], &cpuset);
				pthread_setaffinity_np(workers[workers.size() - 1].native_handle(), sizeof(cpu_set_t), &cpuset);
			}
			// thread.detach();
		}
	}
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if (bind(listen_fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr))
			== -1) {
		printf("Couldn't bind to port %d: %s\n", port, strerror(errno));
		exit(1);
	}
	if (listen(listen_fd, 1000) == -1) {
		printf("Couldn't listen on socket: %s", strerror(errno));
		exit(1);
	}
	while (1) {
		struct sockaddr_in client_addr;
		socklen_t addr_len = sizeof(client_addr);
		int stream = accept(listen_fd,
				reinterpret_cast<sockaddr *>(&client_addr),
				&addr_len);
		lk.lock();
		socklist.push_back(Conn_Data(stream, client_addr, iodepth, flow_size));
		lk.unlock();
		cv.notify_one();
		if (stream < 0) {
			printf("Couldn't accept incoming connection: %s",
				strerror(errno));
			exit(1);
		}
		num_conns++;
		if(num_conns == num_threads)
			break;
		// std::thread thread(nd_pingpong, stream, client_addr, iodepth, flow_size);
		// if(pin) {
		// 	cpu_set_t cpuset;
		// 	CPU_ZERO(&cpuset);
		// 	CPU_SET(cpu_list[(i) % 2], &cpuset);
		// 	pthread_setaffinity_np(thread.native_handle(), sizeof(cpu_set_t), &cpuset);
		// }
	    // thread.detach();
		// i += 1;
	}
	printf("num threads: %lu\n", workers.size());
	for(i = 0; unsigned(i) < workers.size(); i++) {
		workers[i].join();
	}
	// lfile << get_mean_timehist(time_hist) << " " << estimate_percentile(time_hist, 0.99) << " " << estimate_percentile(time_hist, 0.999)  << std::endl; 
	// lfile.close();
}

int main(int argc, char** argv) {
	int next_arg;
	int num_ports = 1;
	int iodepth = 1;
	int flow_size = 64; // bytes
	bool pin = false;
	int count = 1;
	int one_side = 0;
	bool dcpim = false;
	bool shortflow = false;
	std::string ip;
	std::ofstream lfile;
	for (int i = 0; i < MAX_HIST_VALUE; ++i) {
        time_hist[i].store(0);
    }
	if ((argc >= 2) && (strcmp(argv[1], "--help") == 0)) {
		print_help(argv[0]);
		exit(0);
	}
	
	for (next_arg = 1; next_arg < argc; next_arg++) {
		if (strcmp(argv[next_arg], "--help") == 0) {
			print_help(argv[0]);
			exit(0);
		} else if (strcmp(argv[next_arg], "--port") == 0) {
			if (next_arg == (argc-1)) {
				printf("No value provided for %s option\n",
					argv[next_arg]);
				exit(1);
			}
			next_arg++;
			port = get_int(argv[next_arg],
					"Bad port %s; must be positive integer\n");
		} else if (strcmp(argv[next_arg], "--ip") == 0) {
			if (next_arg == (argc-1)) {
				printf("No value provided for %s option\n",
					argv[next_arg]);
				exit(1);
			}
			next_arg++;
			ip = std::string(argv[next_arg]);
		} else if (strcmp(argv[next_arg], "--iodepth") == 0) {
			if (next_arg == (argc-1)) {
				printf("No value provided for %s option\n",
					argv[next_arg]);
				exit(1);
			}
			next_arg++;
			iodepth = get_int(argv[next_arg], 
				"Bad iodepth %s; must be positive integer\n");
		} else if (strcmp(argv[next_arg], "--flowsize") == 0) {
			if (next_arg == (argc-1)) {
				printf("No value provided for %s option\n",
					argv[next_arg]);
				exit(1);
			}
			next_arg++;
			flow_size = get_int(argv[next_arg], 
				"Bad flow size %s; must be positive integer\n");
		} else if (strcmp(argv[next_arg], "--num_ports") == 0) {
			if (next_arg == (argc-1)) {
				printf("No value provided for %s option\n",
					argv[next_arg]);
				exit(1);
			}
			next_arg++;
			num_ports = get_int(argv[next_arg],
				"Bad num_ports %s; must be positive integer\n");
		} else if (strcmp(argv[next_arg], "--validate") == 0) {
			validate = true;
		} else if (strcmp(argv[next_arg], "--shortflow") == 0) {
			shortflow = true;
		} else if (strcmp(argv[next_arg], "--pin") == 0) {
			pin = true;
		} else if (strcmp(argv[next_arg], "--verbose") == 0) {
			verbose = true;
		} else if (strcmp(argv[next_arg], "--dcpim") == 0) {
			dcpim = true;
		} else if (strcmp(argv[next_arg], "--count") == 0) {
			if (next_arg == (argc-1)) {
				printf("No value provided for %s option\n",
					argv[next_arg]);
				exit(1);
			}
			next_arg++;
			count = get_int(argv[next_arg],
				"Bad num of threads %s; must be positive integer\n");
		} else if (strcmp(argv[next_arg], "--oneside") == 0) {
			one_side = true;
		} else {
			printf("Unknown option %s; type '%s --help' for help\n",
				argv[next_arg], argv[0]);
			exit(1);
		}
	}
 	std::vector<std::thread> workers;

	// for (int i = 0; i < num_ports; i++) {
	// 	printf("port number:%i\n", port + i);
	// 	workers.push_back(std::thread (homa_server, ip, port+i));
	// }
	if(shortflow) {
			for (int i = 0; i < count; i++) {
				workers.push_back(std::thread(tcp_shortflow, port, flow_size));
				port += 1;
			}
	} else {
		if (dcpim == false)
			workers.push_back(std::thread(tcp_server, port, count, iodepth, flow_size, pin, one_side));
		else
			workers.push_back(std::thread(dcpim_server, port, count, iodepth, flow_size, pin, one_side));
	}
	// workers.push_back(std::thread(aggre_thread, &agg_stats));
	printf("num_ports:%d\n", num_ports);
	for(unsigned i = 0; i < workers.size(); i++) {
		workers[i].join();
	}
	// if(shortflow) {
	lfile.open("latency.log");
	// }
	lfile << get_mean_timehist(time_hist) << " " << estimate_percentile(time_hist, 0.99) << " " << estimate_percentile(time_hist, 0.999)  << std::endl; 
	lfile.close();
}

