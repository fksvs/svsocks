#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#define SYSLOG_IDENT "svsocks"
#define LISTEN_ADDRESS "::ffff:127.0.0.1"
#define LISTEN_PORT 1080
#define NTHREADS 1000

#define BUFF_SIZE 4096
#define BACKLOG 10

int serverfd;
pthread_mutex_t server_mtx;

uint8_t ipv4_connect(int *hostfd, char *buffer)
{
	struct sockaddr_in host;
	uint32_t dst_addr;
	uint16_t dst_port;

	memcpy(&dst_addr, &buffer[4], 4);
	memcpy(&dst_port, &buffer[8], 2);

	memset(&host, 0, sizeof(struct sockaddr_in));
	host.sin_family = AF_INET;
	host.sin_port = dst_port;
	host.sin_addr.s_addr = dst_addr;

	if ((*hostfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		return 0x01;
	}
	if (connect(*hostfd, (struct sockaddr *)&host, sizeof(struct sockaddr_in)) == -1) {
		int err = errno;
		switch (err) {
		case ECONNREFUSED:
			return 0x05;
		case ENETUNREACH:
			return 0x03;
		default:
			return 0x01;
		}
	}

	return 0x00;
}

uint8_t domain_connect(int *hostfd, char *buffer)
{
	struct addrinfo hint, *result, *ptr;
	uint8_t domain_len, domain_name[255], reply;
	uint16_t dst_port;
	char port_addr[255];

	memset(domain_name, 0, 255);
	domain_len = buffer[4];
	memcpy(domain_name, &buffer[5], domain_len);

	memcpy(&dst_port, &buffer[5 + domain_len], 2);
	snprintf(port_addr, 255, "%d", ntohs(dst_port));
	
	memset(&hint, 0, sizeof(struct addrinfo));
	hint.ai_flags = AI_NUMERICSERV;
	hint.ai_family = AF_UNSPEC;
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_protocol = 0;

	if (getaddrinfo((const char *)domain_name, port_addr, &hint, &result) != 0) {
		return 0x01;
	}
	for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
		if ((*hostfd = socket(ptr->ai_family, ptr->ai_socktype,
					ptr->ai_protocol)) == -1) {
			reply = 0x01;
			continue;
		}
		if (connect(*hostfd, ptr->ai_addr, ptr->ai_addrlen) == -1) {
			int err = errno;
			close(*hostfd);

			switch (err) {
			case ECONNREFUSED:
				reply = 0x05;
				break;
			case ENETUNREACH:
				reply = 0x03;
				break;
			default:
				reply = 0x01;
				break;
			}
			continue;
		} else {
			reply = 0x00;
			break;
		}
	}

	freeaddrinfo(result);
	return reply;
}

uint8_t ipv6_connect(int *hostfd, char *buffer)
{
	struct sockaddr_in6 host;
	uint8_t dst_addr[16];
	uint16_t dst_port;

	memcpy(&dst_addr, &buffer[4], 16);
	memcpy(&dst_port, &buffer[20], 2);

	memset(&host, 0, sizeof(struct sockaddr_in6));
	host.sin6_family = AF_INET6;
	host.sin6_port = dst_port;
	memcpy(&host.sin6_addr.s6_addr, dst_addr, 16);

	if ((*hostfd = socket(AF_INET6, SOCK_STREAM, 0)) == -1) {
		return 0x01;
	}
	if (connect(*hostfd, (struct sockaddr *)&host, sizeof(struct sockaddr_in6)) == -1) {
		int err = errno;
		switch (err) {
		case ECONNREFUSED:
			return 0x05;
		case ENETUNREACH:
			return 0x03;
		default:
			return 0x01;
		}
	}

	return 0x00;
}

int method_negotiation(int clientfd)
{
	int total;
	char buffer[BUFF_SIZE];
	uint8_t version, nmethods, methods[255], i, choosen_method = 0xFF;

	total = recv(clientfd, buffer, BUFF_SIZE, 0);
	if (total <= 0 || total > 257) {
		return -1;
	}

	version = buffer[0];
	if (version != 0x05) {
		return -1;
	}

	nmethods = buffer[1];
	memcpy(methods, &buffer[2], nmethods);

	for (i = 0; i < nmethods; i++) {
		if (methods[i] == 0x00) {
			choosen_method = 0x00;
			break;
		}
	}

	memset(buffer, 0, BUFF_SIZE);
	buffer[0] = 0x05;
	buffer[1] = choosen_method;

	total = send(clientfd, buffer, 2, 0); 
	if (total == -1 || total != 2) {
		return -1;
	}
	if (choosen_method == 0xFF) {
		return -1;
	}

	return 0;
}

int process_request(int clientfd)
{
	int hostfd, total;
	char buffer[BUFF_SIZE];
	uint8_t version, command, atype, reply;

	total = recv(clientfd, buffer, BUFF_SIZE, 0);
	if (total <= 0 || total > 262) {
		return -1;
	}

	version = buffer[0];
	if (version != 0x05) {
		return -1;
	}

	command = buffer[1];
	atype = buffer[3];

	if (command == 0x01) {
		switch (atype) {
		case 0x01:
			reply = ipv4_connect(&hostfd, buffer);
			break;
		case 0x03:
			reply = domain_connect(&hostfd, buffer);
			break;
		case 0x04:
			reply = ipv6_connect(&hostfd, buffer);
			break;
		default:
			reply = 0x08;
			break;
		}
	} else {
		reply = 0x07;
	}

	buffer[1] = reply;
	total = send(clientfd, buffer, total, 0);
	if (total == -1) {
		return -1;
	}
	if (reply != 0x00) {
		return -1;
	}

	return hostfd;
}

int log_session(int clientfd, int hostfd)
{
	struct sockaddr_in6 client_addr;
	struct sockaddr_storage host_addr;
	socklen_t client_len = sizeof(struct sockaddr_in6);
	socklen_t host_len = sizeof(struct sockaddr_storage), host_port;
	char client_ip[INET6_ADDRSTRLEN], host_ip[INET6_ADDRSTRLEN];
	
	if (getpeername(clientfd, (struct sockaddr *)&client_addr, &client_len) == -1) {
		syslog(LOG_ERR, "getpeername error [client][%d] : %s",
			__LINE__, strerror(errno));
		return -1;
	}
	if (getpeername(hostfd, (struct sockaddr *)&host_addr, &host_len) == -1) {
		syslog(LOG_ERR, "getpeername error [host][%d] : %s",
			__LINE__, strerror(errno));
	}

	if (host_addr.ss_family == AF_INET) {
		struct sockaddr_in *host_ipv4 = (struct sockaddr_in *)&host_addr;
		host_port = ntohs(host_ipv4->sin_port);
		inet_ntop(AF_INET, &host_ipv4->sin_addr, host_ip, INET6_ADDRSTRLEN);
	} else if (host_addr.ss_family == AF_INET6) {
		struct sockaddr_in6 *host_ipv6 = (struct sockaddr_in6 *)&host_addr;
		host_port = ntohs(host_ipv6->sin6_port);
		inet_ntop(AF_INET6, &host_ipv6->sin6_addr, host_ip, INET6_ADDRSTRLEN);
	}

	inet_ntop(AF_INET6, &client_addr.sin6_addr, client_ip, INET6_ADDRSTRLEN);
	syslog(LOG_INFO, "[%s]:%d connected to [%s]:%d",
		client_ip, ntohs(client_addr.sin6_port), host_ip, host_port);

	return 0;
}

int set_nonblock(int sockfd)
{
	int flags, yes = 1;

	if ((flags = fcntl(sockfd, F_GETFL)) == -1) {
		return -1;
	}

	flags |= O_NONBLOCK;
	if (fcntl(sockfd, F_SETFL, flags) == -1) {
		return -1;
	}

	if (setsockopt(sockfd, SOL_TCP, TCP_NODELAY, &yes, sizeof(int)) == -1) {
		return -1;
	}

	return 0;
}

int add_epoll_event(int epollfd, int sockfd)
{
	struct epoll_event ev;
	int ret;

	ev.events = EPOLLIN | EPOLLET;
	ev.data.fd = sockfd;
	ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, sockfd, &ev);

	return ret;
}

int init_session(int clientfd, int hostfd)
{
        int epollfd;

	if (set_nonblock(clientfd) == -1) {
		return -1;
	}
	if (set_nonblock(hostfd) == -1) {
		return -1;
	}

        if ((epollfd = epoll_create1(0)) == -1) {
                return -1;
        }
	if (add_epoll_event(epollfd, clientfd) == -1) {
		return -1;
	}
	if (add_epoll_event(epollfd, hostfd) == -1) {
		return -1;
	}

        return epollfd;
}

int transmit_data(int recvfd, int sendfd)
{
        char buffer[BUFF_SIZE];
        int total;

        for (;;) {
                total = recv(recvfd, buffer, BUFF_SIZE, 0);
		if (total == -1) {
                        int err = errno;
                        if (err == EAGAIN || err == EWOULDBLOCK) {
                                return 0;
                        } else {
                                return -1;
                        }
                } else if (total == 0) {
			return -1;
		}

                total = send(sendfd, buffer, total, 0);
                if (total == -1) {
                        return -1;
                }
        }

        return total;
}

int svsocks_session(int epollfd, int clientfd, int hostfd)
{
        struct epoll_event events[2];
        int nfds, n, ret;

        for (;;) {
                nfds = epoll_wait(epollfd, events, 2, -1);
                if (nfds == -1) {
                        return -1;
                }

                for (n = 0; n < nfds; n++) {
                        if ((events[n].events & EPOLLERR) ||
				(events[n].events & EPOLLHUP) ||
				(!(events[n].events & EPOLLIN))) {
				return -1;
			} else if (events[n].data.fd == clientfd) {
				ret = transmit_data(clientfd, hostfd);
                        } else if (events[n].data.fd == hostfd) {
				ret = transmit_data(hostfd, clientfd);
                        }
                }
                if (ret == -1) {
                        return -1;
                }
        }

        return 0;
}

void destroy_session(int epollfd, int clientfd, int hostfd)
{
        close(epollfd);
        close(clientfd);
        close(hostfd);
}

int handle_client(int clientfd)
{
	int epollfd, hostfd;

	if (method_negotiation(clientfd) == -1) {
		close(clientfd);
		return -1;
	}
	if ((hostfd = process_request(clientfd)) == -1) {
		close(clientfd);
		return -1;
	}
	log_session(clientfd, hostfd);

	if ((epollfd = init_session(clientfd, hostfd)) == -1) {
		close(clientfd);
		close(hostfd);
		return -1;
	}

	svsocks_session(epollfd, clientfd, hostfd);
	destroy_session(epollfd, clientfd, hostfd);
	return 0;
}

void *svsocks_worker(void *arg)
{
	int clientfd;
	socklen_t len = sizeof(struct sockaddr_in6);
	struct sockaddr_in6 addr;
	char client_addr[INET6_ADDRSTRLEN];

	for (;;) {
		pthread_mutex_lock(&server_mtx);
		clientfd = accept(serverfd, (struct sockaddr *)&addr, &len);
		pthread_mutex_unlock(&server_mtx);

		if (clientfd == -1) {
			continue;
		}

		inet_ntop(AF_INET6, &addr.sin6_addr.s6_addr, client_addr, INET6_ADDRSTRLEN);
		syslog(LOG_INFO, "[%s]:%d connected", client_addr, ntohs(addr.sin6_port));
		handle_client(clientfd);
		syslog(LOG_INFO, "[%s]:%d disconnected", client_addr, ntohs(addr.sin6_port));
	}
}

void init_threads(int nthreads)
{
	int i, ret;
	pthread_t tid;

	ret = pthread_mutex_init(&server_mtx, NULL);
	if (ret != 0) {
		syslog(LOG_ERR, "pthread_mutex_init error [%d] : could not initalize mutex",
			__LINE__);
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < nthreads; i++) {
		ret = pthread_create(&tid, NULL, svsocks_worker, NULL);
		if (ret != 0) {
			syslog(LOG_ERR, "pthread_create error [%d] : %s",
				__LINE__, strerror(ret));
			exit(EXIT_FAILURE);
		}
	}
}

void init_socket(char *listen_addr, int listen_port)
{
	struct sockaddr_in6 addr;
	int yes = 1, no = 0;

	memset(&addr, 0, sizeof(struct sockaddr_in6));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(listen_port);
	inet_pton(AF_INET6, listen_addr, &addr.sin6_addr.s6_addr);

	if ((serverfd = socket(AF_INET6, SOCK_STREAM, 0)) == -1) {
		syslog(LOG_ERR, "socket error [%d] : %s", __LINE__, strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (setsockopt(serverfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
		syslog(LOG_ERR, "setsockopt error [SO_REUSEADDR][%d] : %s",
			__LINE__, strerror(errno));
		close(serverfd);
		exit(EXIT_FAILURE);
	}
	if (setsockopt(serverfd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(int)) == -1) {
		syslog(LOG_ERR, "setsockopt error [IPV6_V6ONLY][%d] : %s",
			__LINE__, strerror(errno));
		close(serverfd);
		exit(EXIT_FAILURE);
	}
	if (bind(serverfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in6)) == -1) {
		syslog(LOG_ERR, "bind error [%d] : %s", __LINE__, strerror(errno));
		close(serverfd);
		exit(EXIT_FAILURE);
	}
	if (listen(serverfd, BACKLOG) == -1) {
		syslog(LOG_ERR, "listen error [%d] : %s", __LINE__, strerror(errno));
		close(serverfd);
		exit(EXIT_FAILURE);
	}
}

void handle_signal(int signum)
{
	long i;

	syslog(LOG_INFO, "closing svsocks.");

	for (i = 0; i < sysconf(_SC_OPEN_MAX); i++) {
		close(i);
	}
	exit(EXIT_SUCCESS);
}

void init_signal()
{
	struct sigaction act;

	memset(&act, 0, sizeof(struct sigaction));
	act.sa_handler = &handle_signal;

	if (sigaction(SIGINT, &act, NULL) == -1) {
		syslog(LOG_ERR, "sigaction error [%d] : %s", __LINE__, strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (sigaction(SIGTERM, &act, NULL) == -1) {
		syslog(LOG_ERR, "sigaction error [%d] : %s", __LINE__, strerror(errno));
		exit(EXIT_FAILURE);
	}

	memset(&act, 0, sizeof(struct sigaction));
	act.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &act, NULL) == -1) {
		syslog(LOG_ERR, "sigaction error [%d] : %s", __LINE__, strerror(errno));
		exit(EXIT_FAILURE);
	}
}

void init_syslog()
{
	openlog(SYSLOG_IDENT, LOG_NDELAY | LOG_PID, LOG_USER);
}

void daemonize_server()
{
	int fd;
	long i;
	struct sigaction act;

	for (i = 3; i < sysconf(_SC_OPEN_MAX); i++) {
		close(i);
	}

	act.sa_handler = SIG_DFL;
	for (i = 0; i < _NSIG; i++) {
		sigaction(i, &act, NULL);
	}

	switch (fork()) {
	case -1:
		exit(EXIT_FAILURE);
	case 0:
		break;
	default:
		exit(EXIT_SUCCESS);
	}

	if (setsid() == -1) {
		exit(EXIT_FAILURE);
	}

	switch (fork()) {
	case -1:
		exit(EXIT_FAILURE);
	case 0:
		break;
	default:
		exit(EXIT_SUCCESS);
	}

	for (i = 0; i < 3; i++) {
		close(i);
	}

	if ((fd = open("/dev/null", O_RDWR)) == -1) {
		exit(EXIT_FAILURE);
	}
	if (dup2(fd, 1) != 1) {
		exit(EXIT_FAILURE);
	}
	if (dup2(fd, 2) != 2) {
		exit(EXIT_FAILURE);
	}

	umask(0);
	if (chdir("/") == -1) {
		exit(EXIT_FAILURE);
	}
}

void svsocks_usage()
{
	fprintf(stdout, "usage : ./svsocks -a [listen address]\
 -p [listen port] -n [number of threads]\n");
}

void arg_parser(int argc, char *argv[], char *listen_address,
		int *listen_port, int *nthreads){
	int opt;

	while ((opt = getopt(argc, argv, "a:p:n:h")) != -1) {
		switch (opt) {
		case 'a':
			strncpy(listen_address, optarg, INET6_ADDRSTRLEN);
			break;
		case 'p':
			*listen_port = atoi(optarg);
			break;
		case 'n':
			*nthreads = atoi(optarg);
			break;
		case 'h':
			svsocks_usage();
			exit(EXIT_SUCCESS);
		}
	}
}

int main(int argc, char *argv[])
{
	char listen_address[INET6_ADDRSTRLEN];
	int listen_port, nthreads;

	strncpy(listen_address, LISTEN_ADDRESS, INET6_ADDRSTRLEN);
	listen_port = LISTEN_PORT;
	nthreads = NTHREADS;

	if (argc > 1) {
		arg_parser(argc, argv, listen_address, &listen_port, &nthreads);
	}

	daemonize_server();
	init_syslog();
	init_signal();
	init_socket(listen_address, listen_port);
	init_threads(nthreads);
	syslog(LOG_INFO, "svsocks started. listening on [%s]:%d, total threads : %d",
		listen_address, listen_port, nthreads);

	for (;;) {
		pause();
	}

	exit(EXIT_SUCCESS);
}
