#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "sha256.c"

#define NETLINK_USER 31

#define MAX_PAYLOAD 1024 /* maximum payload size*/
struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
int sock_fd;
struct msghdr msg;

int main()
{
    char path[MAX_PAYLOAD];
    sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (sock_fd < 0)
    {
	    printf("ERROR !!!\n");
	    return -1;
    }

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid(); /* self pid */
    bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

    memset(&dest_addr, 0, sizeof(dest_addr));
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0; /* For Linux Kernel */
    dest_addr.nl_groups = 0; /* unicast */

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;


    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    for (;;)
    {
    	/* Read message from kernel */
	    printf("Waiting for message from kernel\n");
	    recvmsg(sock_fd, &msg, 0);

	    /*NLMSG_DATA(nlh), defined in netlink.h, 
	    returns a pointer to the payload of the netlink message*/
	    strcpy(path, NLMSG_DATA(nlh));
	    printf("Received message payload: %s\n", NLMSG_DATA(nlh));

	    /*compute the sha of executable according to received path,
	    and store in hash*/

	    /*Compute sha256*/
	    unsigned char hash[32];
	    int idx;
	    SHA256_CTX ctx;


		FILE* file = fopen(path, "rb");
	    if(!file) return -1;

	    sha256_init(&ctx);
	    const int bufSize = 32768;
	    char* buffer = malloc(bufSize);
	    int bytesRead = 0;

	    if(!buffer) 
	    	return -1;

	    while((bytesRead = fread(buffer, 1, bufSize, file)))
	    {
	        sha256_update(&ctx, buffer, bytesRead);
	    }
	    sha256_final(&ctx,hash);

	    print_hash(hash);
	    fclose(file);
	    free(buffer);
	    


		
	    /*Send sha256 value to kernel*/
	    strcpy(NLMSG_DATA(nlh), hash);
	    printf("Sending message to kernel\n");
	    sendmsg(sock_fd, &msg, 0);
    }
}