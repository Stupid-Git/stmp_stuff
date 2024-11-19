 

 

/*
 Using RAW Sockets
 RAW sockets allows you to bypass the TCP/UDP layer (Layer 4) in the RtxTcpIp stack and communicate directly with the Network IP layer (Layer 3). This functionality allows you to skip the addition of TCP/UDP protocols to your frames and, optionally, provide a comparable protocol of your own.

 With the current implementation, only one raw socket can be opened per device at any given time. To create a raw socket, the type field should be set to SOCK_RAW and the protocol field should be IPPROTO_RAW:

 sock = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
 An application must use sendto to send datagrams on a raw socket. Also, for the current implementation, the application must build the entire IP datagram, including the IP header. No processing is performed by the IP layer on a raw Ethernet socket except for setting the IP header checksum bit to 0. This lets the stack, versus the application, calculate the checksum and populate the IP header checksum value accordingly.

 An application must use recvfrom to read datagrams from a raw socket. Before you can receive packets on a raw socket, you must bind the socket to the IP address of the interface on which you want to receive packets.

 The following pseudo code shows you how to create the socket, define the IP header, and send and receive using the socket.

 char sendbuf[maxsize];
 char recvbuf[maxsize];

 char *Iphdr = sendbuf;

 sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
 Iphdr[0] = version
 IPhdr[1] = Internet header length
 IPhdr[2] = Type of Service
 IPhdr[3] = Total Length
 IPhdr[4] = Identification
 IPhdr[5] = Flags
 IPhdr[6] = Fragment Offset
 IPhdr[7] = Time to Live
 IPhdr[8] = Protocol
 IPhdr[9] = Header Checksum
 IPhdr[10] = Source IP address
 IPhdr[11] = destination IP address
 bind(sock, (sockaddr*) & sendaddr, sizeof(sendaddr);
 if (transmit)
 len = sendto(sock, sendbuf, sizeof(sendbuf), 0,(SOCKADDR *)
 &pFrom, iFromSize);
 else
 len = recvfrom(sock, recvbuf, sizeof(recvbuf), 0,(SOCKADDR *)
 &pFrom, &iFromSize);
 */
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <netinet/if_ether.h>

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>


#include "raw_sock.h"

#define DEST_MAC0	0x00
#define DEST_MAC1	0x00
#define DEST_MAC2	0x00
#define DEST_MAC3	0x00
#define DEST_MAC4	0x00
#define DEST_MAC5	0x00

#define ETHER_TYPE	0x0800

#define BUF_SIZ		1024


//==========================================================
//#define DEFAULT_IF	"eth0"
//#define DEFAULT_IF	"eno1"
#define DEFAULT_IF	"usb0"
static int G_ifindex;

// https://github.com/c-bata/xpcap/blob/master/sniffer.c

error_t RAW_open(int *psd)
{
    error_t err;
    err = NO_ERROR;
    *psd = 0;

    //////////////////////////////////
    struct ifreq if_req;
    struct sockaddr_ll sa;
    int soc;

    if ((soc = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
        perror("socket");
        return -1;
    }

    //strcpy(if_req.ifr_name, "eno1"); //params.interface);
    //strcpy(if_req.ifr_name, "eth0"); //params.interface);
    //NG strcpy(if_req.ifr_name, "wwan0"); //params.interface);
    strcpy(if_req.ifr_name, "usb0"); //params.interface);
    if (ioctl(soc, SIOCGIFINDEX, &if_req) == -1) {
        perror("ioctl SIOCGIFINDEX");
        close(soc);
        return -1;
    }
    {
        // Get copy of the interface index for send
        G_ifindex = if_req.ifr_ifindex;
        
        printf("ifr_ifindex = %d\r\n", if_req.ifr_ifindex);
    }

    sa.sll_family = PF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex = if_req.ifr_ifindex;
    if (bind(soc, (struct sockaddr *) &sa, sizeof(sa)) == -1) {
        perror("bind");
        close(soc);
        return (-1);
    }

    if (ioctl(soc, SIOCGIFFLAGS, &if_req) == -1) {
        perror("ioctl");
        close(soc);
        return (-1);
    }

    if_req.ifr_flags = if_req.ifr_flags|IFF_PROMISC|IFF_UP;
    if (ioctl(soc, SIOCSIFFLAGS, &if_req) == -1) {
        perror("ioctl");
        close(soc);
        return (-1);
    }

    //////////////////////////////////
	*psd = soc;
	return err;

}



error_t RAW_close(int sd)
{
    
    close(sd);
    
    return NO_ERROR;
    
}

int RAW_send(int sd, void* data, size_t length)
{
    int ret;
    
    #define ETH_MAC_ADDR_LEN 6
    
    struct sockaddr_ll dest_addr;
    memset(&dest_addr,0,sizeof(struct sockaddr_ll));
    dest_addr.sll_family = PF_PACKET;
    dest_addr.sll_protocol = htons(8902);
    dest_addr.sll_ifindex = G_ifindex; //2;//0;//TODO info->if_index;
    dest_addr.sll_halen = ETH_MAC_ADDR_LEN;
    dest_addr.sll_pkttype = PACKET_OTHERHOST;
    dest_addr.sll_hatype   = ARPHRD_ETHER;
    memset(dest_addr.sll_addr,0,8);

    dest_addr.sll_addr[0] = 0x00;
    dest_addr.sll_addr[1] = 0xAB;
    dest_addr.sll_addr[2] = 0xCD;
    dest_addr.sll_addr[3] = 0xEF;
    dest_addr.sll_addr[4] = 0x00;
    dest_addr.sll_addr[5] = 0x86;

    ret = sendto(sd, data, length, 0, (struct sockaddr*) &dest_addr, sizeof(struct sockaddr_ll));
    
//printf("RAW_send: len = %d, ret = %d\r\n", length, ret);

    return ret;
}

/*
#include <sys/types.h>
#include <sys/socket.h>

ssize_t recv(int sockfd, void *buf, size_t len, int flags);

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen);

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
*/

int RAW_recv(int sd, void *buf, size_t len);
int RAW_recv(int sd, void *buf, size_t len)
{
    return -1; //TODO
}


