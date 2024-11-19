
#ifndef _DRIVER_RAWSOCK_H_
#define _DRIVER_RAWSOCK_H_


//Dependencies
#include "core/nic.h"

//Maximum packet size
#ifndef PCAP_DRIVER_MAX_PACKET_SIZE
   #define PCAP_DRIVER_MAX_PACKET_SIZE 1536
#elif (PCAP_DRIVER_MAX_PACKET_SIZE < 1)
   #error PCAP_DRIVER_MAX_PACKET_SIZE parameter is not valid
#endif

//Maximum number of packets in the receive queue
#ifndef PCAP_DRIVER_QUEUE_SIZE
   #define PCAP_DRIVER_QUEUE_SIZE 64
#elif (PCAP_DRIVER_QUEUE_SIZE < 1)
   #error PCAP_DRIVER_QUEUE_SIZE parameter is not valid
#endif

//Receive timeout in milliseconds
#ifndef PCAP_DRIVER_TIMEOUT
   #define PCAP_DRIVER_TIMEOUT 1
#elif (PCAP_DRIVER_TIMEOUT < 1)
   #error PCAP_DRIVER_TIMEOUT parameter is not valid
#endif


//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//PCAP driver
extern const NicDriver rawsockDriver;

//PCAP related functions
error_t rawsockDriverInit(NetInterface *interface);

void rawsockDriverTick(NetInterface *interface);

void rawsockDriverEnableIrq(NetInterface *interface);
void rawsockDriverDisableIrq(NetInterface *interface);

void rawsockDriverEventHandler(NetInterface *interface);

error_t rawsockDriverSendPacket(NetInterface *interface,
   const NetBuffer *buffer, size_t offset, NetTxAncillary *ancillary);

error_t rawsockDriverUpdateMacAddrFilter(NetInterface *interface);

void rawsockDriverTask(NetInterface *interface);

//C++ guard
#ifdef __cplusplus
}
#endif


#endif // _DRIVER_RAWSOCK_H_


