//Switch to the appropriate trace level
#define TRACE_LEVEL NIC_TRACE_LEVEL

//Dependencies
#include <stdlib.h>
#include "core/net.h"
//#include "drivers/pcap/pcap_driver.h"
#include "driver_rawsock.h"
#include "debug.h"

#include "raw_sock.h"

//Undefine conflicting definitions
#undef Socket
#undef htons
#undef htonl
#undef ntohs
#undef ntohl

//PCAP dependencies
//#include <pcap.h>

//Undefine conflicting definitions
#undef interface

/**
 * @brief Packet descriptor
 **/

typedef struct {
	size_t length;
	uint8_t data[PCAP_DRIVER_MAX_PACKET_SIZE];
} PcapDriverPacket;

/**
 * @brief PCAP driver context
 **/

typedef struct {
	//pcap_t *handle;
	int sd;
	uint_t writeIndex;
	uint_t readIndex;
	PcapDriverPacket queue[PCAP_DRIVER_QUEUE_SIZE];
} RawsockDriverContext;

/**
 * @brief PCAP driver
 **/

const NicDriver rawsockDriver = { NIC_TYPE_ETHERNET, ETH_MTU, rawsockDriverInit,
		rawsockDriverTick, rawsockDriverEnableIrq, rawsockDriverDisableIrq,
		rawsockDriverEventHandler, rawsockDriverSendPacket,
		rawsockDriverUpdateMacAddrFilter, NULL, NULL, NULL, TRUE, TRUE, TRUE,
		TRUE };

/**
 * @brief PCAP driver initialization
 * @param[in] interface Underlying network interface
 * @return Error code
 **/


error_t rawsockDriverInit(NetInterface *interface) {
	error_t err;
//   int_t ret;
//   uint_t i;
//   uint_t j;
//   pcap_if_t *device;
//   pcap_if_t *deviceList;
//   struct bpf_program filerCode;
//   char_t filterExpr[256];
//   char_t errorBuffer[PCAP_ERRBUF_SIZE];
	RawsockDriverContext *context;
#if (NET_RTOS_SUPPORT == ENABLED)
	OsTaskId taskId;
#endif

	//Debug message
	TRACE_INFO("Initializing RawSock driver...\r\n");

	//Allocate PCAP driver context
	context = (RawsockDriverContext*) osAllocMem(sizeof(RawsockDriverContext));

	//Failed to allocate memory?
	if (context == NULL) {
		//Debug message
		printf("Failed to allocate context!\r\n");

		//Report an error
		return ERROR_FAILURE;
	}
	printf("[0] ");
	//Attach the PCAP driver context to the network interface
	*((RawsockDriverContext**) interface->nicContext) = context;
	//Clear PCAP driver context
	osMemset(context, 0, sizeof(RawsockDriverContext));

	printf("[1] ");
//===============================================================================
	int sd;


#if 1
	err = RAW_open(&sd);
	if (err != NO_ERROR) {
		return err;
	}
#endif
	context->sd = sd;
	printf("sd = %d\r\n", sd);
	//===============================================================================

#if (NET_RTOS_SUPPORT == ENABLED)
	printf("STARTING PCAP TASK");
	//Create the receive task
	taskId = osCreateTask("PCAP", (OsTaskCode) rawsockDriverTask, interface,
			NULL);

	//Failed to create the task?
	if (taskId == OS_INVALID_TASK_ID) {
		//Debug message
		printf("Failed to create task!\r\n");

		//Clean up side effects
		RAW_close(context->sd);
		free(context);

		//Report an error
		return ERROR_FAILURE;
	}
#endif

	//Accept any packets from the upper layer
	osSetEvent(&interface->nicTxEvent);
//printf("END END END END END END ");
//fflush(stdout);
	//Return status code
	return NO_ERROR;
}

/**
 * @brief PCAP timer handler
 *
 * This routine is periodically called by the TCP/IP stack to handle periodic
 * operations such as polling the link state
 *
 * @param[in] interface Underlying network interface
 **/

void rawsockDriverTick(NetInterface *interface) {
	//Not implemented
}

/**
 * @brief Enable interrupts
 * @param[in] interface Underlying network interface
 **/

void rawsockDriverEnableIrq(NetInterface *interface) {
	//Not implemented
}

/**
 * @brief Disable interrupts
 * @param[in] interface Underlying network interface
 **/

void rawsockDriverDisableIrq(NetInterface *interface) {
	//Not implemented
}

/**
 * @brief PCAP event handler
 * @param[in] interface Underlying network interface
 **/

void rawsockDriverEventHandler(NetInterface *interface) {
	uint_t n;
	RawsockDriverContext *context;
	NetRxAncillary ancillary;

//printf("pcapDriverEventHandler.\r\n");

	//Point to the PCAP driver context
	context = *((RawsockDriverContext**) interface->nicContext);

	//Process all pending packets
	while (context->queue[context->readIndex].length > 0) {
		//Additional options can be passed to the stack along with the packet
		ancillary = NET_DEFAULT_RX_ANCILLARY;

		//Pass the packet to the upper layer
		nicProcessPacket(interface, context->queue[context->readIndex].data,
				context->queue[context->readIndex].length, &ancillary);

		//Compute the index of the next packet descriptor
		n = (context->readIndex + 1) % PCAP_DRIVER_QUEUE_SIZE;

		//Release the current packet
		context->queue[context->readIndex].length = 0;
		//Point to the next packet descriptor
		context->readIndex = n;
	}
}

/**
 * @brief Send a packet
 * @param[in] interface Underlying network interface
 * @param[in] buffer Multi-part buffer containing the data to send
 * @param[in] offset Offset to the first data byte
 * @param[in] ancillary Additional options passed to the stack along with
 *   the packet
 * @return Error code
 **/
void debugDisplayArray(FILE *stream, const char_t *prepend, const void *data,  size_t length);

error_t rawsockDriverSendPacket(NetInterface *interface,
		const NetBuffer *buffer, size_t offset, NetTxAncillary *ancillary) {
	int_t ret;
	size_t length;
	RawsockDriverContext *context;
	uint8_t temp[PCAP_DRIVER_MAX_PACKET_SIZE];

//printf("pcapDriverSendPacket.\r\n");

	//Point to the PCAP driver context
	context = *((RawsockDriverContext**) interface->nicContext);

	//Retrieve the length of the packet
	length = netBufferGetLength(buffer) - offset;

	//Check the frame length
	if (length > PCAP_DRIVER_MAX_PACKET_SIZE) {
		//The transmitter can accept another packet
		osSetEvent(&interface->nicTxEvent);
		//Report an error
		return ERROR_INVALID_LENGTH;
	}

	//Copy the packet to the transmit buffer
	netBufferRead(temp, buffer, offset, length);

//   printf("\r\n");
//	printf("sd = %d\r\n", context->sd);
//	printf("pcap_sendpacket: len = %ld\r\n", length);
//	debugDisplayArray(NULL, "", temp, length);
	//Send packet

    ret = RAW_send(context->sd, temp, length);
    
	//The transmitter can accept another packet
	osSetEvent(&interface->nicTxEvent);

	//Return status code
	if (ret < 0) {
		perror("send");
		printf("ERROR ret = %d", ret);
		return ERROR_FAILURE;
	} else {
		return NO_ERROR;
	}
}

/**
 * @brief Configure MAC address filtering
 * @param[in] interface Underlying network interface
 * @return Error code
 **/

error_t rawsockDriverUpdateMacAddrFilter(NetInterface *interface) {
	//Not implemented
	return NO_ERROR;
}


#include <sys/types.h>
#include <sys/socket.h>

/**
 * @brief PCAP receive task
 * @param[in] interface Underlying network interface
 **/

void rawsockDriverTask(NetInterface *interface) {
	int_t ret;
	uint_t n;
	uint_t length;
	//const uint8_t *data;

	size_t nbytes = 1536;
	uint8_t data[1536];

	//struct pcap_pkthdr *header;
	RawsockDriverContext *context;

	//Point to the PCAP driver context
	context = *((RawsockDriverContext**) interface->nicContext);

	printf("\r\n--rawsockDriverTask Start--\r\n");
	fflush(stdout);

	//Process events
	while (1) {
		//Wait for an incoming packet
        
        //TODO ret = RAW_recv(context->sd, data, nbytes);
        
		//ret = pcap_next_ex(context->handle, &header, &data);
		//extern ssize_t read (int __fd, void *__buf, size_t __nbytes) __wur;
		//  ret = read(context->sd, data, nbytes);
		// extern ssize_t recv (int __fd, void *__buf, size_t __n, int __flags);
		// ret = recv(context->sd, data, nbytes, 0);
		ret = recvfrom(context->sd, data, nbytes, 0, NULL, NULL);

//printf("*");
//printf("pcap_recvpacket: len = %d\r\n", length);
//debugDisplayArray(NULL, "", data, length);
//fflush(stdout);
#if 0 //debug
        if (
            (data[0] == 0x00) & (data[1] == 0xAB) & (data[2] == 0xCD) &
            (data[3] == 0xEF) & (data[4] == 0x00) & (data[5] == 0x86)
            /*
            (data[0] == 0x54) &
            (data[1] == 0xBe) &
            (data[2] == 0xf7) &
            (data[3] == 0x0b) &
            (data[4] == 0x04) &
            (data[5] == 0x01)
            */
        ) {
            printf("pcap_recvpacket: len = %d\r\n", length);
            debugDisplayArray(NULL, "", data, length);
            fflush(stdout);         
        }
		//else
		//{
		//	ret = 0; //force bypass
		//}
#endif

		//Any packet received?
		if (ret > 0) {
			//Retrieve the length of the packet
			length = ret;    //header->caplen;

			//Check the length of the received packet
			if (length > 0 && length < PCAP_DRIVER_MAX_PACKET_SIZE) {
				//Check whether the link is up
				if (interface->linkState) {
					//Compute the index of the next packet descriptor
					n = (context->writeIndex + 1) % PCAP_DRIVER_QUEUE_SIZE;

					//Ensure the receive queue is not full
					if (n != context->readIndex) {
//printf("pcap_recvpacket: len = %d\r\n", length);

						//Copy the incoming packet
						osMemcpy(context->queue[context->writeIndex].data, data,
								length);
						//Save the length of the packet
						context->queue[context->writeIndex].length = length;

						//Point to the next packet descriptor
						context->writeIndex = n;

						//Set event flag
						interface->nicEvent = TRUE;
						//Notify the TCP/IP stack of the event
						osSetEvent(&netEvent);
					}

					else {
						printf("Overflow");
						printf("Overflow");
						printf("Overflow");
					}
				}
			}
		} else {
#if (NET_RTOS_SUPPORT == DISABLED)
			//No packet has been received
			break;
#endif
		}
	}
}


