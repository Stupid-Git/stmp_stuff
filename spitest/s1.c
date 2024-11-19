


#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/ioctl.h>
#include <sys/stat.h>
#include <linux/types.h>
#include <linux/spi/spidev.h>

#include "spi1.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))


static const char *device = "/dev/spidev1.0"; // Slave
static uint32_t mode;
static uint8_t bits = 8;
//static char *input_file;
//static char *output_file;
//static uint32_t speed = 500000;
static uint32_t speed = 10000000;
static uint16_t delay;
static int verbose;
static int isSlave = 1;
/*
uint8_t default_tx[] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0x40, 0x00, 0x00, 0x00, 0x00, 0x95,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xF0, 0x0D,
};
*/
uint8_t default_tx[2048];

uint8_t default_rx[ARRAY_SIZE(default_tx)] = {0, };

int main(int argc, char *argv[])
{
	int ret = 0;
	int fd;

	//parse_opts(argc, argv);

	fd = open(device, O_RDWR);
	if (fd < 0)
		pabort("can't open device");

	/*
	 * spi mode
	 */
	ret = ioctl(fd, SPI_IOC_WR_MODE, &mode);
	if (ret == -1)
		pabort("can't set spi mode");

	ret = ioctl(fd, SPI_IOC_RD_MODE, &mode);
	if (ret == -1)
		pabort("can't get spi mode");

	/*
	 * bits per word
	 */
	ret = ioctl(fd, SPI_IOC_WR_BITS_PER_WORD, &bits);
	if (ret == -1)
		pabort("can't set bits per word");

	ret = ioctl(fd, SPI_IOC_RD_BITS_PER_WORD, &bits);
	if (ret == -1)
		pabort("can't get bits per word");

	/*
	 * max speed hz
	 */
	ret = ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed);
	if (ret == -1)
		pabort("can't set max speed hz");

	ret = ioctl(fd, SPI_IOC_RD_MAX_SPEED_HZ, &speed);
	if (ret == -1)
		pabort("can't get max speed hz");

	printf("spi mode: 0x%x\n", mode);
	printf("bits per word: %d\n", bits);
	printf("max speed: %d Hz (%d KHz)\n", speed, speed/1000);

	//transfer(fd, default_tx, default_rx, sizeof(default_tx), isSlave);
    //=========================================================================
    int i;
    for(i=0; i<1000; i++)
    {
        sync_word S;
        hdr H;

        //S.sync_code = 0x11223344;
        //H.opcode = 0x0042;
        //H.length = 10;

        memset( default_tx, 0xcc, sizeof(default_tx));

        //Recv
     	transfer(fd, default_tx, default_rx, 8, isSlave); // recv S and H
        memcpy(&S, &default_rx[0], 4);
        memcpy(&H, &default_rx[4], 4);
        //Recv
     	transfer(fd, default_tx, default_rx, H.length, isSlave); // recv payload

//printf("\n");

        //Send
        memcpy(&default_tx[0], (uint8_t*)&S, 4);
        memcpy(&default_tx[4], (uint8_t*)&H, 4);
        memcpy(&default_tx[8], &default_rx[0], H.length);
     	transfer(fd, default_tx, default_rx, 4+4+H.length, isSlave); // send reply


        //sleep(1);
    }
    //=========================================================================



	close(fd);

	return ret;
}

