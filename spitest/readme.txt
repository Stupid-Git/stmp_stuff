
Copied from:

https://github.com/rm-hull/spidev-test/tree/master

gcc spidev_test2.c -o spidev_test2


root@stm32mp1:~# spidev_test -D /dev/spidev1.0 -p slave-hello-to-master -v

local $: ./spidev_test2 -D /dev/spidev0.0 -p master-hello-to-slave -v


