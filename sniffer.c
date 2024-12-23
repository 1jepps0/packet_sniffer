#include <pcap/pcap.h>
#include <stdio.h>

int main(int argc, char *argv[])
{

    // find the default device
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *device;

    int dev_error_code = pcap_findalldevs(&device, errbuf);
    char *dev = device->name;

    if (device == NULL || dev_error_code == -1) {
        fprintf(stderr, "Couldn't find default device %s\n", errbuf);
        return 2;
    } 
    else {
        printf("Device: %s\n", dev);
    }

    // open the device for sniffing
    pcap_t *handle;
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }


    return 0;
}
