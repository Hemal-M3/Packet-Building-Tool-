#include <stdio.h>
#include <pcap.h>



int get_adapter(char name[][256], char descs[][512], int max_adapters) {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i = 0;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* Retrieve the device list from the local machine */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,
         NULL, /* auth is not needed */
        &alldevs, errbuf) == -1) {
        fprintf(stderr,
        "Error in pcap_findalldevs_ex: %s\n",
        errbuf);
        exit(1);
    }

    for (d = alldevs; d && i < max_adapters; d = d->next) {
      strncpy(name[i], d->name, 256);
      name[i][255] = "\0";

      if (d->description) {
        strncpy(descs[i], d->description, 511);
      } else {
          strncpy(descs[i], "No description", 511);
      }
      descs[i][511] = "\0";
      i++;
    }
    pcap_freealldevs(alldevs);
    return i;
}


