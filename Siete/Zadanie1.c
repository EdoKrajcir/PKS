#include <stdio.h>
#include <pcap.h>

#define LINE_LEN 16

int main()
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	char source[PCAP_BUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	u_int i = 0;
	int res,dlzkaAPI;
	int framecounter = 0;


	/* Create the source string according to the new WinPcap syntax */
	if (pcap_createsrcstr(source,         // variable that will keep the source string
		PCAP_SRC_FILE,  // we want to open a file
		NULL,           // remote host
		NULL,           // port on the remote host
		"ramce/trace-26.pcap",        // name of the file we want to open
		errbuf          // error buffer
	) != 0)
	{
		fprintf(stderr, "\nError creating a source string\n");
		return -1;
	}

	/* Open the capture file */
	if ((fp = pcap_open(source,         // name of the device
		65536,          // portion of the packet to capture
						// 65536 guarantees that the whole packet will be captured on all the link layers
		PCAP_OPENFLAG_PROMISCUOUS,     // promiscuous mode
		1000,              // read timeout
		NULL,              // authentication on the remote machine
		errbuf         // error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the file %s.\n", source);
		return -1;
	}

	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{
		printf("ramec %d\n", ++framecounter);
		dlzkaAPI = header->len;
		printf("dlzka ramca poskytnuta pcap API - %d B\n", dlzkaAPI);

	}
}