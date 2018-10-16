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
	char subor[150];
	FILE *vystup;
	u_int i = 0;
	int res,dlzkaAPI,dlzkaMedium,typ,pozicia,pom1,pom2;
	int framecounter = 0;
	printf("zadaj cestu k suboru PCAP : ramce/trace-26.pcap\n");
	printf("maximalna dlzka cesty je 150 znakov\n");
	gets(subor);

	vystup = fopen("output.txt", "w");
	if (vystup == NULL) { printf("Subor nebolo mozne otvorit\n");  return 0; }

	//vytvorim specialny zdfrojovy string ktory budem dalej este pouzivat
	if (pcap_createsrcstr(source,PCAP_SRC_FILE,NULL,NULL,subor,errbuf) != 0)
	{
		fprintf(stderr, "\nNepodarilo sa vytvorit zdrojovy string\n");
		return -1;
	}

	//idem otvarat PCAP subor, potrebujem pri tom zdrojovy string ktory je ulozeny v premennej source
	if ((fp = pcap_open(source,65536,PCAP_OPENFLAG_PROMISCUOUS,1000,NULL,errbuf)) == NULL)
	{
		fprintf(stderr, "\nNepodarilo sa otvorit subor %s.\n", source);
		return -1;
	}

	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{
		printf("ramec %d\n", ++framecounter);
		fprintf(vystup,"ramec %d\n", framecounter);
		dlzkaAPI = header->len;
		printf("dlzka ramca poskytnuta pcap API - %d B\n", dlzkaAPI);
		fprintf(vystup,"dlzka ramca poskytnuta pcap API - %d B\n", dlzkaAPI);
		if (dlzkaAPI < 60)
		{
			dlzkaMedium = 64;
		}
		else 
		{
			dlzkaMedium = dlzkaAPI + 4;
		}
		printf("dlzka ramca prenasaneho po mediu - %d B\n", dlzkaMedium);
		fprintf(vystup,"dlzka ramca prenasaneho po mediu - %d B\n", dlzkaMedium);
		typ = pkt_data[12] * 256 + pkt_data[13];
		if (typ > 1500) { printf("Ethernet II\n"); fprintf(vystup, "Ethernet II\n"); }
		else
		{
			if (pkt_data[13] == 170) { printf("IEEE 802.3 LLC + SNAP\n"); fprintf(vystup, "IEEE 802.3 LLC + SNAP\n"); }
			else if (pkt_data[13] == 255) { printf("IEEE 802.3 - RAW\n"); fprintf(vystup, "IEEE 802.3 - RAW\n"); }
			else { printf("IEEE 802.3 LLC\n"); fprintf(vystup,"IEEE 802.3 LLC\n"); }
		}
		printf("Zdrojova MAC adressa : ");
		fprintf(vystup,"Zdrojova MAC adressa : ");
		for (i = 6; i < 12; i++) { printf("%.2x ", pkt_data[i]); fprintf(vystup,"%.2x ", pkt_data[i]); }
		printf("\n");
		fprintf(vystup,"\n");
		printf("Cielova MAC adressa : ");
		fprintf(vystup,"Cielova MAC adressa : ");
		for (i = 0; i < 6; i++) { printf("%.2x ", pkt_data[i]); fprintf(vystup, "%.2x ", pkt_data[i]); }
		printf("\n");
		fprintf(vystup,"\n");
		
		
		
		
		typ = pkt_data[12] * 256 + pkt_data[13];
		if (typ > 1500)
		{
			if (typ == 2048)
			{
				printf("IPv4\n");
				fprintf(vystup,"IPv4\n");

				//zdrojova IP
				printf("zdrojova IP adresa: ");
				fprintf(vystup,"zdrojova IP adresa: ");
				for (i = 0; i < 4; i++)
				{
					printf("%d", pkt_data[26 + i]);
					fprintf(vystup,"%d", pkt_data[26 + i]);
					if (i < 3) { printf("."); fprintf(vystup, "."); }
				}
				printf("\n");
				fprintf(vystup,"\n");

				//cielova IP
				printf("cielova IP adresa: ");
				fprintf(vystup,"cielova IP adresa: ");
				for (i = 0; i < 4; i++)
				{
					printf("%d", pkt_data[30 + i]);
					fprintf(vystup,"%d", pkt_data[30 + i]);
					if (i < 3) printf(".");
					if (i < 3) fprintf(vystup, ".");
				}
				printf("\n");
				fprintf(vystup, "\n");


				pozicia = pkt_data[34];
				switch (pkt_data[23])
				{
				case 6:
					printf("TCP\n");
					fprintf(vystup, "TCP\n");
					pom1 = pkt_data[34] * 256 + pkt_data[35];
					printf("Zdrojovy port: %d\n", pom1);
					fprintf(vystup,"Zdrojovy port: %d\n", pom1);
					pom2 = pkt_data[36] * 256 + pkt_data[37];
					printf("Cielovy port port: %d\n", pom2);
					fprintf(vystup,"Cielovy port port: %d\n", pom2);
					break;
				}
			}

		}
		for (i = 1; (i < header->caplen+1); i++)
		{
			if (((i - 1) % 8) == 0 && (i - 1) % 16 == 8) { printf("  "); fprintf(vystup, "  "); }
			{printf("%.2x ", pkt_data[i - 1]); fprintf(vystup,"%.2x ", pkt_data[i - 1]); }
			if ((i % LINE_LEN) == 0) { printf("\n"); fprintf(vystup, "\n"); }

		}

		printf("\n");
		fprintf(vystup,"\n");
		printf("\n");
		fprintf(vystup, "\n");

		
		}
		printf("\n");
		fprintf(vystup,"\n");

	}