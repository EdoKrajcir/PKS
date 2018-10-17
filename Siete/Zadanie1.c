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
	int res, dlzkaAPI, dlzkaMedium, typ, pozicia, pom1, pom2, request = 2, comcounter = 0, reqrep = 2, http = 0, telnet = 0, https = 0, ssh = 0, ftpd = 0, ftpc = 0, tftp = 0;
	int framecounter = 0;
	int arpip[4];
	int bod = 0;
	printf("zadaj cestu k suboru PCAP : ramce/trace-26.pcap\n");
	printf("maximalna dlzka cesty je 150 znakov\n");
	gets(subor);
	printf("bod1 = 1\narp = 2\nhttp = 3\ntelnet = 4\nhttps = 5\nssh = 6\nftp-data = 7\nftp-control = 8\ntftp = 9\nicmp 10\n");
	scanf("%d",&bod);
	


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
	//-------------------------------------------------------------------------------------------------------
	if (bod == 2)
	{
		while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
		{
			//ARPKOM *komhead,*pom, *novy;
			++framecounter;
			typ = pkt_data[12] * 256 + pkt_data[13];
			if (typ == 2054)
				//ak bolo naposledy reply tak napis cislo komunikacie
			{
				if (reqrep == 2)
				{
					comcounter++;
					printf("Komunikacia c.%d\n", comcounter);
				}
			
			
			
					reqrep = pkt_data[20] * 256 + pkt_data[21];
					
			
				
				
						if (reqrep == 1) printf("ARP-Request, "); else printf("ARP-Reply, ");
						printf(" IP adresa: %d.", pkt_data[38]);
						printf("%d.", pkt_data[39]);
						printf("%d.", pkt_data[40]);
						printf("%d, ", pkt_data[41]);
						if (reqrep == 1) printf("MAC adresa: ???\n"); 
						else
						{
							printf("MAC adresa : ");
							for (i = 22; i < 28; i++)
							{
								printf("%.2x", pkt_data[i]);
								printf(" ");
							}
							printf("\n");
						}
							/////////////////////////sem este dopis tie blbe IPcky
							printf("Zdrojova IP: ");
							printf("%d.", pkt_data[28]);
							printf("%d.", pkt_data[29]);
							printf("%d.", pkt_data[30]);
							printf("%d", pkt_data[31]);
							printf(" Cielova IP: ");
							printf("%d.", pkt_data[38]);
							printf("%d.", pkt_data[39]);
							printf("%d.", pkt_data[40]);
							printf("%d", pkt_data[41]);
							printf("\n");
							printf("Ramec %d\n", framecounter);
							//printf("\n");
							//printf("\n");
							//zvysne vypisy ako su aj v bode 1-------------------------------------------------------
							dlzkaAPI = header->len;
							printf("dlzka ramca poskytnuta pcap API - %d B\n", dlzkaAPI);
							fprintf(vystup, "dlzka ramca poskytnuta pcap API - %d B\n", dlzkaAPI);
							if (dlzkaAPI < 60)
							{
								dlzkaMedium = 64;
							}
							else
							{
								dlzkaMedium = dlzkaAPI + 4;
							}
							printf("dlzka ramca prenasaneho po mediu - %d B\n", dlzkaMedium);
							fprintf(vystup, "dlzka ramca prenasaneho po mediu - %d B\n", dlzkaMedium);
							typ = pkt_data[12] * 256 + pkt_data[13];
							if (typ > 1500) { printf("Ethernet II\n"); fprintf(vystup, "Ethernet II\n"); }
							else
							{
								if (pkt_data[13] == 170) { printf("IEEE 802.3 LLC + SNAP\n"); fprintf(vystup, "IEEE 802.3 LLC + SNAP\n"); }
								else if (pkt_data[13] == 255) { printf("IEEE 802.3 - RAW\n"); fprintf(vystup, "IEEE 802.3 - RAW\n"); }
								else { printf("IEEE 802.3 LLC\n"); fprintf(vystup, "IEEE 802.3 LLC\n"); }
							}
							printf("Zdrojova MAC adressa : ");
							fprintf(vystup, "Zdrojova MAC adressa : ");
							for (i = 6; i < 12; i++) { printf("%.2x ", pkt_data[i]); fprintf(vystup, "%.2x ", pkt_data[i]); }
							printf("\n");
							fprintf(vystup, "\n");
							printf("Cielova MAC adressa : ");
							fprintf(vystup, "Cielova MAC adressa : ");
							for (i = 0; i < 6; i++) { printf("%.2x ", pkt_data[i]); fprintf(vystup, "%.2x ", pkt_data[i]); }
							printf("\n");
							fprintf(vystup, "\n");
							printf("\n");
							fprintf(vystup, "\n");
			}

		}
	}

	//-------------------------------------------------------------------------------------------------------
	if(bod == 1)
	{
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


//HTTP

		if (bod == 3)
		{
			
			while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
			{
				framecounter++;
				
				typ = pkt_data[12] * 256 + pkt_data[13];
				//if (typ > 1500)
					pom1 = pkt_data[34] * 256 + pkt_data[35];
					pom2 = pkt_data[36] * 256 + pkt_data[37];
					http = 0;
					if (pom1 == 80) http = 1;
					if (pom2 == 80) http = 1;
					if (typ == 2048 && pkt_data[23] == 6 && http == 1)
					{
						printf("ramec %d\n", framecounter);
						fprintf(vystup, "ramec %d\n", framecounter);
						dlzkaAPI = header->len;
						printf("dlzka ramca poskytnuta pcap API - %d B\n", dlzkaAPI);
						fprintf(vystup, "dlzka ramca poskytnuta pcap API - %d B\n", dlzkaAPI);
						if (dlzkaAPI < 60)
						{
							dlzkaMedium = 64;
						}
						else
						{
							dlzkaMedium = dlzkaAPI + 4;
						}
						printf("dlzka ramca prenasaneho po mediu - %d B\n", dlzkaMedium);
						fprintf(vystup, "dlzka ramca prenasaneho po mediu - %d B\n", dlzkaMedium);
						printf("Ethernet II\n"); fprintf(vystup, "Ethernet II\n");
						printf("Zdrojova MAC adressa : ");
						fprintf(vystup, "Zdrojova MAC adressa : ");
						for (i = 6; i < 12; i++) { printf("%.2x ", pkt_data[i]); fprintf(vystup, "%.2x ", pkt_data[i]); }
						printf("\n");
						fprintf(vystup, "\n");
						printf("Cielova MAC adressa : ");
						fprintf(vystup, "Cielova MAC adressa : ");
						for (i = 0; i < 6; i++) { printf("%.2x ", pkt_data[i]); fprintf(vystup, "%.2x ", pkt_data[i]); }
						printf("\n");
						fprintf(vystup, "\n");
						printf("IPv4\n");
						fprintf(vystup, "IPv4\n");

						//zdrojova IP
						printf("zdrojova IP adresa: ");
						fprintf(vystup, "zdrojova IP adresa: ");
						for (i = 0; i < 4; i++)
						{
							printf("%d", pkt_data[26 + i]);
							fprintf(vystup, "%d", pkt_data[26 + i]);
							if (i < 3) { printf("."); fprintf(vystup, "."); }
						}
						printf("\n");
						fprintf(vystup, "\n");

						//cielova IP
						printf("cielova IP adresa: ");
						fprintf(vystup, "cielova IP adresa: ");
						for (i = 0; i < 4; i++)
						{
							printf("%d", pkt_data[30 + i]);
							fprintf(vystup, "%d", pkt_data[30 + i]);
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
							fprintf(vystup, "Zdrojovy port: %d\n", pom1);
							pom2 = pkt_data[36] * 256 + pkt_data[37];
							printf("Cielovy port port: %d\n", pom2);
							fprintf(vystup, "Cielovy port port: %d\n", pom2);
							break;
						}
						for (i = 1; (i < header->caplen + 1); i++)
						{
							if (((i - 1) % 8) == 0 && (i - 1) % 16 == 8) { printf("  "); fprintf(vystup, "  "); }
							{printf("%.2x ", pkt_data[i - 1]); fprintf(vystup, "%.2x ", pkt_data[i - 1]); }
							if ((i % LINE_LEN) == 0) { printf("\n"); fprintf(vystup, "\n"); }
						}
						printf("\n");
						fprintf(vystup, "\n");
						printf("\n");
						fprintf(vystup, "\n");
					}

				

				
			}
			printf("\n");
			fprintf(vystup, "\n");
		}



//TELNET


		if (bod == 4)
		{

			while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
			{
				framecounter++;
				

				typ = pkt_data[12] * 256 + pkt_data[13];
				//if (typ > 1500)
				pom1 = pkt_data[34] * 256 + pkt_data[35];
				pom2 = pkt_data[36] * 256 + pkt_data[37];
				telnet = 0;
				if (pom1 == 23) telnet = 1;
				if (pom2 == 23) telnet = 1;
				if (typ == 2048 && pkt_data[23] == 6 && telnet == 1)
				{
					printf("ramec %d\n", framecounter);
					fprintf(vystup, "ramec %d\n", framecounter);
					dlzkaAPI = header->len;
					printf("dlzka ramca poskytnuta pcap API - %d B\n", dlzkaAPI);
					fprintf(vystup, "dlzka ramca poskytnuta pcap API - %d B\n", dlzkaAPI);
					if (dlzkaAPI < 60)
					{
						dlzkaMedium = 64;
					}
					else
					{
						dlzkaMedium = dlzkaAPI + 4;
					}
					printf("dlzka ramca prenasaneho po mediu - %d B\n", dlzkaMedium);
					fprintf(vystup, "dlzka ramca prenasaneho po mediu - %d B\n", dlzkaMedium);
					printf("Ethernet II\n"); fprintf(vystup, "Ethernet II\n");
					printf("Zdrojova MAC adressa : ");
					fprintf(vystup, "Zdrojova MAC adressa : ");
					for (i = 6; i < 12; i++) { printf("%.2x ", pkt_data[i]); fprintf(vystup, "%.2x ", pkt_data[i]); }
					printf("\n");
					fprintf(vystup, "\n");
					printf("Cielova MAC adressa : ");
					fprintf(vystup, "Cielova MAC adressa : ");
					for (i = 0; i < 6; i++) { printf("%.2x ", pkt_data[i]); fprintf(vystup, "%.2x ", pkt_data[i]); }
					printf("\n");
					fprintf(vystup, "\n");
					printf("IPv4\n");
					fprintf(vystup, "IPv4\n");

					//zdrojova IP
					printf("zdrojova IP adresa: ");
					fprintf(vystup, "zdrojova IP adresa: ");
					for (i = 0; i < 4; i++)
					{
						printf("%d", pkt_data[26 + i]);
						fprintf(vystup, "%d", pkt_data[26 + i]);
						if (i < 3) { printf("."); fprintf(vystup, "."); }
					}
					printf("\n");
					fprintf(vystup, "\n");

					//cielova IP
					printf("cielova IP adresa: ");
					fprintf(vystup, "cielova IP adresa: ");
					for (i = 0; i < 4; i++)
					{
						printf("%d", pkt_data[30 + i]);
						fprintf(vystup, "%d", pkt_data[30 + i]);
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
						fprintf(vystup, "Zdrojovy port: %d\n", pom1);
						pom2 = pkt_data[36] * 256 + pkt_data[37];
						printf("Cielovy port port: %d\n", pom2);
						fprintf(vystup, "Cielovy port port: %d\n", pom2);
						break;
					}
					for (i = 1; (i < header->caplen + 1); i++)
					{
						if (((i - 1) % 8) == 0 && (i - 1) % 16 == 8) { printf("  "); fprintf(vystup, "  "); }
						{printf("%.2x ", pkt_data[i - 1]); fprintf(vystup, "%.2x ", pkt_data[i - 1]); }
						if ((i % LINE_LEN) == 0) { printf("\n"); fprintf(vystup, "\n"); }
					}
					printf("\n");
					fprintf(vystup, "\n");
					printf("\n");
					fprintf(vystup, "\n");
				}




			}
			printf("\n");
			fprintf(vystup, "\n");
		}

//HTTPS

		if (bod == 5)
		{

			while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
			{
				framecounter++;


				typ = pkt_data[12] * 256 + pkt_data[13];
				//if (typ > 1500)
				pom1 = pkt_data[34] * 256 + pkt_data[35];
				pom2 = pkt_data[36] * 256 + pkt_data[37];
				https = 0;
				if (pom1 == 443) https = 1;
				if (pom2 == 443) https = 1;
				if (typ == 2048 && pkt_data[23] == 6 && https == 1)
				{
					printf("ramec %d\n", framecounter);
					fprintf(vystup, "ramec %d\n", framecounter);
					dlzkaAPI = header->len;
					printf("dlzka ramca poskytnuta pcap API - %d B\n", dlzkaAPI);
					fprintf(vystup, "dlzka ramca poskytnuta pcap API - %d B\n", dlzkaAPI);
					if (dlzkaAPI < 60)
					{
						dlzkaMedium = 64;
					}
					else
					{
						dlzkaMedium = dlzkaAPI + 4;
					}
					printf("dlzka ramca prenasaneho po mediu - %d B\n", dlzkaMedium);
					fprintf(vystup, "dlzka ramca prenasaneho po mediu - %d B\n", dlzkaMedium);
					printf("Ethernet II\n"); fprintf(vystup, "Ethernet II\n");
					printf("Zdrojova MAC adressa : ");
					fprintf(vystup, "Zdrojova MAC adressa : ");
					for (i = 6; i < 12; i++) { printf("%.2x ", pkt_data[i]); fprintf(vystup, "%.2x ", pkt_data[i]); }
					printf("\n");
					fprintf(vystup, "\n");
					printf("Cielova MAC adressa : ");
					fprintf(vystup, "Cielova MAC adressa : ");
					for (i = 0; i < 6; i++) { printf("%.2x ", pkt_data[i]); fprintf(vystup, "%.2x ", pkt_data[i]); }
					printf("\n");
					fprintf(vystup, "\n");
					printf("IPv4\n");
					fprintf(vystup, "IPv4\n");

					//zdrojova IP
					printf("zdrojova IP adresa: ");
					fprintf(vystup, "zdrojova IP adresa: ");
					for (i = 0; i < 4; i++)
					{
						printf("%d", pkt_data[26 + i]);
						fprintf(vystup, "%d", pkt_data[26 + i]);
						if (i < 3) { printf("."); fprintf(vystup, "."); }
					}
					printf("\n");
					fprintf(vystup, "\n");

					//cielova IP
					printf("cielova IP adresa: ");
					fprintf(vystup, "cielova IP adresa: ");
					for (i = 0; i < 4; i++)
					{
						printf("%d", pkt_data[30 + i]);
						fprintf(vystup, "%d", pkt_data[30 + i]);
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
						fprintf(vystup, "Zdrojovy port: %d\n", pom1);
						pom2 = pkt_data[36] * 256 + pkt_data[37];
						printf("Cielovy port port: %d\n", pom2);
						fprintf(vystup, "Cielovy port port: %d\n", pom2);
						break;
					}
					for (i = 1; (i < header->caplen + 1); i++)
					{
						if (((i - 1) % 8) == 0 && (i - 1) % 16 == 8) { printf("  "); fprintf(vystup, "  "); }
						{printf("%.2x ", pkt_data[i - 1]); fprintf(vystup, "%.2x ", pkt_data[i - 1]); }
						if ((i % LINE_LEN) == 0) { printf("\n"); fprintf(vystup, "\n"); }
					}
					printf("\n");
					fprintf(vystup, "\n");
					printf("\n");
					fprintf(vystup, "\n");
				}




			}
			printf("\n");
			fprintf(vystup, "\n");
		}



//SSH



		if (bod == 6)
		{

			while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
			{
				framecounter++;


				typ = pkt_data[12] * 256 + pkt_data[13];
				//if (typ > 1500)
				pom1 = pkt_data[34] * 256 + pkt_data[35];
				pom2 = pkt_data[36] * 256 + pkt_data[37];
				ssh = 0;
				if (pom1 == 22) ssh = 1;
				if (pom2 == 22) ssh = 1;
				if (typ == 2048 && pkt_data[23] == 6 && ssh == 1)
				{
					printf("ramec %d\n", framecounter);
					fprintf(vystup, "ramec %d\n", framecounter);
					dlzkaAPI = header->len;
					printf("dlzka ramca poskytnuta pcap API - %d B\n", dlzkaAPI);
					fprintf(vystup, "dlzka ramca poskytnuta pcap API - %d B\n", dlzkaAPI);
					if (dlzkaAPI < 60)
					{
						dlzkaMedium = 64;
					}
					else
					{
						dlzkaMedium = dlzkaAPI + 4;
					}
					printf("dlzka ramca prenasaneho po mediu - %d B\n", dlzkaMedium);
					fprintf(vystup, "dlzka ramca prenasaneho po mediu - %d B\n", dlzkaMedium);
					printf("Ethernet II\n"); fprintf(vystup, "Ethernet II\n");
					printf("Zdrojova MAC adressa : ");
					fprintf(vystup, "Zdrojova MAC adressa : ");
					for (i = 6; i < 12; i++) { printf("%.2x ", pkt_data[i]); fprintf(vystup, "%.2x ", pkt_data[i]); }
					printf("\n");
					fprintf(vystup, "\n");
					printf("Cielova MAC adressa : ");
					fprintf(vystup, "Cielova MAC adressa : ");
					for (i = 0; i < 6; i++) { printf("%.2x ", pkt_data[i]); fprintf(vystup, "%.2x ", pkt_data[i]); }
					printf("\n");
					fprintf(vystup, "\n");
					printf("IPv4\n");
					fprintf(vystup, "IPv4\n");

					//zdrojova IP
					printf("zdrojova IP adresa: ");
					fprintf(vystup, "zdrojova IP adresa: ");
					for (i = 0; i < 4; i++)
					{
						printf("%d", pkt_data[26 + i]);
						fprintf(vystup, "%d", pkt_data[26 + i]);
						if (i < 3) { printf("."); fprintf(vystup, "."); }
					}
					printf("\n");
					fprintf(vystup, "\n");

					//cielova IP
					printf("cielova IP adresa: ");
					fprintf(vystup, "cielova IP adresa: ");
					for (i = 0; i < 4; i++)
					{
						printf("%d", pkt_data[30 + i]);
						fprintf(vystup, "%d", pkt_data[30 + i]);
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
						fprintf(vystup, "Zdrojovy port: %d\n", pom1);
						pom2 = pkt_data[36] * 256 + pkt_data[37];
						printf("Cielovy port port: %d\n", pom2);
						fprintf(vystup, "Cielovy port port: %d\n", pom2);
						break;
					}
					for (i = 1; (i < header->caplen + 1); i++)
					{
						if (((i - 1) % 8) == 0 && (i - 1) % 16 == 8) { printf("  "); fprintf(vystup, "  "); }
						{printf("%.2x ", pkt_data[i - 1]); fprintf(vystup, "%.2x ", pkt_data[i - 1]); }
						if ((i % LINE_LEN) == 0) { printf("\n"); fprintf(vystup, "\n"); }
					}
					printf("\n");
					fprintf(vystup, "\n");
					printf("\n");
					fprintf(vystup, "\n");
				}




			}
			printf("\n");
			fprintf(vystup, "\n");
		}

//ftpd

		if (bod == 7)
		{

			while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
			{
				framecounter++;


				typ = pkt_data[12] * 256 + pkt_data[13];
				//if (typ > 1500)
				pom1 = pkt_data[34] * 256 + pkt_data[35];
				pom2 = pkt_data[36] * 256 + pkt_data[37];
				ftpd = 0;
				if (pom1 == 20) ftpd = 1;
				if (pom2 == 20) ftpd = 1;
				if (typ == 2048 && pkt_data[23] == 6 && ftpd == 1)
				{
					printf("ramec %d\n", framecounter);
					fprintf(vystup, "ramec %d\n", framecounter);
					dlzkaAPI = header->len;
					printf("dlzka ramca poskytnuta pcap API - %d B\n", dlzkaAPI);
					fprintf(vystup, "dlzka ramca poskytnuta pcap API - %d B\n", dlzkaAPI);
					if (dlzkaAPI < 60)
					{
						dlzkaMedium = 64;
					}
					else
					{
						dlzkaMedium = dlzkaAPI + 4;
					}
					printf("dlzka ramca prenasaneho po mediu - %d B\n", dlzkaMedium);
					fprintf(vystup, "dlzka ramca prenasaneho po mediu - %d B\n", dlzkaMedium);
					printf("Ethernet II\n"); fprintf(vystup, "Ethernet II\n");
					printf("Zdrojova MAC adressa : ");
					fprintf(vystup, "Zdrojova MAC adressa : ");
					for (i = 6; i < 12; i++) { printf("%.2x ", pkt_data[i]); fprintf(vystup, "%.2x ", pkt_data[i]); }
					printf("\n");
					fprintf(vystup, "\n");
					printf("Cielova MAC adressa : ");
					fprintf(vystup, "Cielova MAC adressa : ");
					for (i = 0; i < 6; i++) { printf("%.2x ", pkt_data[i]); fprintf(vystup, "%.2x ", pkt_data[i]); }
					printf("\n");
					fprintf(vystup, "\n");
					printf("IPv4\n");
					fprintf(vystup, "IPv4\n");

					//zdrojova IP
					printf("zdrojova IP adresa: ");
					fprintf(vystup, "zdrojova IP adresa: ");
					for (i = 0; i < 4; i++)
					{
						printf("%d", pkt_data[26 + i]);
						fprintf(vystup, "%d", pkt_data[26 + i]);
						if (i < 3) { printf("."); fprintf(vystup, "."); }
					}
					printf("\n");
					fprintf(vystup, "\n");

					//cielova IP
					printf("cielova IP adresa: ");
					fprintf(vystup, "cielova IP adresa: ");
					for (i = 0; i < 4; i++)
					{
						printf("%d", pkt_data[30 + i]);
						fprintf(vystup, "%d", pkt_data[30 + i]);
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
						fprintf(vystup, "Zdrojovy port: %d\n", pom1);
						pom2 = pkt_data[36] * 256 + pkt_data[37];
						printf("Cielovy port port: %d\n", pom2);
						fprintf(vystup, "Cielovy port port: %d\n", pom2);
						break;
					}
					for (i = 1; (i < header->caplen + 1); i++)
					{
						if (((i - 1) % 8) == 0 && (i - 1) % 16 == 8) { printf("  "); fprintf(vystup, "  "); }
						{printf("%.2x ", pkt_data[i - 1]); fprintf(vystup, "%.2x ", pkt_data[i - 1]); }
						if ((i % LINE_LEN) == 0) { printf("\n"); fprintf(vystup, "\n"); }
					}
					printf("\n");
					fprintf(vystup, "\n");
					printf("\n");
					fprintf(vystup, "\n");
				}




			}
			printf("\n");
			fprintf(vystup, "\n");
		}


//ftpc


		if (bod == 8)
		{

			while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
			{
				framecounter++;


				typ = pkt_data[12] * 256 + pkt_data[13];
				//if (typ > 1500)
				pom1 = pkt_data[34] * 256 + pkt_data[35];
				pom2 = pkt_data[36] * 256 + pkt_data[37];
				ftpc = 0;
				if (pom1 == 21) ftpc = 1;
				if (pom2 == 21) ftpc = 1;
				if (typ == 2048 && pkt_data[23] == 6 && ftpc == 1)
				{
					printf("ramec %d\n", framecounter);
					fprintf(vystup, "ramec %d\n", framecounter);
					dlzkaAPI = header->len;
					printf("dlzka ramca poskytnuta pcap API - %d B\n", dlzkaAPI);
					fprintf(vystup, "dlzka ramca poskytnuta pcap API - %d B\n", dlzkaAPI);
					if (dlzkaAPI < 60)
					{
						dlzkaMedium = 64;
					}
					else
					{
						dlzkaMedium = dlzkaAPI + 4;
					}
					printf("dlzka ramca prenasaneho po mediu - %d B\n", dlzkaMedium);
					fprintf(vystup, "dlzka ramca prenasaneho po mediu - %d B\n", dlzkaMedium);
					printf("Ethernet II\n"); fprintf(vystup, "Ethernet II\n");
					printf("Zdrojova MAC adressa : ");
					fprintf(vystup, "Zdrojova MAC adressa : ");
					for (i = 6; i < 12; i++) { printf("%.2x ", pkt_data[i]); fprintf(vystup, "%.2x ", pkt_data[i]); }
					printf("\n");
					fprintf(vystup, "\n");
					printf("Cielova MAC adressa : ");
					fprintf(vystup, "Cielova MAC adressa : ");
					for (i = 0; i < 6; i++) { printf("%.2x ", pkt_data[i]); fprintf(vystup, "%.2x ", pkt_data[i]); }
					printf("\n");
					fprintf(vystup, "\n");
					printf("IPv4\n");
					fprintf(vystup, "IPv4\n");

					//zdrojova IP
					printf("zdrojova IP adresa: ");
					fprintf(vystup, "zdrojova IP adresa: ");
					for (i = 0; i < 4; i++)
					{
						printf("%d", pkt_data[26 + i]);
						fprintf(vystup, "%d", pkt_data[26 + i]);
						if (i < 3) { printf("."); fprintf(vystup, "."); }
					}
					printf("\n");
					fprintf(vystup, "\n");

					//cielova IP
					printf("cielova IP adresa: ");
					fprintf(vystup, "cielova IP adresa: ");
					for (i = 0; i < 4; i++)
					{
						printf("%d", pkt_data[30 + i]);
						fprintf(vystup, "%d", pkt_data[30 + i]);
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
						fprintf(vystup, "Zdrojovy port: %d\n", pom1);
						pom2 = pkt_data[36] * 256 + pkt_data[37];
						printf("Cielovy port port: %d\n", pom2);
						fprintf(vystup, "Cielovy port port: %d\n", pom2);
						break;
					}
					for (i = 1; (i < header->caplen + 1); i++)
					{
						if (((i - 1) % 8) == 0 && (i - 1) % 16 == 8) { printf("  "); fprintf(vystup, "  "); }
						{printf("%.2x ", pkt_data[i - 1]); fprintf(vystup, "%.2x ", pkt_data[i - 1]); }
						if ((i % LINE_LEN) == 0) { printf("\n"); fprintf(vystup, "\n"); }
					}
					printf("\n");
					fprintf(vystup, "\n");
					printf("\n");
					fprintf(vystup, "\n");
				}




			}
			printf("\n");
			fprintf(vystup, "\n");
		}


//TFTP

		if (bod == 9)
		{

			while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
			{
				framecounter++;


				typ = pkt_data[12] * 256 + pkt_data[13];
				//if (typ > 1500)
				pom1 = pkt_data[34] * 256 + pkt_data[35];
				pom2 = pkt_data[36] * 256 + pkt_data[37];
				tftp = 0;
				if (pom1 == 69) tftp = 1;
				if (pom2 == 69) tftp = 1;
				if (typ == 2048 && pkt_data[23] == 17 && tftp == 1)
				{
					printf("ramec %d\n", framecounter);
					fprintf(vystup, "ramec %d\n", framecounter);
					dlzkaAPI = header->len;
					printf("dlzka ramca poskytnuta pcap API - %d B\n", dlzkaAPI);
					fprintf(vystup, "dlzka ramca poskytnuta pcap API - %d B\n", dlzkaAPI);
					if (dlzkaAPI < 60)
					{
						dlzkaMedium = 64;
					}
					else
					{
						dlzkaMedium = dlzkaAPI + 4;
					}
					printf("dlzka ramca prenasaneho po mediu - %d B\n", dlzkaMedium);
					fprintf(vystup, "dlzka ramca prenasaneho po mediu - %d B\n", dlzkaMedium);
					printf("Ethernet II\n"); fprintf(vystup, "Ethernet II\n");
					printf("Zdrojova MAC adressa : ");
					fprintf(vystup, "Zdrojova MAC adressa : ");
					for (i = 6; i < 12; i++) { printf("%.2x ", pkt_data[i]); fprintf(vystup, "%.2x ", pkt_data[i]); }
					printf("\n");
					fprintf(vystup, "\n");
					printf("Cielova MAC adressa : ");
					fprintf(vystup, "Cielova MAC adressa : ");
					for (i = 0; i < 6; i++) { printf("%.2x ", pkt_data[i]); fprintf(vystup, "%.2x ", pkt_data[i]); }
					printf("\n");
					fprintf(vystup, "\n");
					printf("IPv4\n");
					fprintf(vystup, "IPv4\n");

					//zdrojova IP
					printf("zdrojova IP adresa: ");
					fprintf(vystup, "zdrojova IP adresa: ");
					for (i = 0; i < 4; i++)
					{
						printf("%d", pkt_data[26 + i]);
						fprintf(vystup, "%d", pkt_data[26 + i]);
						if (i < 3) { printf("."); fprintf(vystup, "."); }
					}
					printf("\n");
					fprintf(vystup, "\n");

					//cielova IP
					printf("cielova IP adresa: ");
					fprintf(vystup, "cielova IP adresa: ");
					for (i = 0; i < 4; i++)
					{
						printf("%d", pkt_data[30 + i]);
						fprintf(vystup, "%d", pkt_data[30 + i]);
						if (i < 3) printf(".");
						if (i < 3) fprintf(vystup, ".");
					}
					printf("\n");
					fprintf(vystup, "\n");


					pozicia = pkt_data[34];
					switch (pkt_data[23])
					{
					case 17:
						printf("UDP\n");
						fprintf(vystup, "UDP\n");
						pom1 = pkt_data[34] * 256 + pkt_data[35];
						printf("Zdrojovy port: %d\n", pom1);
						fprintf(vystup, "Zdrojovy port: %d\n", pom1);
						pom2 = pkt_data[36] * 256 + pkt_data[37];
						printf("Cielovy port port: %d\n", pom2);
						fprintf(vystup, "Cielovy port port: %d\n", pom2);
						break;
					}
					for (i = 1; (i < header->caplen + 1); i++)
					{
						if (((i - 1) % 8) == 0 && (i - 1) % 16 == 8) { printf("  "); fprintf(vystup, "  "); }
						{printf("%.2x ", pkt_data[i - 1]); fprintf(vystup, "%.2x ", pkt_data[i - 1]); }
						if ((i % LINE_LEN) == 0) { printf("\n"); fprintf(vystup, "\n"); }
					}
					printf("\n");
					fprintf(vystup, "\n");
					printf("\n");
					fprintf(vystup, "\n");
				}




			}
			printf("\n");
			fprintf(vystup, "\n");
		}


//ICMP


		if (bod == 10)
		{

			while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
			{
				framecounter++;


				typ = pkt_data[12] * 256 + pkt_data[13];
				if (typ == 2048 && pkt_data[23] == 1)
				{
					printf("ramec %d\n", framecounter);
					fprintf(vystup, "ramec %d\n", framecounter);
					dlzkaAPI = header->len;
					printf("dlzka ramca poskytnuta pcap API - %d B\n", dlzkaAPI);
					fprintf(vystup, "dlzka ramca poskytnuta pcap API - %d B\n", dlzkaAPI);
					if (dlzkaAPI < 60)
					{
						dlzkaMedium = 64;
					}
					else
					{
						dlzkaMedium = dlzkaAPI + 4;
					}
					printf("dlzka ramca prenasaneho po mediu - %d B\n", dlzkaMedium);
					fprintf(vystup, "dlzka ramca prenasaneho po mediu - %d B\n", dlzkaMedium);
					printf("Ethernet II\n"); fprintf(vystup, "Ethernet II\n");
					printf("Zdrojova MAC adressa : ");
					fprintf(vystup, "Zdrojova MAC adressa : ");
					for (i = 6; i < 12; i++) { printf("%.2x ", pkt_data[i]); fprintf(vystup, "%.2x ", pkt_data[i]); }
					printf("\n");
					fprintf(vystup, "\n");
					printf("Cielova MAC adressa : ");
					fprintf(vystup, "Cielova MAC adressa : ");
					for (i = 0; i < 6; i++) { printf("%.2x ", pkt_data[i]); fprintf(vystup, "%.2x ", pkt_data[i]); }
					printf("\n");
					fprintf(vystup, "\n");
					printf("IPv4\n");
					fprintf(vystup, "IPv4\n");

					//zdrojova IP
					printf("zdrojova IP adresa: ");
					fprintf(vystup, "zdrojova IP adresa: ");
					for (i = 0; i < 4; i++)
					{
						printf("%d", pkt_data[26 + i]);
						fprintf(vystup, "%d", pkt_data[26 + i]);
						if (i < 3) { printf("."); fprintf(vystup, "."); }
					}
					printf("\n");
					fprintf(vystup, "\n");

					//cielova IP
					printf("cielova IP adresa: ");
					fprintf(vystup, "cielova IP adresa: ");
					for (i = 0; i < 4; i++)
					{
						printf("%d", pkt_data[30 + i]);
						fprintf(vystup, "%d", pkt_data[30 + i]);
						if (i < 3) printf(".");
						if (i < 3) fprintf(vystup, ".");
					}
					printf("\n");
					fprintf(vystup, "\n");


					switch (pkt_data[23])
					{
					case 1:
						printf("ICMP\n");
						fprintf(vystup, "ICMP\n");
						break;
					}
					for (i = 1; (i < header->caplen + 1); i++)
					{
						if (((i - 1) % 8) == 0 && (i - 1) % 16 == 8) { printf("  "); fprintf(vystup, "  "); }
						{printf("%.2x ", pkt_data[i - 1]); fprintf(vystup, "%.2x ", pkt_data[i - 1]); }
						if ((i % LINE_LEN) == 0) { printf("\n"); fprintf(vystup, "\n"); }
					}
					printf("\n");
					fprintf(vystup, "\n");
					printf("\n");
					fprintf(vystup, "\n");
				}




			}
			printf("\n");
			fprintf(vystup, "\n");
		}

		
	}