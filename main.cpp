#include <winsock2.h>
//#include <Ws2tcpip.h>		// inet_ntop()
#include <stdio.h>		// printf()
#include <stdlib.h>
#include <vector>		// offset[]
#include <regex>		// URL_pattern
#include <fstream>		// file in/out
#include <string>		// string
#include "windivert.h"
#include "net_hdr.h"		// tcp/ip header

using namespace std;

#define MAXBUF			0xFFFF
#define MAX_NUMBER		1000004
#define MAXPAYLOAD		1500-sizeof(struct ipv4_hdr)-sizeof(struct tcp_hdr)
#define half(x, y)		((x)+(y))/2

#pragma pack(push, 1)
struct return_packet {
	struct ipv4_hdr ip;
	struct tcp_hdr tcp;
	char payload[MAXPAYLOAD];
}pkt;
#pragma pack(pop)

vector<uint32_t> offset;
regex pattern("Host: ([^\r]+)");  	// windows pattern
//regex pattern("Host: ([^\n]+)");	// linux pattern

bool offset_txt() {
	ifstream in("Black_url_offset.txt");
	string temp;

	puts("Offset_loading");
	if (in.is_open()) {
		for (uint32_t i=0; i<MAX_NUMBER; i++) {
			getline(in, temp);
			offset.push_back(stoi(temp));
		}
	}
	else { fprintf(stderr, "error: File not found\n"); return 1; }
	in.close();
	puts("Load complete.\n");

	return 0;
}

bool binarysearch(ifstream* in, string URL) {
	uint32_t max_p = MAX_NUMBER;
	uint32_t min_p = 0;
	uint32_t now_p = half(max_p, min_p);
	while (1) {
		string black_url;
		(*in).seekg(offset[now_p]);
		getline(*in, black_url);
		int res = URL.compare(black_url);
		if(res == 0) {				// Matched.
			return true;
		}
		else if(max_p - min_p == 1) {		// Unmatched.
			return false;
		}
		else if(res < 0) { 			// Front.
			max_p = now_p;
			now_p = half(max_p, min_p);
		}
		else if(res > 0) { 			// Back.
			min_p = now_p;
			now_p = half(max_p, min_p);
		}
		else { fprintf(stderr, "error: occurred during search\n"); exit(1); }
	}
}

void filter(HANDLE handle) {
	ifstream in;
	in.open("Black_url.txt");
	if (!in.is_open()) { fprintf(stderr, "error: File not found\n"); return; }

	static string html  =	"HTTP/1.0 302 Redirect\r\n"
				"Location: http://warning.or.kr/i1.html\r\n\r\n";
	uint32_t pkt_len = sizeof(struct return_packet);
	memcpy(pkt.payload, html.c_str(), html.size());

	while (TRUE) {
		uint8_t packet[MAXBUF];
		uint32_t packet_len;
		WINDIVERT_ADDRESS addr;
		if(!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len)) {
			fprintf(stderr, "warning: failed to read packet\n");
			continue;
		}

		struct ipv4_hdr *ip_p = (struct ipv4_hdr*)packet;
		if(ip_p->protocol != IPPROTO_TCP) continue;

		uint32_t ip_len = (ip_p->HL) << 2;
		struct tcp_hdr *tcp_p = (struct tcp_hdr*)(packet + ip_len);
		if(ntohs(tcp_p->d_port) != IPPORT_HTTP) continue;

		uint32_t tcp_len = tcp_p->off << 2;
		uint32_t http_len = ntohs(ip_p->len) - ip_len - tcp_len;
		uint8_t *http_p = (uint8_t*)tcp_p + tcp_len;
		if(http_len) {
			string payload(http_p, http_p + http_len);
			if(strncmp(payload.c_str(), "GET", 3)) continue;

			smatch m;
			if(regex_search(payload, m, pattern)) {
				string URL = m[1].str();
				if(binarysearch(&in, URL) == true) {
//					ip_p->tos = 1;
					ip_p->len = htons(ntohs(ip_p->len)-http_len);
					tcp_p->flag = RST+ACK;
					WinDivertHelperCalcChecksums(packet,ntohs(ip_p->len),&addr,0);
					if(!WinDivertSend(handle, packet, ntohs(ip_p->len), &addr, NULL)) {
						fprintf(stderr, "warning: failed to send\n");
						continue;
					}

//					pkt_ip->tos = 2;
					pkt.ip.len = htons(pkt_len);
					pkt.ip.src = ip_p->dst;
					pkt.ip.dst = ip_p->src;
					pkt.tcp.s_port = tcp_p->d_port;
					pkt.tcp.d_port = tcp_p->s_port;
					pkt.tcp.seq = tcp_p->ack;
					pkt.tcp.ack = htonl(ntohl(tcp_p->seq) + http_len);
					pkt.tcp.flag = FIN+ACK;
					WinDivertHelperCalcChecksums(&pkt, pkt_len, &addr, 0);
					if(!WinDivertSend(handle, &pkt, pkt_len, &addr, NULL)) {
						fprintf(stderr, "warning: failed to send\n");
						continue;
					}
					printf("Blocked URL : %s\n", URL.c_str());
				}
			}
		}
	}
	in.close();
}

int main() {
	if (offset_txt()) { fprintf(stderr, "error: program exit\n"); return 1; }

	uint16_t priority = 0;
	HANDLE handle = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, priority, WINDIVERT_FLAG_SNIFF);
	if (handle == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "error: failed to open the WinDivert device\n");
		return 1;
	}
	puts("[ Filtering Start! ]");
	filter(handle);
	return 0;
}
