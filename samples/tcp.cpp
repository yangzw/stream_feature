extern "C"{
#include "nids.h"
};
#include<string.h>
#include<ctype.h>
#include<arpa/inet.h>
#include<stdlib.h>
#include<map>
#include<string>
#include<iostream>
#include<fstream>

#define TH_PUSH 0x08
using namespace std;

extern "C"{
void nids_register_tcp(void (*x)(struct tcp_stream *, void**));
void nids_register_udp(void (*x)(struct tuple4 *, char *, int, struct ip *));
int nids_init();
int nids_run();
}

struct ndpi_flag{
	string src;
	string dst;
	string sport;
	string dport;
	string transprotocol;
	string kind;
};
map<string, ndpi_flag*> map_ndpi_tcp;
ifstream infile; //ndpi打标签的流文件
ofstream outfile;

int win_size;
void tcp_protocol_callback(struct tcp_stream *tcp_connection, void **arg)
{
	int i;
	char address_string[512];
	struct tuple4 ip_and_port = tcp_connection->addr;
	switch (tcp_connection->nids_state) // 判断LIBNIDS的状态 
	{
		case NIDS_JUST_EST:
			tcp_connection->client.collect++;
			tcp_connection->server.collect++;
			tcp_connection->server.collect_urg++;
			tcp_connection->client.collect_urg++;
			return ;
		case NIDS_CLOSE:
			// 表示TCP连接正常关闭 
			return ;
		case NIDS_RESET:
			// 表示TCP连接被RST关闭 
			return ;
		case NIDS_DATA:
			// 表示有新的数据到达 
			{
				if(tcp_connection->s_v.pkt_number > win_size)
					return ;
				else if(tcp_connection->s_v.pkt_number == win_size)
				{
					strcpy(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.saddr))));
					sprintf(address_string + strlen(address_string), " %i ", ip_and_port.source);
					strcat(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.daddr))));
					sprintf(address_string + strlen(address_string), " %i", ip_and_port.dest);
					strcat(address_string, " TCP");
					string str = string(address_string);
					cout << str << endl;
					map<string, ndpi_flag* >::iterator iter_ndpi =map_ndpi_tcp.find(str);
					if(iter_ndpi != map_ndpi_tcp.end())
					{
						outfile << str << " " << tcp_connection->s_v.push_pkts_serv << " " << (double)(tcp_connection->s_v.arg_seg_size_serv/win_size) << " " << tcp_connection->s_v.act_data_pkt_clnt << " " << tcp_connection->s_v.serv_port << " " << tcp_connection->s_v.fir_plength_clnt << " " << tcp_connection->s_v.fir_sec_diff_clnt << " " << iter_ndpi->second->kind << endl;
					}
					tcp_connection->s_v.pkt_number++;
					return;
				}
				else
					tcp_connection->s_v.pkt_number++;
				struct half_stream *hlf;
				// 表示TCP连接的一端的信息，可以是客户端，也可以是服务器端 
				if (tcp_connection->server.count_new_urg || tcp_connection->server.count_new)
				{
					//cout << "urg to server" << endl;
					// 表示TCP服务器端接收到新的紧急数据  或者数据
					if(!tcp_connection->s_v.dt_bg)
					{
						tcp_connection->s_v.fir_plength_clnt = tcp_connection->s_v.datalen;
						tcp_connection->s_v.fir_sec_diff_clnt = tcp_connection->s_v.datalen - tcp_connection->s_v.len_third;
						tcp_connection->s_v.dt_bg = 1;
					}
					if(tcp_connection->s_v.datalen >= 1)
					{
						tcp_connection->s_v.act_data_pkt_clnt ++;
					}
					tcp_connection->s_v.arg_seg_size_clnt += tcp_connection->s_v.datalen;
					return ;
				}
				if (tcp_connection->client.count_new_urg || tcp_connection->client.count_new)
				{
					//cout << "urg to client" << endl;
					//表示TCP客户端接收到新的紧急数据 或新数据
					if((tcp_connection->s_v.flags & TH_PUSH))
						tcp_connection->s_v.push_pkts_serv += 1;
					tcp_connection->s_v.arg_seg_size_serv += tcp_connection->s_v.datalen;
					return ;
				}
			}
		default:
			break;
	}
	return ;
}

void udp_callback(struct tuple4 *addr, char *buf, int len, struct ip *iph)
{
	/*
	   char address_string[1024];
	// 获取UDP的地址和端口对 获取源地址 获取源端口 获取目的地址 获取目的端口 
	strcpy(address_string, inet_ntoa(*((struct in_addr*) &(addr->saddr))));
	sprintf(address_string + strlen(address_string), " : %i", addr->source);
	strcat(address_string, " ---> ");
	strcat(address_string, inet_ntoa(*((struct in_addr*) &(addr->daddr))));
	sprintf(address_string + strlen(address_string), " : %i", addr->dest);
	strcat(address_string, "\n");
	printf("UDP: %s--------\n",address_string);
	*/
	return;
}

void get_stream_init()
{
	string ndpi_file = "ndpi.data";
	//cout << "输入ndpi文件" << endl;
	//cin >> ndpi_file;
	infile.open(ndpi_file.c_str(),ifstream::in);

	string md5_forward, md5_reverse;
	while(!infile.eof())
	{
		ndpi_flag * ndpiflag = new ndpi_flag();
		infile >> ndpiflag->kind >> ndpiflag->src >> ndpiflag->sport >> ndpiflag->dst >> ndpiflag->dport >> ndpiflag->transprotocol;
		if (ndpiflag->transprotocol == "TCP")
		{
			md5_forward += ndpiflag->src;
			md5_forward += " " + ndpiflag->sport;
			md5_forward += " " + ndpiflag->dst;
			md5_forward += " " + ndpiflag->dport;
			md5_forward += " " + ndpiflag->transprotocol;
			map<string, ndpi_flag* >::iterator iter_ndpi =map_ndpi_tcp.find(md5_forward);
			//cout << ndpiflag->src << ndpiflag->sport << ndpiflag->dst << ndpiflag->dport << ndpiflag->transprotocol << endl;
			if(iter_ndpi==map_ndpi_tcp.end())
			{
				if(ndpiflag->kind!="smb" && ndpiflag->kind!="unknown")
					map_ndpi_tcp.insert(pair<string, ndpi_flag* >(md5_forward, ndpiflag));
			}
			else
				cout << "not new" << endl;

			md5_reverse += ndpiflag->dst;
			md5_reverse += " " + ndpiflag->dport;
			md5_reverse += " " + ndpiflag->src;
			md5_reverse += " " + ndpiflag->sport;
			md5_reverse += " " + ndpiflag->transprotocol;
			iter_ndpi =map_ndpi_tcp.find(md5_reverse);
			if(iter_ndpi==map_ndpi_tcp.end())
			{
				if(ndpiflag->kind!="smb" && ndpiflag->kind!="unknown")
					map_ndpi_tcp.insert(pair<string, ndpi_flag* >(md5_reverse, ndpiflag));
			}
			else
				cout << "not new_reverse" << endl;
		}
		//if(ndpiflag->protocol=="udp")

		//	map_ndpi_udp.insert(pair<string,ndpi_flag* >(cmd5.GetDigestKey(),ndpiflag));
		while (isspace(infile.peek()))
			infile.get();
		md5_forward.erase();
		md5_reverse.erase();
	}
}

int main(int argc, char ** argv)
{
	struct nids_chksum_ctl temp;
	temp.netaddr = 0;
	temp.mask = 0;
	temp.action = 1;
	nids_register_chksum_ctl(&temp,1);
	//char filename[100];
	//filename = "/home/yang/a.cap";
	//cout << "输入流量包" << endl;
	//cin >> filename;
	//nids_params.filename = "/home/yang/a.cap";
	nids_params.filename = argv[1];
	//cout << "输入观察窗口大小" << endl;
	//cin >> win_size;
	win_size = 6;
	get_stream_init();
	if (!nids_init())
		// Libnids初始化 
	{
		printf("出现错误：%s\n", nids_errbuf);
		exit(1);
	}
	nids_register_tcp(tcp_protocol_callback);
	nids_register_udp(udp_callback);
	outfile.open("out.data",ifstream::out);
	// 注册回调函数 
	nids_run();
	// Libnids进入循环捕获数据包状态 
	return 0;
}
