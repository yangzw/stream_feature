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
	u_short sport;
	u_short dport;
	string transprotocol;
	string kind;
};
map<string, ndpi_flag*> map_ndpi_tcp;
ifstream infile; //ndpi打标签的流文件

// Libnids的头文件，必须包含 
char ascii_string[10000];
char *char_to_ascii(char ch)
// 此函数的功能主要用于把协议数据进行显示 
{
    char *string;
    ascii_string[0] = 0;
    string = ascii_string;
    if (isgraph(ch))
     // 可打印字符 
    {
        *string++ = ch;
    }
    else if (ch == ' ')
     // 空格 
    {
        *string++ = ch;
    }
    else if (ch == '\n' || ch == '\r')
     // 回车和换行 
    {
        *string++ = ch;
    }
    else
     // 其它字符以点"."表示 
    {
        *string++ = '.';
    }
    *string = 0;
    return ascii_string;
}
/*
=======================================================================================================================
下面的函数是回调函数，用于分析TCP连接，分析TCP连接状态，对TCP协议传输的数据进行分析
=======================================================================================================================
 */
int win_size;
void tcp_protocol_callback(struct tcp_stream *tcp_connection, void **arg)
{
    int i;
    char address_string[1024];
    //char content[65535];
    //char content_urgent[65535];
    struct tuple4 ip_and_port = tcp_connection->addr;
    /*
    // 获取TCP连接的地址和端口对
    strcpy(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.saddr))));
    // 获取源地址 
    sprintf(address_string + strlen(address_string), " : %i", ip_and_port.source);
    // 获取源端口 
    strcat(address_string, " <---> ");
    strcat(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.daddr))));
    // 获取目的地址 
    sprintf(address_string + strlen(address_string), " : %i", ip_and_port.dest);
    // 获取目的端口 
    sprintf(address_string + strlen(address_string), " : %i", tcp_connection->s_v.serv_port);
    sprintf(address_string + strlen(address_string), " : %d", tcp_connection->s_v.push_pkts_serv);
    sprintf(address_string + strlen(address_string), " : %f", tcp_connection->s_v.now_time);
    sprintf(address_string + strlen(address_string), " : %d", tcp_connection->s_v.flags);
    strcat(address_string, "\n");
    */
    switch (tcp_connection->nids_state) // 判断LIBNIDS的状态 
    {
        case NIDS_JUST_EST:
            // 表示TCP客户端和TCP服务器端建立连接状态 
            tcp_connection->client.collect++;
            // 客户端接收数据 
            tcp_connection->server.collect++;
            // 服务器接收数据 
            tcp_connection->server.collect_urg++;
            // 服务器接收紧急数据 
            tcp_connection->client.collect_urg++;
            // 客户端接收紧急数据 
    	    //sprintf(address_string + strlen(address_string), " : %d", tcp_connection->s_v.len_third);
            //printf("%sTCP连接建立\n", address_string);
            return ;
        case NIDS_CLOSE:
            // 表示TCP连接正常关闭 
            //printf("--------------------------------\n");
            //printf("%sTCP连接正常关闭\n", address_string);
            return ;
        case NIDS_RESET:
            // 表示TCP连接被RST关闭 
            //printf("--------------------------------\n");
            //printf("%sTCP连接被RST关闭\n", address_string);
            return ;
        case NIDS_DATA:
            // 表示有新的数据到达 
            {
		    if((tcp_connection->s_v.flags & TH_PUSH))
			    tcp_connection->s_v.push_pkts_serv += 1;
		    if(tcp_connection->s_v.pkt_number > win_size)
			    return ;
		    else if(tcp_connection->s_v.pkt_number == win_size)
		    {
			    tcp_connection->s_v.pkt_number++;
		    }
		    else
			    tcp_connection->s_v.pkt_number++;
                struct half_stream *hlf;
                // 表示TCP连接的一端的信息，可以是客户端，也可以是服务器端 
                if (tcp_connection->server.count_new_urg)
                {
			/*
                    // 表示TCP服务器端接收到新的紧急数据 
                    printf("--------------------------------\n");
                    strcpy(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.saddr))));
                    sprintf(address_string + strlen(address_string), " : %i", ip_and_port.source);
                    strcat(address_string, " urgent---> ");
                    strcat(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.daddr))));
		    sprintf(address_string + strlen(address_string), " : %i", ip_and_port.dest);
		    sprintf(address_string + strlen(address_string), " : %i", tcp_connection->s_v.serv_port);
		    sprintf(address_string + strlen(address_string), " : %d", tcp_connection->s_v.push_pkts_serv);
    		    sprintf(address_string + strlen(address_string), " : %f", tcp_connection->s_v.now_time);
                    strcat(address_string, "\n");
                    address_string[strlen(address_string) + 1] = 0;
                    //address_string[strlen(address_string)] = tcp_connection->server.urgdata;
                    printf("%s", address_string);
		    */
                    return ;
                }
                if (tcp_connection->client.count_new_urg)
                {
		    //表示TCP客户端接收到新的紧急数据 
                    return ;
                }
                if (tcp_connection->client.count_new)
                {
                    /* 表示客户端接收到新的数据 */
                    hlf = &tcp_connection->client;
		    
                    // 此时hlf表示的是客户端的TCP连接信息 
                    strcpy(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.saddr))));
                    sprintf(address_string + strlen(address_string), ":%i", ip_and_port.source);
                    strcat(address_string, " <--- ");
                    strcat(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.daddr))));
		    sprintf(address_string + strlen(address_string), ":%i", ip_and_port.dest);
		    sprintf(address_string + strlen(address_string), " : %i", tcp_connection->s_v.serv_port);
		    sprintf(address_string + strlen(address_string), " : %d", tcp_connection->s_v.push_pkts_serv);
    		    sprintf(address_string + strlen(address_string), " : %f", tcp_connection->s_v.now_time);
                    strcat(address_string, "\n");
                    printf("--------------------------------\n");
                    printf("%s", address_string);
		   
		    cout << hlf->count_new  << " " << tcp_connection->s_v.now_time << " " << hlf->count << endl;
                }
                else
                {
                    /* 表示服务器端接收到新的数据 */
                    hlf = &tcp_connection->server;
                    // 此时hlf表示服务器端的TCP连接信息 
                    //memcpy(content, hlf->data, hlf->count_new);
                    //content[hlf->count_new] = '\0';
		    
                    printf("服务器端接收数据\n");
                    strcpy(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.saddr))));
                    sprintf(address_string + strlen(address_string), ":%i", ip_and_port.source);
                    strcat(address_string, " <--- ");
                    strcat(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.daddr))));
		    sprintf(address_string + strlen(address_string), ":%i", ip_and_port.dest);
		    sprintf(address_string + strlen(address_string), " : %i", tcp_connection->s_v.serv_port);
		    sprintf(address_string + strlen(address_string), " : %d", tcp_connection->s_v.push_pkts_serv);
    		    sprintf(address_string + strlen(address_string), " : %f", tcp_connection->s_v.now_time);
                    strcat(address_string, "\n");
                    printf("--------------------------------\n");
                    printf("%s", address_string);
		   
		    cout << hlf->count_new  << " " << hlf->count << "fuck" << endl;
		    
		    if(!tcp_connection->s_v.dt_bg)
		    {
			    tcp_connection->s_v.fir_plength_clnt = hlf->count_new;
			    tcp_connection->s_v.fir_sec_diff_clnt = hlf->count_new - tcp_connection->s_v.len_third;
			    tcp_connection->s_v.dt_bg = 1;
			    //cout << "first" << tcp_connection->s_v.fir_plength_clnt << tcp_connection->s_v.fir_sec_diff_clnt << endl;
		    }
		}
            }
        default:
            break;
    }
    return ;
}

void udp_callback(struct tuple4 *addr, char *buf, int len, struct ip *iph)
{
	char address_string[1024];
	// 获取UDP的地址和端口对 
	strcpy(address_string, inet_ntoa(*((struct in_addr*) &(addr->saddr))));
	// 获取源地址 
	sprintf(address_string + strlen(address_string), " : %i", addr->source);
	// 获取源端口 
	strcat(address_string, " ---> ");
	strcat(address_string, inet_ntoa(*((struct in_addr*) &(addr->daddr))));
	// 获取目的地址 
	sprintf(address_string + strlen(address_string), " : %i", addr->dest);
	// 获取目的端口 
	strcat(address_string, "\n");
	printf("UDP: %s--------\n",address_string);
}

void get_stream_init()
{
	string ndpi_file = "ndpi.data";
	//cout << "输入ndpi文件" << endl;
	//cin >> ndpi_file;
	infile.open(ndpi_file.c_str(),ifstream::in);

	//CMd5 cmd5,cmd5r;
	string md5_forward, md5_reverse;
	while(!infile.eof())
	{
		ndpi_flag * ndpiflag = new ndpi_flag();
		infile >> ndpiflag->kind >> ndpiflag->src >> ndpiflag->sport >> ndpiflag->dst >> ndpiflag->dport >> ndpiflag->transprotocol;
		if (ndpiflag->transprotocol == "TCP")
		{
			md5_forward += ndpiflag->src;
			md5_forward += ndpiflag->sport;
			md5_forward += ndpiflag->dst;
			md5_forward += ndpiflag->dport;
			md5_forward += ndpiflag->transprotocol;
			//cout << ndpiflag->kind << "	" << ndpiflag->src << ":" << ndpiflag->sport << "->" << ndpiflag->dst << ":" << ndpiflag->dport << " " << ndpiflag->transprotocol << endl;
			map<string, ndpi_flag* >::iterator iter_ndpi =map_ndpi_tcp.find(md5_forward);
			if(iter_ndpi==map_ndpi_tcp.end())
			{
				if(ndpiflag->kind!="smb" && ndpiflag->kind!="unknown")
					map_ndpi_tcp.insert(pair<string, ndpi_flag* >(md5_forward, ndpiflag));
			}
			else
				cout << "not new" << endl;
			//cout<<"OK"<<endl;

			md5_reverse += ndpiflag->dst;
			md5_reverse += ndpiflag->dport;
			md5_reverse += ndpiflag->src;
			md5_reverse += ndpiflag->sport;
			md5_reverse += ndpiflag->transprotocol;
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

int main()
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
	nids_params.filename = "try.cap";
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
	// 注册回调函数 
	nids_run();
	// Libnids进入循环捕获数据包状态 
	return 0;
}
