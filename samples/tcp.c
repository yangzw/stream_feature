#include "nids.h"
/* Libnids��ͷ�ļ���������� */
char ascii_string[10000];
char *char_to_ascii(char ch)
/* �˺����Ĺ�����Ҫ���ڰ�Э�����ݽ�����ʾ */
{
    char *string;
    ascii_string[0] = 0;
    string = ascii_string;
    if (isgraph(ch))
     /* �ɴ�ӡ�ַ� */
    {
        *string++ = ch;
    }
    else if (ch == ' ')
     /* �ո� */
    {
        *string++ = ch;
    }
    else if (ch == '\n' || ch == '\r')
     /* �س��ͻ��� */
    {
        *string++ = ch;
    }
    else
     /* �����ַ��Ե�"."��ʾ */
    {
        *string++ = '.';
    }
    *string = 0;
    return ascii_string;
}
/*
=======================================================================================================================
����ĺ����ǻص����������ڷ���TCP���ӣ�����TCP����״̬����TCPЭ�鴫������ݽ��з���
=======================================================================================================================
 */
void tcp_protocol_callback(struct tcp_stream *tcp_connection, void **arg)
{
    int i;
    char address_string[1024];
    char content[65535];
    char content_urgent[65535];
    struct tuple4 ip_and_port = tcp_connection->addr;
    /* ��ȡTCP���ӵĵ�ַ�Ͷ˿ڶ� */
    strcpy(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.saddr))));
    /* ��ȡԴ��ַ */
    sprintf(address_string + strlen(address_string), " : %i", ip_and_port.source);
    /* ��ȡԴ�˿� */
    strcat(address_string, " <---> ");
    strcat(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.daddr))));
    /* ��ȡĿ�ĵ�ַ */
    sprintf(address_string + strlen(address_string), " : %i", ip_and_port.dest);
    /* ��ȡĿ�Ķ˿� */
    sprintf(address_string + strlen(address_string), " : %i", tcp_connection->s_v.serv_port);
    sprintf(address_string + strlen(address_string), " : %d", tcp_connection->s_v.push_pkts_serv);
    sprintf(address_string + strlen(address_string), " : %f", tcp_connection->s_v.now_time);
    strcat(address_string, "\n");
    switch (tcp_connection->nids_state) /* �ж�LIBNIDS��״̬ */
    {
        case NIDS_JUST_EST:
            /* ��ʾTCP�ͻ��˺�TCP�������˽�������״̬ */
            tcp_connection->client.collect++;
            /* �ͻ��˽������� */
            tcp_connection->server.collect++;
            /* �������������� */
            tcp_connection->server.collect_urg++;
            /* ���������ս������� */
            tcp_connection->client.collect_urg++;
            /* �ͻ��˽��ս������� */
            printf("%sTCP���ӽ���\n", address_string);
            return ;
        case NIDS_CLOSE:
            /* ��ʾTCP���������ر� */
            printf("--------------------------------\n");
            printf("%sTCP���������ر�\n", address_string);
            return ;
        case NIDS_RESET:
            /* ��ʾTCP���ӱ�RST�ر� */
            printf("--------------------------------\n");
            printf("%sTCP���ӱ�RST�ر�\n", address_string);
            return ;
        case NIDS_DATA:
            /* ��ʾ���µ����ݵ��� */
            {
                struct half_stream *hlf;
                /* ��ʾTCP���ӵ�һ�˵���Ϣ�������ǿͻ��ˣ�Ҳ�����Ƿ������� */
                if (tcp_connection->server.count_new_urg)
                {
                    /* ��ʾTCP�������˽��յ��µĽ������� */
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
                    address_string[strlen(address_string)] = tcp_connection->server.urgdata;
                    printf("%s", address_string);
                    return ;
                }
                if (tcp_connection->client.count_new_urg)
                {
                    /* ��ʾTCP�ͻ��˽��յ��µĽ������� */
                    printf("--------------------------------\n");
                    strcpy(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.saddr))));
                    sprintf(address_string + strlen(address_string), " : %i", ip_and_port.source);
                    strcat(address_string, " <--- urgent ");
                    strcat(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.daddr))));
		    sprintf(address_string + strlen(address_string), " : %i", ip_and_port.dest);
		    sprintf(address_string + strlen(address_string), " : %i", tcp_connection->s_v.serv_port);
		    sprintf(address_string + strlen(address_string), " : %d", tcp_connection->s_v.push_pkts_serv);
    		    sprintf(address_string + strlen(address_string), " : %f", tcp_connection->s_v.now_time);
                    strcat(address_string, "\n");
                    address_string[strlen(address_string) + 1] = 0;
                    address_string[strlen(address_string)] = tcp_connection->client.urgdata;
                    printf("%s", address_string);
                    return ;
                }
                if (tcp_connection->client.count_new)
                {
                    /* ��ʾ�ͻ��˽��յ��µ����� */
                    hlf = &tcp_connection->client;
                    /* ��ʱhlf��ʾ���ǿͻ��˵�TCP������Ϣ */
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
                    //memcpy(content, hlf->data, hlf->count_new);
                    //content[hlf->count_new] = '\0';
		    /*
                    printf("�ͻ��˽�������\n");
                    for (i = 0; i < hlf->count_new; i++)
                    {
                        printf("%s", char_to_ascii(content[i]));
                        // ����ͻ��˽��յ��µ����ݣ��Կɴ�ӡ�ַ�������ʾ 
                    }
                    printf("\n");
		    */
                }
                else
                {
                    /* ��ʾ�������˽��յ��µ����� */
                    hlf = &tcp_connection->server;
                    /* ��ʱhlf��ʾ�������˵�TCP������Ϣ */
                    strcpy(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.saddr))));
                    sprintf(address_string + strlen(address_string), ":%i", ip_and_port.source);
                    strcat(address_string, " ---> ");
                    strcat(address_string, inet_ntoa(*((struct in_addr*) &(ip_and_port.daddr))));
		    sprintf(address_string + strlen(address_string), ":%i", ip_and_port.dest);
		    sprintf(address_string + strlen(address_string), " : %i", tcp_connection->s_v.serv_port);
		    sprintf(address_string + strlen(address_string), " : %d", tcp_connection->s_v.push_pkts_serv);
    		    sprintf(address_string + strlen(address_string), " : %f", tcp_connection->s_v.now_time);
                    strcat(address_string, "\n");
                    printf("--------------------------------\n");
                    printf("%s", address_string);
                    //memcpy(content, hlf->data, hlf->count_new);
                    //content[hlf->count_new] = '\0';
		    /*
                    printf("�������˽�������\n");
                    for (i = 0; i < hlf->count_new; i++)
                    {
                        printf("%s", char_to_ascii(content[i]));
                        // ������������յ����µ����� 
                    }
                    printf("\n");
		    */
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
	/* ��ȡUDP�ĵ�ַ�Ͷ˿ڶ� */
	strcpy(address_string, inet_ntoa(*((struct in_addr*) &(addr->saddr))));
	/* ��ȡԴ��ַ */
	sprintf(address_string + strlen(address_string), " : %i", addr->source);
	/* ��ȡԴ�˿� */
	strcat(address_string, " <---> ");
	strcat(address_string, inet_ntoa(*((struct in_addr*) &(addr->daddr))));
	/* ��ȡĿ�ĵ�ַ */
	sprintf(address_string + strlen(address_string), " : %i", addr->dest);
	/* ��ȡĿ�Ķ˿� */
	strcat(address_string, "\n");
	printf("UDP: %s--------\n",address_string);
}

void main()
{
	struct nids_chksum_ctl temp;
	temp.netaddr = 0;
	temp.mask = 0;
	temp.action = 1;
	nids_register_chksum_ctl(&temp,1);
	//nids_params.device = "wlan0";
	nids_params.filename = "try.cap";
	if (!nids_init())
		/* Libnids��ʼ�� */
	{
		printf("���ִ���%s\n", nids_errbuf);
		exit(1);
	}
	nids_register_tcp(tcp_protocol_callback);
	nids_register_udp(udp_callback);
	/* ע��ص����� */
	nids_run();
	/* Libnids����ѭ���������ݰ�״̬ */
}
