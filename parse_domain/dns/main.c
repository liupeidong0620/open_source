#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>


//#define DNS_SVR "202.96.199.133"
#define DNS_SVR "114.114.114.114" // dns 服务器地址

#define DNS_HOST 0x01
#define DNS_CNAME 0X05

int socketfd;
struct sockaddr_in dest;

static void send_dns_request (const char *dns_name);

static void parse_dns_response ();

static void generate_question (const char *dns_name, unsigned char *buf, int *len);

static int is_pointer (int in);

/**
 *parse data chunk into dns name
 *@param chunk The complete response chunk
 *@param ptr the pointer points to data
 *@param out This will be filled with dns name
 *@param len This will be filled witeh the length of dns name
 */

static void parse_dns_name (unsigned char *chunk, unsigned char *ptr, char *out, int *len);

int main (int argc, char **argv)
{
    if (argc != 2) {
        printf("Usage : %s <domain name>\n", argv[0]);
        exit(-1);
    }
    socketfd = socket(AF_INET, SOCK_DGRAM,0);
    if(socketfd < 0) {
        perror("create socket failed");
        exit(-1);
    }

    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = inet_addr(DNS_SVR);

    printf("%s\n",argv[1]);

    send_dns_request(argv[1]);

    parse_dns_response();

    return 0;
}

static void parse_dns_response()
{
    unsigned char buf[1024];
    unsigned char *ptr = buf;
    struct sockaddr_in addr;
    char *src_ip;
    int n , i ,flag,querys,answers;
    int type,ttl,datalen,len;
    char cname[128],aname[128],ip[20],*cname_ptr;
    unsigned char netip[4];
    socklen_t addr_len = sizeof(struct sockaddr_in);

    n = recvfrom(socketfd, buf, sizeof(buf),0,(struct sockaddr*)&addr,&addr_len);
    ptr += 4;
    querys = ntohs(*((unsigned short *)ptr)); // 问题数
    ptr += 2;
    answers = ntohs(*((unsigned short *)ptr)); // 回答信息数  就是一个域名对于几个ip
    ptr += 6;

    for (i = 0; i < querys;i++) { // 查询包中的回答数
        for(;;) {
            flag = (int)ptr[0];
            ptr += (flag+1);
            if (flag == 0) {
                break;
            }
        }
        ptr += 4;
    }

    printf("-----------------------------\n"); // 回答字段解析
    for(i = 0; i < answers ; i++) {
        bzero(aname, sizeof(aname));
        len = 0;
        parse_dns_name(buf, ptr, aname, &len);
        ptr += 2;
        type = htons(*((unsigned short *)ptr));
        ptr += 4;
        ttl = htonl(*((unsigned short *)ptr));
        ptr += 4;
        datalen = ntohs(*((unsigned short *)ptr));
        ptr += 2;
        if(type == DNS_CNAME) {
            bzero(cname, sizeof(cname));
            len = 0;
            parse_dns_name(buf,ptr,cname,&len);
            printf("%s is an alias for %s \n",aname,cname);
            ptr += datalen;
        }

        if(type == DNS_HOST) {
            bzero(ip, sizeof(ip));
            if (datalen == 4) {
                memcpy(netip,ptr,datalen);
                inet_ntop(AF_INET,netip,ip,sizeof(struct sockaddr));
                printf("%s has address %s\n",aname,ip);
                printf("\tTime to live: %d minutes , %d seconds\n",ttl /60,ttl % 60);
            }
            ptr += datalen;
        }
    }
    ptr += 2;
}

static void parse_dns_name (unsigned char *chunk, unsigned char *ptr,char *out, int *len)
{
    int n,alen,flag;
    char *pos = out + (*len);

    while(1) {
        flag = (int)ptr[0];
        if (flag == 0) {
            break;
        }
        if (is_pointer(flag)) {
            n = (int)ptr[1];
            ptr = chunk + n;
            parse_dns_name(chunk, ptr, out, len);
            break;
        }
        else {
            ptr ++;
            memcpy(pos, ptr, flag);
            pos += flag;
            ptr += flag;
            *len += flag;
            if ((int)ptr[0] != 0) {
                memcpy(pos, ".",1);
                pos += 1;
                (*len) += 1;
            }
        }
    }
}

static int is_pointer (int in)
{
    return ((in & 0xc0) == 0xc0); //  由于代表指针偏移地址   就是找到 ip地址的数据域，详情看文档记载
}

static void send_dns_request (const char *dns_name) {
    unsigned char request[256];
    unsigned char *ptr = request;
    unsigned char question[128];
    int question_len;

    generate_question(dns_name , question, &question_len);

    *((unsigned short *)ptr) = htons(0xff00); // 标识数
    ptr += 2;
    *((unsigned short *)ptr) = htons(0x0100); // 标志
    ptr += 2;
    *((unsigned short *)ptr) = htons(1); // 问题数 表示1个
    ptr += 2;
    *((unsigned short *)ptr) = 0; // 回答RR数
    ptr += 2;
    *((unsigned short *)ptr) = 0; // 权威RR数
    ptr += 2;
    *((unsigned short *)ptr) = 0; // 附加RR数
    ptr += 2;
    memcpy(ptr, question, question_len);
    ptr += question_len;

    sendto(socketfd, request, question_len + 12, 0, (struct sockaddr *)&dest, sizeof(struct sockaddr));
}

static void generate_question(const char *dns_name, unsigned char *buf, int *len)
{
    char *pos;
    unsigned char *ptr;
    int n;

    *len = 0;
    ptr = buf;
    pos = (char *)dns_name;
    while(1) {
        n = strlen(pos) - (strstr(pos, ".")  ? strlen(strstr(pos, ".")) : 0 );
        *ptr ++= (unsigned char ) n;
        memcpy(ptr, pos, n);
        *len += n + 1;
        ptr += n;
        if(!strstr(pos, ".")) {
            *ptr = (unsigned char ) 0;
            ptr ++;
            *len += 1;
            break;
        }
        pos += n + 1;
    }
    *((unsigned short *)ptr) = htons(1); // 查询类型 ipv4
    *len += 2;
    ptr += 2;
    *((unsigned short *)ptr) = htons(1); // 指示互联网地址
    *len += 2;
}

