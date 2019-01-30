#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/wait.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include "tcp.h"

#define BUFFER_SIZE 1024
#define RESPONSE_HEADER_LEN_MAX 1024
#define GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
/*-------------------------------------------------------------------
0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-------+-+-------------+-------------------------------+
|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
|N|V|V|V|       |S|             |   (if payload len==126/127)   |
| |1|2|3|       |K|             |                               |
+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
|     Extended payload length continued, if payload len == 127  |
+ - - - - - - - - - - - - - - - +-------------------------------+
|                               |Masking-key, if MASK set to 1  |
+-------------------------------+-------------------------------+
| Masking-key (continued)       |          Payload Data         |
+-------------------------------- - - - - - - - - - - - - - - - +
:                     Payload Data continued ...                :
+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
|                     Payload Data continued ...                |
+---------------------------------------------------------------+
--------------------------------------------------------------------*/
typedef struct _frame_head {
    char fin;
    char opcode;
    char mask;
    unsigned long long payload_length;
    char masking_key[4];
}frame_head;

int base64_encode(char *in_str, int in_len, char *out_str)
{
    BIO *b64, *bio;
    BUF_MEM *bptr = NULL;
    size_t size = 0;

    if (in_str == NULL || out_str == NULL)
        return -1;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, in_str, in_len);
    BIO_flush(bio);

    BIO_get_mem_ptr(bio, &bptr);
    memcpy(out_str, bptr->data, bptr->length);
    out_str[bptr->length-1] = '\0';
    size = bptr->length;

    BIO_free_all(bio);
    return size;
}

/**
 * @brief _readline
 * read a line string from all buffer
 * @param allbuf
 * @param level
 * @param linebuf
 * @return
 */
int _readline(char* allbuf,int level,char* linebuf)
{
    int len = strlen(allbuf);
    for (;level<len;++level)
    {
        if(allbuf[level]=='\r' && allbuf[level+1]=='\n')
            return level+2;
        else
            *(linebuf++) = allbuf[level];
    }
    return -1;
}

int shakehands(int cli_fd)
{
    //next line's point num
    int level = 0;
    //all request data
    char buffer[BUFFER_SIZE];
    //a line data
    char linebuf[256];
    //Sec-WebSocket-Accept
    char sec_accept[32];
    //sha1 data
    unsigned char sha1_data[SHA_DIGEST_LENGTH+1]={0};
    //reponse head buffer
    char head[BUFFER_SIZE] = {0};

    if (read(cli_fd,buffer,sizeof(buffer))<=0)
        perror("read");
    printf("request\n");
    printf("%s\n",buffer);

    do {
        memset(linebuf,0,sizeof(linebuf));
        level = _readline(buffer,level,linebuf);
        //printf("line:%s\n",linebuf);

        if (strstr(linebuf,"Sec-WebSocket-Key")!=NULL)
        {
            strcat(linebuf,GUID);
//            printf("key:%s\nlen=%d\n",linebuf+19,strlen(linebuf+19));
            SHA1((unsigned char*)&linebuf+19,strlen(linebuf+19),(unsigned char*)&sha1_data);
//            printf("sha1:%s\n",sha1_data);
            base64_encode(sha1_data,strlen(sha1_data),sec_accept);
//            printf("base64:%s\n",sec_accept);
            /* write the response */
            sprintf(head, "HTTP/1.1 101 Switching Protocols\r\n" \
                          "Upgrade: websocket\r\n" \
                          "Connection: Upgrade\r\n" \
                          "Sec-WebSocket-Accept: %s\r\n" \
                          "\r\n",sec_accept);

            printf("response\n");
            printf("%s",head);
            if (write(cli_fd,head,strlen(head))<0)
                perror("write");

            break;
        }
    }while((buffer[level]!='\r' || buffer[level+1]!='\n') && level!=-1);
    return 0;
}

int recv_frame_head(int fd,frame_head* head)
{
    char one_char;
    /*read fin and op code*/
    if (read(fd,&one_char,1)<=0)
    {
        perror("read fin");
        return -1;
    }
    head->fin = (one_char & 0x80) == 0x80;
    head->opcode = one_char & 0x0F;
    if (read(fd,&one_char,1)<=0)
    {
        perror("read mask");
        return -1;
    }
    head->mask = (one_char & 0x80) == 0X80;

    /*get payload length*/
    head->payload_length = one_char & 0x7F;

    if (head->payload_length == 126)
    {
        char extern_len[2];
        if (read(fd,extern_len,2)<=0)
        {
            perror("read extern_len");
            return -1;
        }
        head->payload_length = (extern_len[0]&0xFF) << 8 | (extern_len[1]&0xFF);
    }
    else if (head->payload_length == 127)
    {
        char extern_len[8],temp;
        int i;
        if (read(fd,extern_len,8)<=0)
        {
            perror("read extern_len");
            return -1;
        }
        for(i=0;i<4;i++)
        {
            temp = extern_len[i];
            extern_len[i] = extern_len[7-i];
            extern_len[7-i] = temp;
        }
        memcpy(&(head->payload_length),extern_len,8);
    }

    /*read masking-key*/
    if (read(fd,head->masking_key,4)<=0)
    {
        perror("read masking-key");
        return -1;
    }

    return 0;
}

/**
 * @brief umask
 * xor decode
 * @param data
 * @param len
 * @param mask
 */
void umask(char *data,int len,char *mask)
{
    int i;
    for (i=0;i<len;++i)
        *(data+i) ^= *(mask+(i%4));
}

int send_frame_head(int fd,frame_head* head)
{
    char *response_head; //声明 返回头部
    int head_length = 0; //返回头部的初始长度 0
    head->payload_length = 28;
    printf("payload_length长度:%d\n",head->payload_length);
    if(head->payload_length<126)
    {
        response_head = (char*)malloc(2);
        response_head[0] = 0x81;
        response_head[1] = head->payload_length;
        head_length = 2;
    }
    else if (head->payload_length<0xFFFF) //65535
    {
        response_head = (char*)malloc(4);
        response_head[0] = 0x81;
        response_head[1] = 126;
        response_head[2] = (head->payload_length >> 8 & 0xFF);
        response_head[3] = (head->payload_length & 0xFF);
        head_length = 4;
    }
    else
    {
        //no code
        response_head = (char*)malloc(12); //更大
//        response_head[0] = 0x81;
//        response_head[1] = 127;
//        response_head[2] = (head->payload_length >> 8 & 0xFF);
//        response_head[3] = (head->payload_length & 0xFF);
        head_length = 12;
    }

    printf("response_head内容是:%s\n",response_head);

    if(write(fd,response_head,head_length)<=0) //发送 整理好的 返回头部数据
    {
        perror("write head");
        return -1;
    }

    free(response_head);
    return 0;
}


int wait_client(int listen_socket)
{
    struct sockaddr_in cliaddr;
    int addrlen = sizeof(cliaddr);
    printf("waiting for new client ... \n");
    int client_socket = accept(listen_socket, (struct sockaddr *)&cliaddr, &addrlen);
    if(client_socket == -1){
        perror("accept");
        return -1;
    }

    printf("success for new client66 : %s\n", inet_ntoa(cliaddr.sin_addr));

    return client_socket;
}

void hanld_client(int ser_fd, int conn)
{
    shakehands(conn);
    int s;

    int count = 10;
    while (count--) // 为什么要加 while
    {
    frame_head head;//这里就是声明 head的意思  head将会拥有和 frame_head 一样的属性
    s = sizeof(head);
    printf("head的长度是%d\n",s);
    int rul = recv_frame_head(conn,&head);//整理 接收的数据到 &head 中去  ,如果整理失败 则返回 -1  //这里应该是进程不结束 则会一直 读取 接受过来的数据
    if(rul < 0)
        break;
    printf("fin=%d\nopcode=0x%X\nmask=%d\npayload_len=%llu\n",head.fin,head.opcode,head.mask,head.payload_length);
    //echo head
    send_frame_head(conn,&head); //向客户端 发送 response 数据 发送正确后 才可以继续 发送数据
    //read payload data
    char payload_data[1024] = {0}; //声明一个将要 存储发送数据的变量
    char payload_test[] = "{\"code\":200,\"msg\":\"success\"}"; //单独定义一个测试 的数据

//    if (write(conn,payload_test,rul)<=0){
//        perror("write data_test");
//    }
    int size = 0;
    do {
                int rul;
                rul = read(conn,payload_data,1024);//读取 从客户端发送过来的数据 hello jack 存入 payload_data
                printf("rul的长度是:%d\n",rul);
                if (rul<=0)
                    break;
                size+=rul;
                printf("size当前是:%d\n",size);
                umask(payload_data,size,head.masking_key);
                printf("recive内容是:%s\n",payload_data);
                printf("rul长度是:%d\n",rul);
                printf("head.payload_length长度为%d\n",head.payload_length);
                //echo data
                if (write(conn,payload_test,28)<=0)
                    break;

            }while(size<rul); // 这里的 head.payload_length = sizeof(hello jack) = 10


     /* 单独发送数据 start */
     /*int i = 0;
     do {
        if (write(conn,payload_test,rul)<=0)
            printf("不能发送");
            break;
     }while(i<5);*/
     /* 单独发送数据 end */

            printf("\n-----------\n");
            printf("data_test:%s",payload_data);
            printf("\n-----------\n");
    }
    close(conn);
}

void handler(int sig)
{
    while (waitpid(-1,  NULL,   WNOHANG) > 0)
    	{
    		printf ("success to do exit for a client \n");
    	}
}

int main()
{
    int ser_fd = passive_server(9527,20);
    signal(SIGCHLD, handler);
    while(1){
        int conn = wait_client(ser_fd);
        int pid = fork();
        if(pid == -1){
            perror("fork");
            break;
        }
        if(pid > 0){
            close(conn);
            continue;
        }
        if(pid == 0){
            close(ser_fd);
            hanld_client(ser_fd, conn);
            break;
        }
    }
    close(ser_fd);
}
