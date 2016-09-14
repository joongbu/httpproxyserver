#define WIN32_LEAN_AND_MEAN
#include<winsock2.h>
#include<stdio.h>
#include<string>
#include<iostream>
#include<process.h>
#include<string.h>
#pragma comment (lib, "Ws2_32.lib")
#define BUFFER 1024
CRITICAL_SECTION cs;
void proxy(char *sendbuf,int sendlen);
bool addresschange(char *addr);
char remotebuf[BUFFER] = {0x00,}; //받아오기
int remotelen = BUFFER; // 받아오기
char *domainip; // 도메인 주소 변환
char *addr;
void find(char * changebuf);
int check = 1;
unsigned int WINAPI fn1(void* p) {
	char recvbuf[BUFFER] = {0x00,} ;
	int recvbuflen = BUFFER ;
	SOCKET Client = (SOCKET) p ;

	if(recv(Client, recvbuf, recvbuflen,0) > 0)
	{
		printf("%s\n",recvbuf);
		proxy(recvbuf,recvbuflen) ;
		
	}
		EnterCriticalSection(&cs);

		
			if(send(Client, remotebuf, remotelen, 0) == SOCKET_ERROR)
			{
				printf("ERROR : the buffer back to the sender\n");
				closesocket(Client);
				WSACleanup();
				exit(0);
			}
			else 
			{
				printf("send success\n");
				memset(recvbuf,0x00,BUFFER);
				memset(remotebuf,0x00,BUFFER);
			}
		LeaveCriticalSection(&cs);

	return 0;
}
void resetAddress(sockaddr_in *serverAddr, ADDRESS_FAMILY sin_family, int port, ULONG sin_addr)
{
	ZeroMemory(serverAddr, sizeof(*serverAddr));
	serverAddr->sin_family = sin_family;
	serverAddr->sin_port = htons(port);
	serverAddr->sin_addr.s_addr = sin_addr;
}

void remoteAddress(sockaddr_in *remoteAddr, ADDRESS_FAMILY sin_family, int port, char *addr)
{
	ZeroMemory(remoteAddr, sizeof(*remoteAddr));
	remoteAddr->sin_family = sin_family;
	remoteAddr->sin_port = htons(port);
	remoteAddr->sin_addr.s_addr = inet_addr(addr);
}
int getaddr(char *recv)
{
	char *buf1 = strstr(recv,"Host: ")+6;
	char *buf2 = strstr(buf1,"\n");
	int len = strlen(buf1) - strlen(buf2);
	addr = (char *)malloc(len);
	memset(addr,0x00,len);
	memcpy(addr,buf1,len-1);
	if(addr == NULL)
	{
		printf("error : addr not get\n");
		return 1;
	}
	return 0;
}
void proxy(char *sendbuf,int sendlen)
{

	SOCKET RemoteSocket = INVALID_SOCKET;
	struct sockaddr_in remoteAddr;
	int port = 80;
	if(check == 1) 
	{
		getaddr(sendbuf);
		if(addresschange(addr))
		{
			remoteAddress(&remoteAddr, AF_INET, port, domainip);
		}
	}

	if((RemoteSocket = socket(PF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
	{
		printf("ERROR : Create a Socket for conneting to server");
		WSACleanup();
		exit(0);
	}

	if(connect(RemoteSocket, (struct sockaddr*)&remoteAddr, sizeof(remoteAddr)) == SOCKET_ERROR) //SCOKET_ERROR return -1
	{
		printf("Error : Connect to server\n");
		closesocket(RemoteSocket);
		WSACleanup();
		exit(0);
	}

	if(send(RemoteSocket, sendbuf, sendlen, 0) == SOCKET_ERROR) //SOCKET_ERROR return -1;
		{
			printf("Error : Send an initial buffer\n");
			closesocket(RemoteSocket);
			WSACleanup();
			exit(0);
		}
	while(recv(RemoteSocket, remotebuf, remotelen, 0) > 0)
		{
		printf("%s",remotebuf);		
		}
}

bool addresschange(char *addr)
{
	int i = 0;
	struct hostent *hostinfo;
	hostinfo = gethostbyname(addr);
	if(hostinfo->h_addr_list[i] != NULL)
	{
		domainip = inet_ntoa(*(struct in_addr*)hostinfo->h_addr_list[i]);
		return true;
	}
	return false;
}

int main(int argc, char **argv)
{	
	DWORD TIME = 1;
	WSADATA wsaData;
	SOCKET Listen = INVALID_SOCKET;
	SOCKET Client = INVALID_SOCKET;
	struct sockaddr_in serverAddr;
	int port = 0;
	InitializeCriticalSection(&cs);
	if(!(argc <= 3 && argc >=2))
	{
		printf("syntax : netserver <port> [-echo]\n");
		exit(0);
	}
	printf("local Proxy server\n");
	port = atoi(argv[1]);
	if(WSAStartup(MAKEWORD(2,2), &wsaData) != 0)
	{
		printf("Error : Initialize Winsock\n");
		WSACleanup();
		exit(0);
	}
	if((Listen = socket(PF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
	{
		printf("ERROR : Create a Socket for connetcting to server\n");
		WSACleanup();
		exit(0);
	}
	resetAddress(&serverAddr, AF_INET, port, htonl(INADDR_ANY));
	if(bind(Listen, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) != 0)
	{
		printf("ERROR : Setup the TCP Listening socket\n");
		closesocket(Listen);
		WSACleanup();
		exit(0);
	}
	if(listen(Listen, SOMAXCONN) == SOCKET_ERROR)
	{
		printf("ERROR : Listen\n");
		closesocket(Listen);
		WSACleanup();

		exit(0);
	}

while(1)
{
	while((Client = accept(Listen,NULL,NULL)) != INVALID_SOCKET)
	{
		_beginthreadex(NULL,0, fn1,(void*)Client,0,NULL);
	}	
		DeleteCriticalSection(&cs);

}
closesocket(Listen);
closesocket(Client);
WSACleanup();
return 0;
}
