#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <string>
#include <stdio.h>
#include <iostream>
#include <WS2tcpip.h>
#include <thread>
#include <regex>
#include<process.h>
#pragma comment (lib, "Ws2_32.lib")
#define BUFFER 50000 //tcp 패킷 최대 바이트 수
std::string getAddr(char *_data);
void checkArguments(int argc, char **argv);
std::string URLToAddrStr(std::string addr);
struct sockaddr_in initAddr(int port, std::string addr);
void initWSA();
void errorHandle(std::string msg, SOCKET s);
std::string web_error(char *_data);
void backward(SOCKET Client, SOCKET RemoteSocket);
void forward(struct sockaddr_in serverAddr);
using namespace std;
int main(int argc, char **argv)
{
	checkArguments(argc, argv);
	initWSA();
	int port = atoi(argv[1]);//인자로 받은 포트값 넣기
	struct sockaddr_in serverAddr = initAddr(port, std::string(""));
	std::thread(forward, serverAddr).join();
}

std::string getAddr(char *_data)
{
	std::string data(_data);
	std::smatch result;
	std::regex pattern("Host: (.*)");
	if (std::regex_search(data, result, pattern)){
		return result[1];
	}
	return "";
}

void checkArguments(int argc, char **argv)
{
	if (!(argc <= 3 && argc >= 2))
	{
		printf("syntax : netserver <port> [-echo]\n");
		exit(0);
	}
}

std::string URLToAddrStr(std::string addr)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	struct sockaddr_in *sin;
	int *listen_fd;
	int listen_fd_num = 0;
	char buf[80] = {0x00, };
	int i = 0;
	memset(&hints, 0x00, sizeof(struct addrinfo));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(addr.c_str(), NULL, &hints, &result) != 0) {
		perror("getaddrinfo");
		return std::string("");
	}
	for (rp = result; rp != NULL; rp = rp->ai_next)
	{
		listen_fd_num++;
	}
	listen_fd = (int *)malloc(sizeof(int)*listen_fd_num);
	printf("Num %d", listen_fd_num);
	for (rp = result, i = 0; rp != NULL; rp = rp->ai_next, i++)
	{
		if (rp->ai_family == AF_INET)
		{
			sin = (sockaddr_in *)rp->ai_addr;
			inet_ntop(rp->ai_family, &sin->sin_addr, buf, sizeof(buf));
			printf("<bind 정보 %d %d %s>\n", rp->ai_protocol, rp->ai_socktype, buf);
			return std::string(buf);
		}
	}
	return std::string("");
}

struct sockaddr_in initAddr(int port, std::string addr)
{
	struct sockaddr_in newAddr;
	ZeroMemory(&newAddr, sizeof(newAddr));
	newAddr.sin_family = AF_INET;
	newAddr.sin_port = htons(port);
	if (addr.empty()) {
		newAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	}
	else {
		inet_pton(AF_INET, addr.c_str(), &newAddr.sin_addr.s_addr);
	}
	return newAddr;
}

void initWSA() {
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		printf("Error : Initialize Winsock\n");
		WSACleanup();
		exit(0);
	}
}

void errorHandle(std::string msg, SOCKET s) {
	std::cerr << "ERROR : " << msg;
	if (s != NULL) {
		closesocket(s);
	}
	WSACleanup();
	exit(0);
}
std::string web_error(char *_data)
{
	std::string data(_data);
	std::regex pattern("404");
	std::smatch result;
	if (std::regex_search(data, result, pattern)) {
		return "";
	}
	return "true";
}
void backward(SOCKET Client, SOCKET RemoteSocket)
{
	char buf[BUFFER];
	char *remotebuf;
	int recvlen;
	while ((recvlen = recv(RemoteSocket, buf, BUFFER, 0)) > 0) {
		if (recvlen == -1)
		{
			cout << "error : backward recv()\n";
			continue;
		}
		remotebuf = (char *)calloc(recvlen, sizeof(char)); //recv 받은 바이트 만큼 저장
		memcpy(remotebuf, buf, recvlen);
		cout << "Proxy => Web\n";
		cout << remotebuf << "\n";
		//delete[] buf;
		memset(buf, NULL, BUFFER);
		if (send(Client, remotebuf, recvlen, 0) == SOCKET_ERROR) {
			printf("send to client failed.");
			continue;
		}
	/*	if (web_error(remotebuf).empty())
			break;
		else
			continue;*/
		delete[] remotebuf;

	}
}

void forward(struct sockaddr_in serverAddr)
{
	SOCKET Client, Server;
	if ((Server = socket(PF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
		errorHandle("ERROR : Create a Socket for connetcting to server\n", NULL);
	}
	if (::bind(Server, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) != 0) {
		errorHandle("ERROR : Setup the TCP Listening socket\n", Server);
	}
	if (listen(Server, SOMAXCONN) == SOCKET_ERROR) {
		errorHandle("ERROR : Listen\n", Server);
	}

	char buf[BUFFER];
	char *recvbuf;
	int recvbuflen;
	int port; //input auto port
	//여기서 443포트 확인

	std::string hostAddr, domainip;
	SOCKET RemoteSocket;
	//memset(recvbuf, 0x00, BUFFER);

	while (true) {
		if ((Client = accept(Server, NULL, NULL)) == INVALID_SOCKET) {
			printf("error : accept\n");
			continue;
		}
		port = 80;
		//프록시 -> 웹 으로 요청하는 반복문
		while ((recvbuflen = recv(Client, buf, BUFFER, 0)) > 0) {
			if (recvbuflen == -1)
			{
				break;
			}
			recvbuf = (char *)calloc(recvbuflen, sizeof(char));
			memcpy(recvbuf, buf, recvbuflen);
			//delete[] buf; //메모리 해제
			memset(buf, NULL, BUFFER); //NULL 초기화
			cout << " HOST => Proxy \n";
			cout << recvbuf <<"\n";
			hostAddr = getAddr(recvbuf);
			if (hostAddr == "")
			{
				printf("Empty Host Address..\n");
				break;
			}
			else if (strstr(hostAddr.c_str(), "443") != NULL)
			{
				cout << "ssl Host :" << hostAddr<<endl;
				port = 443;
			}
			
			domainip = URLToAddrStr(hostAddr);
			cout << domainip << endl;
			if (domainip == "") {
				break;
			}
			struct sockaddr_in remoteAddr; //proxy -> web send
			remoteAddr = initAddr(port, domainip); //포트와 도메인 소켓에 넣기
			if ((RemoteSocket = socket(PF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
				errorHandle("ERROR : Create a Socket for conneting to server\n", NULL);
			}
			if (connect(RemoteSocket, (struct sockaddr*) &remoteAddr, sizeof(remoteAddr)) == SOCKET_ERROR) {
				errorHandle("Error : Connect to server\n", RemoteSocket);
			}			
			if (send(RemoteSocket, recvbuf, recvbuflen, 0) == SOCKET_ERROR)
			{
				printf("send to webserver failed.");
				continue;
			}
			delete[] recvbuf;
			cout<<"프록시로 보냄\n";
			std::thread(backward, Client, RemoteSocket).detach();
		}
	}
}