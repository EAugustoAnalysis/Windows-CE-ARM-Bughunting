// HarnessHandler.cpp 
// Written in Visual Studio 2006 using the Dot Net Framework for Windows CE
// Author: Elias Augusto
// Remote Fuzzing Harness For Windows CE 4.2 (Any Architecture)
// Will be used in upcomming projects
//

#include "stdafx.h"
#include "Winsock2.h"
#include "ws2tcpip.h"
#include "stdlib.h"
#include <iostream>
#include <exception>
#pragma comment(lib,"Ws2.lib")

//Timeout for processing can be adjusted here
#define FUZZ_TIME_OUT 5000

//Error codes
#define FUZZ_TIME_ERROR 0xDEAD0500
#define FUZZ_CRASH 0xDEAD0404
#define NON_FUZZ_EXCEPT 0xDEAD0400 //Return value provided for standard function exceptions

//Bind server port
#define PORT 8337

//Handle, global for benefit of exception handler
HANDLE fuzzMethod;

//Socket Declarations
WSADATA wsock;
SOCKET sock1,sock2;
struct sockaddr_in host,client;

//Fuzz result return value
DWORD fuzzResultReturn;


//Structure to store data for method being fuzzed
struct FUZZDATA{
	unsigned char* fuzzIn;
	int dataSize;
};

DWORD WINAPI metHandler(LPVOID lpParam){
	//This part must be edited every time a new function is being fuzzed
	//Should return a DWORD corresponding to the return value
	//Note: In many instances a function will return errors that are not indicators of a bug, but rather of bad input
	//		Any expected errors for the function being tested must be handled here

	FUZZDATA* passedData=(FUZZDATA*)lpParam;
	int size=passedData->dataSize;
	unsigned char* data= (unsigned char *)malloc(size);
	memcpy(data,passedData->fuzzIn,size);

	free(data);
	fuzzResultReturn=0; //The actual return value of the function being tested
	return 0; //Dummy for the thread handler
}

DWORD threadHandler(unsigned char* funInput, int inSize){
	FUZZDATA params;
	params.fuzzIn=(unsigned char *)malloc(inSize);
	memcpy(params.fuzzIn,funInput,inSize);
	params.dataSize=inSize;

	_try{
		//Run one iteration of fuzzing
		DWORD retValue;
		DWORD timeout;

		fuzzMethod = CreateThread(NULL,0,metHandler,&params,0,&retValue);
		
		//Wait for the fuzzMethod to return and give a timeout error if it fails
		timeout = WaitForSingleObject(fuzzMethod,FUZZ_TIME_OUT);
		if(timeout==WAIT_TIMEOUT){
			free(params.fuzzIn);
			return FUZZ_TIME_ERROR;
		}
		else{
			free(params.fuzzIn);
			return fuzzResultReturn;
		}
	}
	_except(EXCEPTION_EXECUTE_HANDLER){
		//Let SEH capture any exceptions and return the failure code
		TerminateThread(fuzzMethod,404);
		free(params.fuzzIn);
		return FUZZ_CRASH;
	}
}

int initWinSock(){
	int soc=WSAStartup(MAKEWORD(2,2),&wsock);
	if(soc!=0){
		return 0; //Winsock failed to start
	}
	return 1;
}

int openSocket(){
	sock1=socket(AF_INET,SOCK_STREAM,0);
	if(sock1==INVALID_SOCKET){ 
		return 0; //Socket initialization failed
	}
	return 1;
}

int bindSocket(){
	//Declare host information
	host.sin_family=AF_INET; //TCP
	host.sin_addr.s_addr=INADDR_ANY; //Bind to all device IP's
	host.sin_port=htons(PORT);

	int berr=bind(sock1,(struct sockaddr *)&host,sizeof(host));
	if(berr==SOCKET_ERROR){
		return 0; //Error binding socket
	}
	return 1;
}

int _tmain(int argc, _TCHAR* argv[])
{
	unsigned char *sockFile;
	int transferSize; //Size of file being transfered
	bool isFuzzing;

	isFuzzing=true; //

	printf("Initializing winsock...");
	if(initWinSock()==0){
		printf("\nwinsock failed");
		return 0;
	}
	printf("\nDone");
	printf("\nInitializing socket...");
	if(openSocket()==0){
		printf("\nSocket failed...");
		WSACleanup();
		return 0;
	}
	printf("\nDone");
	printf("\nBinding socket...");
	if(bindSocket()==0){
		printf("\nBinding failed...");
		closesocket(sock1);
		WSACleanup();
		return 0;
	}
	printf("\nDone");
	
	while(isFuzzing==true &&sock1!=INVALID_SOCKET){
		int socSize=sizeof(struct sockaddr_in);
		
		listen(sock1,2); //Max clients 2, intended clients 1
		printf("\nListening for clients");
		sock2=accept(sock1,(struct sockaddr *)&client,&socSize);
		printf("\nConnected to client");
		
		int tOut=FUZZ_TIME_OUT;
		int tOutLen=sizeof(tOut);
		//setsockopt(sock2,SOL_SOCKET,SO_SNDTIMEO,(char *)&tOut,tOutLen); //Send timeout
		//setsockopt(sock2,SOL_SOCKET,SO_RCVTIMEO,(char *)&tOut,tOutLen); //Recieve timeout
		
		char* initmsg="Fuzzer, send a filesize: ";
		int serr=send(sock2,initmsg,strlen(initmsg),0);
		
		if(sock2==INVALID_SOCKET){
			printf("\nClient error");
			break;
		}
		printf("\nRequesting file size");
		char fileLen[6];
		int rerr= recv(sock2,fileLen,5,0);
		if(sock2==INVALID_SOCKET){
			printf("\nClient error");
			break;
		}
		transferSize=atoi(fileLen);
		if(transferSize==0 || transferSize<0){
			printf("\nFuzzing finished");
			break;
		}
		initmsg="Send file: ";
		char *sockFileSigned=(char *)malloc(transferSize);
		sockFile=(unsigned char *)malloc(transferSize);
		serr=send(sock2,initmsg,strlen(initmsg),0);
		if(sock2==INVALID_SOCKET){
			printf("\nClient error");
			free(sockFile);
			free(sockFileSigned);
			break;
		}
		printf("\nRequesting file");
		rerr= recv(sock2,sockFileSigned,transferSize,0);
		if(sock2==INVALID_SOCKET){
			printf("\nClient error");
			free(sockFile);
			free(sockFileSigned);
			break;
		}
		memcpy(sockFile,sockFileSigned,transferSize);
		DWORD thrd = threadHandler(sockFile,transferSize);
		free(sockFile);
		free(sockFileSigned);
		char result[50];
		sprintf(result,"Return Code: %d",thrd); //Send result of fuzzing back to agent
		printf("\nSending result to fuzz agent");
		serr=send(sock2,result,strlen(result),0);
		if(sock2==INVALID_SOCKET){
			printf("\nClient error");
			break;
		}
		closesocket(sock2);
	}

	closesocket(sock1);
	WSACleanup();
	printf("\nExiting");
	return 0;
}

