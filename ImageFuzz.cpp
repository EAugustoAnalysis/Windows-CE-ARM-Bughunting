// ImageFuzz.cpp : Fuzzes the LoadKernelLibrary function 
// Written in Visual Studio 2006 using the Dot Net Framework for Windows CE
// Author: Elias Augusto


#include "stdafx.h"
#include "tchar.h"
#include "windows.h"
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
#define HARNESS_CRASH 0xDEAD0512
#define FUZZ_CRASH 0xDEAD0404
#define NON_FUZZ_EXCEPT 0xDEAD0400

//Recieve file rules
#define MAX_FILESIZE 50000 //Max filesize of ~50kb
#define MAX_FILEALLOC 51200 //Max recieve allocation of 50kb
#define MIN_FILESIZE 1 //Min filesize of 4 bytes

//Bind server and remote monitor port
#define PORT 8337
#define MONPORT 8457

//Handle, global for benefit of exception handler
HANDLE fuzzMethod;

//Socket Declarations
WSADATA wsock;
SOCKET sock1,sock2,MonAgent;
struct sockaddr_in host,client,monaddr;

//Fuzz result return value
DWORD fuzzResultReturn;

//Structure to store data for method being fuzzed
struct FUZZDATA{
	unsigned char* fuzzIn;
	int dataSize;
};

//Typedefs for coredll functions
typedef BOOL(WINAPI *SETKMODE)(BOOL);
typedef DWORD(WINAPI *SETPROCPERMISSIONS)(DWORD);
typedef int(WINAPI *NKVDBGPRINTFW)(LPCWSTR);
typedef HMODULE(WINAPI *LOADKERNELLIBRARY)(LPCWSTR);
SETKMODE SetKMode;
SETPROCPERMISSIONS SetProcPermissions;
NKVDBGPRINTFW NKvDbgPrintfW;
LOADKERNELLIBRARY LoadKernelLibrary;

void fuzzFunc(unsigned char* data, int size){

	//Set thread to kernel mode
	DWORD oldPerm = SetProcPermissions(0xFFFFFFFF);
	BOOL Kmode = SetKMode(TRUE);
	
	//Turn unsigned char* to wide string
	wchar_t * utfData=(wchar_t *)malloc(size*2);
	mbstowcs(utfData,(char*)data,size); //We don't need to account for the null byte because that's done in the agent
	LPWSTR winData=utfData;

	try{
	HMODULE hModule = LoadKernelLibrary(winData);
		if(hModule==NULL){ //Return function failure
			fuzzResultReturn=0x516;
		}
		else{
			fuzzResultReturn=0x200; //Return function success
		}
	}
	catch(...){
		fuzzResultReturn=NON_FUZZ_EXCEPT ; //Return error	
	}
	//Restore to usermode
	SetKMode(FALSE);
	SetProcPermissions(oldPerm);
}

DWORD WINAPI metHandler(LPVOID lpParam){
	FUZZDATA* passedData=(FUZZDATA*)lpParam;
	int size=passedData->dataSize;
	unsigned char* data= (unsigned char *)malloc(size);
	memcpy(data,passedData->fuzzIn,size);
	
	_try{
		fuzzFunc(data,size);
	}
	_except(EXCEPTION_EXECUTE_HANDLER){
		fuzzResultReturn=FUZZ_CRASH;
	}
	free(data);
	return 0; //Dummy for the thread handler
}

DWORD threadHandler(unsigned char* funInput, int inSize){
	FUZZDATA params;
	params.fuzzIn=(unsigned char *)malloc(inSize);
	memcpy(params.fuzzIn,funInput,inSize);
	params.dataSize=inSize;
	fuzzResultReturn=0; //Initialize fuzzResultReturn to prevent errors during testing
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
	//Load Coredll Functions
	HMODULE hModule =LoadLibrary(L"coredll.dll");
	
	SetKMode=(SETKMODE)GetProcAddress(hModule,L"SetKMode");
	SetProcPermissions=(SETPROCPERMISSIONS)GetProcAddress(hModule,L"SetProcPermissions");
	LoadKernelLibrary =(LOADKERNELLIBRARY)GetProcAddress(hModule,L"LoadKernelLibrary");
	NKvDbgPrintfW=(NKVDBGPRINTFW)GetProcAddress(hModule,L"NKvDbgPrintfW");

	unsigned char *sockFile;
	bool isFuzzing=true;

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

		DWORD rBuf=MAX_FILEALLOC; //Max filesize allocation is 50kb
		int rBufLen=sizeof(rBuf);
		DWORD rLow=MIN_FILESIZE; //Min transmission is 4 bytes
		int rLowLen=sizeof(rLow);

		setsockopt(sock2,SOL_SOCKET,SO_SNDTIMEO,(char *)&tOut,tOutLen); //Send timeout
		setsockopt(sock2,SOL_SOCKET,SO_RCVTIMEO,(char *)&tOut,tOutLen); //Recieve timeout
		setsockopt(sock2,SOL_SOCKET,SO_RCVBUF,(char *)&rBuf,rBufLen);
		setsockopt(sock2,SOL_SOCKET,SO_RCVBUF,(char *)&rLow,rLowLen);


		char *sockFileSigned=(char *)malloc(MAX_FILESIZE);
		//memset(sockFileSigned, 0, sizeof(sockFileSigned)); //Inefficient, put here for testing purposes
		printf("\nRequesting file");
		int rVal= recv(sock2,sockFileSigned,MAX_FILESIZE,0); //Note: Null byte must manually be sent, not a string
		//Exit if a real crash occurs
		if(rVal==-1 || sock2==INVALID_SOCKET){
			printf("\nClient error");
			closesocket(sock2);
			free(sockFileSigned);
			break;
		}
		//Every once in a while the recv performs a "graceful exit"
		//We don't want to test the function with a zero value but we do want to continue
		if(rVal==0){
			printf("\nClient error");
			closesocket(sock2);
			free(sockFileSigned);
			goto Replay;
		}
		closesocket(sock2);
		sockFile=(unsigned char *)malloc(rVal);
		memcpy(sockFile,sockFileSigned,rVal);
		DWORD thrd = threadHandler(sockFile,rVal);
		printf("\nReturn Value: %d",thrd);
		free(sockFile);
		free(sockFileSigned);
		if(thrd==FUZZ_CRASH){
			printf("\nSending fault to fuzz agent");
			//Create socket for connecting to monitor
			MonAgent=socket(AF_INET,SOCK_STREAM,0);
			if(MonAgent==INVALID_SOCKET){
				printf("\nServer error");
				break;
			}
			//Reuses client address as address of harness to avoid hardcoding addresses
			monaddr.sin_family=AF_INET;
			monaddr.sin_addr.s_addr=client.sin_addr.s_addr;
			monaddr.sin_port=htons(MONPORT);
			int conAg = connect( MonAgent, (struct sockaddr*) &monaddr, sizeof(monaddr));
			if ( conAg == SOCKET_ERROR) {
				closesocket(MonAgent);
				printf("\nConnection error");
				break;
			}
			char * initmsg="[fault]";
			int serr=send(sock2,initmsg,strlen(initmsg),0);
			if(MonAgent==INVALID_SOCKET){
				closesocket(MonAgent);
				printf("\nMonitor error");
				break;
			}
			closesocket(MonAgent);
		}
	Replay:;
	}

	closesocket(sock1);
	WSACleanup();
	printf("\nExiting");
	return 0;
}

