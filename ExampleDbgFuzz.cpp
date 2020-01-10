// ExampleDbgFuzz.cpp : Example debug fuzzer
// Written in Visual Studio 2008 using the Dot Net Framework for Windows CE
// Author: Elias Augusto

#include "stdafx.h"
#include "tchar.h"
#include "windows.h"
#include "Winsock2.h"
#include "ws2tcpip.h"
#include "stdlib.h"
#include "winbase.h"
#include <iostream>
#include <exception>
#pragma comment(lib,"Ws2.lib")

//Timeout for processing can be adjusted here
#define FUZZ_TIME_OUT 9000
#define DBG_TIMEOUT 6000
#define KILL_DI_T 1000

//Error codes
#define FUZZ_TIME_ERROR 0xDEAD0500
#define HARNESS_CRASH 0xDEAD0512
#define FUZZ_CRASH 0xDEAD0404
#define NON_FUZZ_EXCEPT 0xDEAD0400

//Recieve file rules
#define MAX_FILESIZE 50000 //Max filesize of ~50kb
#define MAX_FILEALLOC 51200 //Max recieve allocation of 50kb
#define MIN_FILESIZE 50 //Min filesize of 50 bytes

//Bind server and remote monitor port
#define PORT 8337
#define MONPORT 8457

//Logging - Should be disabled if peach is the fuzzer as it logs crashes more space efficiently
//Note: Enabled because peach is a dumb fuzzer
//Peach cannot tell what payload crashed the system post of the time when debugging rather than hooking due to timing
//This can be improved by changin the timing in your peach pitt file
#define LOGFILENAME "\\Storage Card\\pwdlogfile.txt"
#define ENABLE_ACTIVE_LOGGING TRUE


//Key variables
INPUT downKey;
INPUT enterKey;

//Handle, global for benefit of exception handler
HANDLE fuzzMethod;

//Socket Declarations
WSADATA wsock;
SOCKET sock1,sock2,MonAgent;
struct sockaddr_in host,client,monaddr;

//Fuzz result return value
DWORD fuzzResultReturn;
DWORD fuzzExceptReturn;

//For ease of process killing
STARTUPINFO si;
PROCESS_INFORMATION pi;

//Running tracker for process permissions
DWORD oldPerm;

//Structure for hwnd return function
struct windHand{
	DWORD procID;
	HWND window;
};

struct DEBUGPASS{
	wchar_t *args;
	DWORD flags;
};

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

void HunterKiller(wchar_t arg[]){ //Kills our process of choice
	HWND testWindow;
	do{	
		testWindow=NULL;
		testWindow=FindWindow(NULL,arg);

		DWORD testProcID;

		if(testWindow!=NULL){
			GetWindowThreadProcessId(testWindow,&testProcID);
			
			NKDbgPrintfW(L"Procid of illicit IE Window: %X\n",testProcID);
			
			if(testProcID!=NULL){
				HANDLE tmpHandle=OpenProcess(PROCESS_TERMINATE,FALSE,testProcID);
				if(tmpHandle!=NULL){
					TerminateProcess(tmpHandle,0);
				}
			}

		}
	}while(testWindow!=NULL);
}

void HuggerCloserPW(){ //Kills our process of choice gently
	HWND testWindow=FindWindow(L"Worker",L"Pocket Word");

	DWORD testProcID;

	if(testWindow!=NULL){
		GetWindowThreadProcessId(testWindow,&testProcID);
			
		NKDbgPrintfW(L"Procid of worker window being closed: %X\n",testProcID);

		SendMessage(testWindow,WM_CANCELMODE,NULL,NULL);

	}
	
	HWND testWindow2=FindWindow(L"Pocket Word",L"Pocket Word");

	DWORD testProcID2;

	if(testWindow2!=NULL){
		GetWindowThreadProcessId(testWindow,&testProcID2);
			
		NKDbgPrintfW(L"Procid of main window being closed: %X\n",testProcID2);

		SendMessage(testWindow2,WM_CLOSE,NULL,NULL);

	}
}

//Every once in a while, a mutation creates a dialog box trying to connrect to a work network. This attempts to kill it using kernel permissions
DWORD WINAPI KillDialogue(LPVOID lpParam){
	HWND box=NULL;
	HWND prevBox=NULL;
	do{
		_try{
			box=FindWindow(L"Dialog",NULL);
			if(box!=NULL && box!=prevBox){
				SendMessage(box,WM_DESTROY,0,0); //This line actually kills dialog boxes quite well, just not necessarily the ones we care about
				//Note: It also kills connection boxes, just very slowly
			}
			else{
				break;
			}
			prevBox=box;
		}
		_except(EXCEPTION_EXECUTE_HANDLER){
			NKvDbgPrintfW(L"Failed to kill dialog box");
			break;
		}
	}while(box!=NULL);
	return 0;
}


DWORD debugProc(DWORD timeout){
			DEBUG_EVENT debug_event;
			memset(&debug_event,0,sizeof(debug_event));
			
			while(true){
				if(!WaitForDebugEvent(&debug_event,timeout)){
					break;
				}
				//Note that we're doing some exploitability assesment ourselves because peach can't
				if(debug_event.dwDebugEventCode==EXCEPTION_DEBUG_EVENT){
					NKDbgPrintfW(L"\nEXCEPTION DEFINITELY HAPPENED: %d\n",debug_event.u.Exception.ExceptionRecord.ExceptionCode);
					//Common, possibly exploitable exception types
					if(debug_event.u.Exception.ExceptionRecord.ExceptionCode==EXCEPTION_ACCESS_VIOLATION){
						goto ReturnCrash;
					}
					else if(debug_event.u.Exception.ExceptionRecord.ExceptionCode==EXCEPTION_ARRAY_BOUNDS_EXCEEDED){
						goto ReturnCrash;
					}
					else if(debug_event.u.Exception.ExceptionRecord.ExceptionCode==EXCEPTION_DATATYPE_MISALIGNMENT){
						goto ReturnCrash;
					}
					/*else if(debug_event.u.Exception.ExceptionRecord.ExceptionCode==EXCEPTION_GUARD_PAGE){
						goto ReturnCrash;
					}*/
					
					//Common DoS exception types
					/*else if(debug_event.u.Exception.ExceptionRecord.ExceptionCode==EXCEPTION_STACK_OVERFLOW){
						goto ReturnCrash;
					}*/
					else if(debug_event.u.Exception.ExceptionRecord.ExceptionCode==EXCEPTION_ILLEGAL_INSTRUCTION){
						goto ReturnCrash;
					}
					else if(debug_event.u.Exception.ExceptionRecord.ExceptionCode==EXCEPTION_IN_PAGE_ERROR){
						goto ReturnCrash;
					}
					else if(debug_event.u.Exception.ExceptionRecord.ExceptionCode==EXCEPTION_PRIV_INSTRUCTION){
						goto ReturnCrash;
					}

					//Breakpoints, we don't care about those
					else if(debug_event.u.Exception.ExceptionRecord.ExceptionCode==EXCEPTION_SINGLE_STEP){
						goto KeepDebugging;
					}
					else if(debug_event.u.Exception.ExceptionRecord.ExceptionCode==EXCEPTION_BREAKPOINT){
						goto KeepDebugging;
					}

					//Ignore unimportant exceptions
					else{
						NKDbgPrintfW(L"Boring");
						break;
					}
					ReturnCrash:
						fuzzResultReturn=FUZZ_CRASH;
						NKDbgPrintfW(L"CRASHCRASHCRASH");
						fuzzExceptReturn=debug_event.u.Exception.ExceptionRecord.ExceptionCode;
						break;
				}
				else if(debug_event.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT){
					NKDbgPrintfW(L"Exit\n");

				}
				else{
					NKDbgPrintfW(L"Debug: %d\n",debug_event.dwDebugEventCode);
				}
				KeepDebugging:
					ContinueDebugEvent(debug_event.dwProcessId,debug_event.dwThreadId,DBG_CONTINUE);
			}
			return 0;
}

void fuzzFunc(unsigned char* data, int size){

	char fuzzFilename[]="\\Program Files\\ppc.txt";
	wchar_t procFFArgs[]=L"\\Program Files\\ppc.txt"; //Bad practice but the filename is static

	//Turn unsigned char* to wide string
	FILE * fuFil=fopen(fuzzFilename,"w+");
	fwrite((char *)data,sizeof(char),size,fuFil);
	fclose(fuFil);

	//Set thread to kernel mode
	oldPerm = SetProcPermissions(0xFFFFFFFF);
	BOOL Kmode = SetKMode(TRUE);

	//Debug program
	_try{
		memset(&si,0,sizeof(si));
		memset(&pi,0,sizeof(pi));
		//DWORD cProcFlags = DEBUG_ONLY_THIS_PROCESS; //Testing
		DWORD cProcFlags =DEBUG_PROCESS;
		
		CreateProcess(L"pword.exe",procFFArgs,NULL,NULL,FALSE,cProcFlags,NULL,NULL,&si,&pi);
		
		NKDbgPrintfW(L"Procid: %X\n",pi.dwProcessId);

		debugProc(DBG_TIMEOUT);

		HWND testWindow = FindWindow(NULL,L"Pocket Word");

		DWORD testProcID;

		GetWindowThreadProcessId(testWindow,&testProcID);

		NKDbgPrintfW(L"Procid: %X\n",testProcID);
		
		if(pi.dwProcessId==testProcID){ //Be gentle
			HuggerCloserPW();
		}
		else{ //Be rude
			HunterKiller(L"Pocket Word");
		}
		
		
	}
	_except(EXCEPTION_EXECUTE_HANDLER){
		fuzzResultReturn=NON_FUZZ_EXCEPT; //Changed because  of failcriticalerrors
	}

	CreateThread(NULL,0,KillDialogue,0,0,0); //Just in case
	DWORD killtimeout = WaitForSingleObject(KillDialogue,KILL_DI_T);
	if(killtimeout==WAIT_TIMEOUT){
		NKDbgPrintfW(L"\nNoKill");
		TerminateThread(KillDialogue,404);
	}
	else{
		NKDbgPrintfW(L"\nKill");
	}

	//Set process permissions to normal
	SetKMode(FALSE);
	SetProcPermissions(oldPerm);

	//Delete the file
	DeleteFile(procFFArgs);
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
		fuzzResultReturn=NON_FUZZ_EXCEPT;
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
			TerminateThread(fuzzMethod,404);
			free(params.fuzzIn);
			if(fuzzResultReturn!=FUZZ_CRASH){
				return FUZZ_TIME_ERROR;
			}
			else{
				return FUZZ_CRASH;
			}
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
			SetKMode(FALSE);
			SetProcPermissions(oldPerm);
			if(fuzzResultReturn!=FUZZ_CRASH){
				return NON_FUZZ_EXCEPT;
			}
			else{
				return FUZZ_CRASH;
			}
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

	//Open up the log if logging is enabled
	if(ENABLE_ACTIVE_LOGGING){
		FILE * logFil=fopen(LOGFILENAME,"w+");
		fclose(logFil);
	}

	unsigned char *sockFile;
	bool isFuzzing=true;

	NKvDbgPrintfW(L"Initializing winsock...");
	if(initWinSock()==0){
		NKvDbgPrintfW(L"\nwinsock failed");
		return 0;
	}
	NKvDbgPrintfW(L"\nDone");
	NKvDbgPrintfW(L"\nInitializing socket...");
	if(openSocket()==0){
		NKvDbgPrintfW(L"\nSocket failed...");
		WSACleanup();
		return 0;
	}
	NKvDbgPrintfW(L"\nDone");
	NKvDbgPrintfW(L"\nBinding socket...");
	if(bindSocket()==0){
		NKvDbgPrintfW(L"\nBinding failed...");
		closesocket(sock1);
		WSACleanup();
		return 0;
	}
	NKvDbgPrintfW(L"\nDone");

	HunterKiller(L"Pocket Word");
	NKDbgPrintfW(L"Killing errant word processes");
	
	while(isFuzzing==true && sock1!=INVALID_SOCKET){
		int socSize=sizeof(struct sockaddr_in);
		
		listen(sock1,2); //Max clients 2, intended clients 1
		NKvDbgPrintfW(L"\nListening for clients");
		sock2=accept(sock1,(struct sockaddr *)&client,&socSize);
		NKvDbgPrintfW(L"\nConnected to client");
		
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
		NKvDbgPrintfW(L"\nRequesting file");
		int rVal= recv(sock2,sockFileSigned,MAX_FILESIZE,0); //Note: Null byte must manually be sent, not a string
		//Exit if a real crash occurs
		if(rVal==-1 || sock2==INVALID_SOCKET){
			NKvDbgPrintfW(L"\nClient error");
			closesocket(sock2);
			free(sockFileSigned);
			break;
		}
		//Every once in a while the recv performs a "graceful exit"
		//We don't want to test the function with a zero value but we do want to continue
		if(rVal==0){
			NKvDbgPrintfW(L"\nClient error");
			closesocket(sock2);
			free(sockFileSigned);
			goto Replay;
		}
		closesocket(sock2);
		sockFile=(unsigned char *)malloc(rVal);
		memcpy(sockFile,sockFileSigned,rVal);
		DWORD thrd = threadHandler(sockFile,rVal);
		wchar_t thrdPrinter[50];
		wsprintf(thrdPrinter,L"\nReturn Value: %X\n",thrd);
		NKvDbgPrintfW(thrdPrinter);

		//Free the sock file
		free(sockFile);
		if(thrd==FUZZ_CRASH){
			if(ENABLE_ACTIVE_LOGGING){
				//Log crash
				FILE * logFileP = fopen(LOGFILENAME,"a");
				fprintf(logFileP,"\nLog Crash: %X\nData:\n\n",fuzzExceptReturn);
				fwrite(sockFileSigned,sizeof(char),sizeof(sockFileSigned),logFileP);
				fclose(logFileP);
			}

			NKvDbgPrintfW(L"\nSending fault to fuzz agent");
			//Create socket for connecting to monitor
			MonAgent=socket(AF_INET,SOCK_STREAM,0);
			if(MonAgent==INVALID_SOCKET){
				NKvDbgPrintfW(L"\nServer error");
				break;
			}
			//Reuses client address as address of harness to avoid hardcoding addresses
			monaddr.sin_family=AF_INET;
			monaddr.sin_addr.s_addr=client.sin_addr.s_addr;
			monaddr.sin_port=htons(MONPORT);
			int conAg = connect( MonAgent, (struct sockaddr*) &monaddr, sizeof(monaddr));
			if ( conAg == SOCKET_ERROR) {
				closesocket(MonAgent);
				NKvDbgPrintfW(L"\nConnection error");
				break;
			}
			char * initmsg="[fault]";
			int serr=send(sock2,initmsg,strlen(initmsg),0);
			if(MonAgent==INVALID_SOCKET){
				closesocket(MonAgent);
				NKvDbgPrintfW(L"\nMonitor error");
				break;
			}
			closesocket(MonAgent);
		}
		free(sockFileSigned);
		Replay:;
	}

	closesocket(sock1);
	WSACleanup();
	NKvDbgPrintfW(L"\nExiting");
	return 0;
}
