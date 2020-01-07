// KeyPressTest.cpp : Integrated into our new fuzzing project, tests the ability to click on a link repeatedly in a process that's being created and destroyed
// Written in Visual Studio 2006 using the Dot Net Framework for Windows CE
// Author: Elias Augusto

#include "stdafx.h"
#include "tchar.h"
#include "windows.h"
#include "stdlib.h"
#include "winuser.h"
#include <iostream>
#include <exception>


#define TOUT_IE 20000

#define TOUT_CLICK INFINITE

//Process variables;
DWORD pidCurr;
DWORD pidLast;
HWND wHandleCurr;

//Key variables
INPUT downKey;
INPUT enterKey;

//Debug message printer
typedef int(WINAPI *NKVDBGPRINTFW)(LPCWSTR);
NKVDBGPRINTFW NKvDbgPrintfW;

struct windHand{
	DWORD procID;
	HWND window;
};

BOOL CALLBACK checkWind(HWND window, LPARAM lP){
	windHand& chInfo=*(windHand*)lP;
	DWORD procID=NULL;
	GetWindowThreadProcessId(window,&procID);
	if(chInfo.procID!=procID || !IsWindowVisible(window)){
		return TRUE;
	}
	else{
		chInfo.window=window;
		return FALSE;
	}
}


HWND findIEWindow(DWORD procID){
	windHand wInfo;
	wInfo.procID=procID;
	wInfo.window=NULL;
	EnumWindows(checkWind,(LPARAM)&wInfo);
	return wInfo.window;

}

void initializeKeys(){
	//Initialize down arrow
	downKey.type=INPUT_KEYBOARD;
	downKey.ki.wVk=VK_DOWN;
	downKey.ki.wScan=NULL;
	downKey.ki.dwFlags=NULL;
	downKey.ki.time=NULL;
	downKey.ki.dwExtraInfo=NULL;
	
	//Initialize enter key
	enterKey.type=INPUT_KEYBOARD;
	enterKey.ki.wVk=VK_RETURN;
	enterKey.ki.wScan=NULL;
	enterKey.ki.dwFlags=NULL;
	enterKey.ki.time=NULL;
	enterKey.ki.dwExtraInfo=NULL;
}


DWORD WINAPI ieThread(LPVOID lpParam){
		STARTUPINFO si;
		PROCESS_INFORMATION pi;
		memset(&si,0,sizeof(si));
		memset(&pi,0,sizeof(pi));

		wchar_t ieArgs[]= L"\\Storage Card\\ppc.htm";

		//Start process for we want to monitor
		CreateProcess(L"iexplore.exe",ieArgs,NULL,NULL,FALSE,NULL,NULL,NULL,&si,&pi);

		//Print process ID for debugger
		wchar_t pidPrinter[50];
		wsprintf(pidPrinter,L"\n%d\n",pi.dwProcessId);
		NKvDbgPrintfW(pidPrinter);
		
		//Ensure that no two windows have the same process ID
		pidCurr=pi.dwProcessId;
		if(pidCurr!=pidLast){
			Sleep(5000);
		}
		//After execution of process for set period, record last process id
		pidLast=pi.dwProcessId;
		HANDLE closeHandle=OpenProcess(PROCESS_TERMINATE,FALSE,pi.dwProcessId);
		TerminateProcess(closeHandle,0);

		return 0;

}

//Clicks on last link on page in Internet Explorer Window
DWORD WINAPI clicThread(LPVOID lpParam){
	DWORD sameAsCurr;
	DWORD activePID;
	activePID=NULL;
	while(true){
		HWND ieWindow;
		_try{
			//Do not try to click on the same process twice
			if(pidCurr!=sameAsCurr){
				//Set the current active process identifier
				activePID=pidCurr;
				
				//Find the window associated with said process
				ieWindow=findIEWindow(activePID);
				SetForegroundWindow(ieWindow);
				//Click the down arrow 20 times and the enter key
				initializeKeys();
				for(int i=0; i<20; i++){
					SendInput(1,&downKey,sizeof(INPUT));
				}
				SendInput(1,&enterKey,sizeof(INPUT));
					
				//Set current PID to ensure it changes before next run
				sameAsCurr=activePID;
			}
		}
		_except(EXCEPTION_EXECUTE_HANDLER){
			break;
		}
	}
	return 0;
}

int _tmain(int argc, _TCHAR* argv[])
{	
	//Allow printing of debug messages
	HMODULE hModule =LoadLibrary(L"coredll.dll");
	
	NKvDbgPrintfW=(NKVDBGPRINTFW)GetProcAddress(hModule,L"NKvDbgPrintfW");

	DWORD retValue1;
	DWORD retValue2;
	
	//Initialize the last pid
	pidLast=NULL;

	HANDLE clThread= CreateThread(NULL,0,clicThread,0,0,&retValue1);
	while(true){
		HANDLE iThread = CreateThread(NULL,0,ieThread,0,0,&retValue2);
		WaitForSingleObject(iThread,TOUT_IE);
	}
	WaitForSingleObject(clThread, TOUT_CLICK);
	return(0);
}

