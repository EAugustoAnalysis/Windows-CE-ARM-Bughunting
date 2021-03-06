// DebugTest.cpp : Tests ability to catch exceptions in a program by debugging, integrated into our new fuzzer
// Written in Visual Studio 2006 using the Dot Net Framework for Windows CE
// Author: Elias Augusto

#include "stdafx.h"
#include "tchar.h"
#include "windows.h"
#include "stdlib.h"
#include "Winbase.h"
#include <iostream>
#include <exception>

//Debug timeout
#define DBG_TIMEOUT 5000 //Our debug timeout is 3 seconds

//Typedefs for coredll functions
typedef BOOL(WINAPI *SETKMODE)(BOOL);
typedef DWORD(WINAPI *SETPROCPERMISSIONS)(DWORD);
typedef int(WINAPI *NKVDBGPRINTFW)(LPCWSTR);
SETKMODE SetKMode;
SETPROCPERMISSIONS SetProcPermissions;
NKVDBGPRINTFW NKvDbgPrintfW;

//Fuzzer variable we'll use for testing
DWORD fuzzResultReturn;


//Relevant Crash
#define FUZZ_CRASH 0xDEAD0404

int _tmain(int argc, _TCHAR* argv[])
{
	fuzzResultReturn=0;
	//Load Coredll Functions
	HMODULE hModule =LoadLibrary(L"coredll.dll");
	
	SetKMode=(SETKMODE)GetProcAddress(hModule,L"SetKMode");
	SetProcPermissions=(SETPROCPERMISSIONS)GetProcAddress(hModule,L"SetProcPermissions");
	NKvDbgPrintfW=(NKVDBGPRINTFW)GetProcAddress(hModule,L"NKvDbgPrintfW");

	//Set thread to kernel mode
	DWORD oldPerm = SetProcPermissions(0xFFFFFFFF);
	BOOL Kmode = SetKMode(TRUE);
	
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	memset(&si,0,sizeof(si));
	memset(&pi,0,sizeof(pi));
	//DWORD cProcFlags = CREATE_NEW_CONSOLE;
	DWORD cProcFlags =DEBUG_PROCESS | CREATE_NEW_CONSOLE;
	
	wchar_t uBookArgs[]=L"\\Storage Card\\whatsnew.html";

	//Start process for we want to monitor
	CreateProcess(L"iexplore.exe",uBookArgs,NULL,NULL,FALSE,cProcFlags,NULL,NULL,&si,&pi);
	//DebugActiveProcess(pi.dwProcessId);

	DEBUG_EVENT debug_event;
	memset(&debug_event,0,sizeof(debug_event));
	while(true){
		if(!WaitForDebugEvent(&debug_event,DBG_TIMEOUT)){
			break;
		}
		//Note that we're doing some exploitability assesment ourselves because peach can't
		if(debug_event.dwDebugEventCode==EXCEPTION_DEBUG_EVENT){
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
			else if(debug_event.u.Exception.ExceptionRecord.ExceptionCode==EXCEPTION_GUARD_PAGE){
				goto ReturnCrash;
			}
			
			//Common DoS exception types
			else if(debug_event.u.Exception.ExceptionRecord.ExceptionCode==EXCEPTION_STACK_OVERFLOW){
				goto ReturnCrash;
			}
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
				break;
			}
			ReturnCrash:
				fuzzResultReturn=FUZZ_CRASH;
				break;
		}
		KeepDebugging:
			ContinueDebugEvent(debug_event.dwProcessId,debug_event.dwThreadId,DBG_CONTINUE);
	}
	HANDLE tmpHandle=OpenProcess(PROCESS_ALL_ACCESS,TRUE,pi.dwProcessId);
	if(tmpHandle!=NULL){
				TerminateProcess(tmpHandle,404);
	}


	//Restore to usermode
	SetKMode(FALSE);
	SetProcPermissions(oldPerm);
}

