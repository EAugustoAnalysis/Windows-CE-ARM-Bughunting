// WMPTest.cpp: Used to test a DOS bug found in Windows Media Player 10 for Pocket PC 2003
// Written in Visual Studio 2008 using the Dot Net Framework for Windows CE
// Author: Elias Augusto

#include "stdafx.h"
#include "tchar.h"
#include "windows.h"
#include "stdlib.h"
#include "winbase.h"
#include <iostream>
#include <exception>

typedef BOOL(WINAPI *SETKMODE)(BOOL);
typedef DWORD(WINAPI *SETPROCPERMISSIONS)(DWORD);
SETKMODE SetKMode;
SETPROCPERMISSIONS SetProcPermissions;


int _tmain(int argc, _TCHAR* argv[])
{
	//Load Coredll Functions
	HMODULE hModule =LoadLibrary(L"coredll.dll");
	
	SetKMode=(SETKMODE)GetProcAddress(hModule,L"SetKMode");
	SetProcPermissions=(SETPROCPERMISSIONS)GetProcAddress(hModule,L"SetProcPermissions");

	//Set thread to kernel mode - Not required but sometimes needed for debugging
	DWORD oldPerm = SetProcPermissions(0xFFFFFFFF);
	BOOL Kmode = SetKMode(TRUE);

	//For ease of process killing
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	wchar_t procFFArgs[]=L"Playlist \"\\Storage Card\\wmpcrashdemo3G.asx\"";
	memset(&si,0,sizeof(si));
	memset(&pi,0,sizeof(pi));
	DWORD cProcFlags = DEBUG_ONLY_THIS_PROCESS; //Let's debug

	//DWORD cProcFlags =NULL;
	DWORD exitCode=NULL;	
	CreateProcess(L"wmplayer.exe",procFFArgs,NULL,NULL,FALSE,cProcFlags,NULL,NULL,&si,&pi);

	DEBUG_EVENT debug_event;
	memset(&debug_event,0,sizeof(debug_event));
	
	while(true){
		if(!WaitForDebugEvent(&debug_event,5000)){
			break;
		}
		if(debug_event.dwDebugEventCode==OUTPUT_DEBUG_STRING_EVENT){
					DWORD len=debug_event.u.DebugString.nDebugStringLength+1;
					WCHAR *dbMG=new wchar_t[len];
					ReadProcessMemory(pi.hProcess,debug_event.u.DebugString.lpDebugStringData,dbMG,debug_event.u.DebugString.nDebugStringLength,NULL);
					NKDbgPrintfW(L"Debug message from process: ");
					NKDbgPrintfW(dbMG);
					NKDbgPrintfW(L"\n");
		}
		else if(debug_event.dwDebugEventCode==EXCEPTION_DEBUG_EVENT){
					NKDbgPrintfW(L"\nEXCEPTION DEFINITELY HAPPENED: %X\n",debug_event.u.Exception.ExceptionRecord.ExceptionCode);
					goto KeepDebuggingWithExcept;
		}
		KeepDebugging:
					ContinueDebugEvent(debug_event.dwProcessId,debug_event.dwThreadId,DBG_CONTINUE);
					continue;
		KeepDebuggingWithExcept:
			ContinueDebugEvent(debug_event.dwProcessId,debug_event.dwThreadId,DBG_EXCEPTION_NOT_HANDLED);
	}

	GetExitCodeProcess(pi.hProcess,&exitCode);
	NKDbgPrintfW(L"Exit Code: 0x%X\n",exitCode);

	//Set process permissions to normal
	SetKMode(FALSE);
	SetProcPermissions(oldPerm);
}

