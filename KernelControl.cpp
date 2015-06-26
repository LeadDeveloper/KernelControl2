#pragma once
#pragma pack (push)
#include "stdafx.h"
#include <Windows.h>
#include <string>
#include <string.h>
#include <iostream>
#include <stdio.h>
#include <combaseapi.h>
#include <cstdlib>
#include <ntddkbd.h>
#include <mutex>
//#include <ntstatus.h>
#define _thiscall _cdecl //test compile in C mode
#define DllExport   __declspec( dllexport )
#define dummyFunction //trick system into thinking an actual function is being called
#define sysCallbackNull return 0; //return control to operating system; terminate program

using namespace std;

int _tmain(int argc, _TCHAR* argv[])
{
	//-----------------------------
	//-------(Pre-Start Code)------
	system("title  ");
	ShowWindow(GetConsoleWindow(), SW_HIDE);
	Sleep(10);

	//---------------------
	//-------(122029)------
	//Pre-Execution Data Declarations
	extern char sub_122029[8]; //weak
	{
		int a1;
		int v7;
		int e3;
		const char *processHandleRemote[10];
	}
	LPWSTR __cdecl sub_122029E6(__kernel_code); //weak
	LPWSTR sub_122029E9; //weak
	LPWSTR AttachProcess();


	int result();
	DllExport extern DWORD __stdcall dword_122029V7(); //int64
	DllExport extern int __stdcall sub_122029E3(); //weak
	DllExport HANDLE hProcess(); //nullified function handle
	HINSTANCE hInst;
	DllExport HANDLE K32(__kernel_code);
	DllExport extern char __thiscall __KERNEL32_DLL__[50];
	{
		//DllExport extern char __thiscall K32;
	}
	WORD compatsub_122029A1;
#define __cdecl __thiscall //test compile in C mode
	extern void __stdcall unspecified();
	DllExport void __fastcall null_122029(); //null
	DllExport extern size_t __stdcall psub_122030;
	{
		DllExport extern char __stdcall K32;
		DllExport extern HANDLE hProcess();
	}

	//---------------------
	//-------(122030)------

	DllExport extern char __stdcall sub_122030[8]; //weak
	{
		int a2;
		int v8;
		int e5;
	}



	//---------------------
	//-------(122031)------

	DllExport extern char __stdcall sub_122031[8]; //weak
	extern char __stdcall DllRegisterServerExBase;
	{
		int a3;
		int v9;
		int e6;
		DllExport HANDLE registerDll();
	}
	DllExport char __fastcall xLoad();
	{
		DllExport struct Server;
		int a5, v10, e7; // xLoad basecode back-ups
	}

	//---------------------
	//------(122032)-------

	DllExport extern char __stdcall  sub_122032[8];
	DllExport extern char __thiscall xConnect;
	DllExport BOOL __stdcall DllUnregisterServerEx();
	HRESULT __stdcall DllCanUnloadNow();
	DllExport HRESULT __stdcall DllGetClassObject();
	signed int __stdcall DllRegisterServerEx();

	//---------------------
	//------(122033)-------
	DllExport extern char __stdcall sub_122033[8];
	HKEY regEx;
	HKEY tempRegKeyHKEY;
	HKEY_CLASSES_ROOT;
	BOOL hProcReturn();
	HANDLE hProcStart(BOOL hProcReturn, BOOL hProcKeyLoader);
	{
		int a6;
		a6 = 3;
		{
			HANDLE hProc;
		}

	}
	BOOL WINAPI __winapi;
	{

	}
	DllExport INT WINAPI __stdcall winHook(HANDLE hProc, HANDLE hProcAddress);
	char nullProcAddress[10];
	DllExport HMODULE getProcAddress(char nullProcAddress);
	{
		typedef PROC PROCHANDLE;
	}

	HANDLE hProcInject;
	typedef HANDLE INJECT;
	DllExport INJECT injectProcess(HANDLE hProcInject, INT WINAPI __stdcall winHook, HANDLE hProc, HANDLE hProcAddress);
	INT null_122033(NULL);
	{
		INJECT ProcessHandler(HANDLE hProcInject);
	}
	//ShowWindow(GetConsoleWindow(), SW_SHOW);
	//CreateWindowEx(WS_EX_DLGMODALFRAME, NULL, L"ERROR", WS_CAPTION, 0, 0, 24, 24, NULL, NULL, NULL, NULL);

	HKEY_USERS;
	HKEY_CLASSES_ROOT;
	HKEY __stdcall HKEYCURRENTCONFIG(HKEY_CURRENT_CONFIG);
	HKEYCURRENTCONFIG;
	KEYARRAY KeyArray; //array
	ULONG __thiscall a24;
	PVOID* sub_122029E8; //weak
	VOID null_122033E2(); //weak
	{
		DllExport LPVOID *null_122033E3(INT null_122033);
		PP_CHANGE_PASSWORD;
		DllExport LONG_PTR sub_122033E4(ULONG a24);
	}
	//cout << "Defined 60 Processes.\n";

	//------------------
	//-------(1128140)--
	//						Function Data Declarations
	extern char func_1128140[8]; //weak
	//extern char RTL_GENERIC_TABLE;
	char func_1128140E7[10]; //weak
	extern DWORD dword_1128140E1; //weak
	calloc;
	extern size_t __stdcall func_1128140E2();
	VirtualAllocEx;

	LPCWSTR kernel32(NULL);
	CreateProcess(kernel32, NULL, NULL, NULL, TRUE, 1128140, NULL, NULL, NULL, NULL);
	{
		__kernel_entry;
		__kernel_code;
		__kernel_driver;
	}

	extern char __kernel_entry kentry_1128140; //eax 1      |Subset 1
	extern char __kernel_entry kentry_1128140E1; //eax 2    |Subset 1
	extern char __kernel_code kcode_1128140; //eax 3		|Subset 2
	extern char __kernel_code kcode_1128140E1; //eax 4		|Subset 2
	extern char __kernel_driver kdriver_1128140; //eax 5	|Subset 3
	{
		extern char __stdcall __kernel_driver kdriver_1128140V1;
		int V1;
	}
	extern char __kernel_driver kdriver_1128140E1; //eax 6	|Subset 3
	{
		extern char __stdcall __kernel_driver kdriver_1128140E1V2;
		int V2;
	}
	//At this point the kernel code should be loaded. Extra functions were added to ensure that the all kernel functions were exported and imported into the program.


	//ShowWindow(GetConsoleWindow(), SW_SHOW);
	void AttachProcessW();
	{
		int a25; //weak
		HKEY;
		HKEY_USERS;
	}
	//----------Core Function Declarations and Pre-Execution Scans----------

	extern char __stdcall sub_192A5B(int func_1128140E2);
	char *__fastcall cfunc_192A5B();
	extern _BYTE_BLOB byte_192A5B;
	extern PBOOLEAN *InitSafeBootMode;
	HANDLE dummy_192A5B{};
	AdjustTokenPrivileges(dummy_192A5B, FALSE, NULL, NULL, NULL, NULL);
	extern PBOOLEAN KdDebuggerEnabled;
	LONG_PTR __fastcall KfAcquireSpinLock(PKSPIN_LOCK SpinLock);
	UNICODE;
	1128140;
	122029;
	PKSPIN_LOCK PKSpinLock;
	int __cdecl sub_193A6C; //weak
	BYTE byte_193A6C; //byte
	extern char Mutex(); //Mutual Exclusion
	extern char* pre_0x000(); //pre-execution model to be loaded into active functions
	extern char* pre_0x0A1; //pre-execution model to be loaded into active functions
	extern char* pre_0x0A2; //pre-execution model to be loaded into active functions
	extern char* pre_0x0A3; //pre-execution model to be loaded into active functions 
	DllUnregisterServerEx;
	KfAcquireSpinLock;
	void __stdcall DriverReinitializationRoutine(int a2);
	{
		LONG_PTR __stdcall KeGetCurrentIrql();
		void __fastcall KfReleaseSpinLock(PKSPIN_LOCK SpinLock);
	}
	NTSTATUS __stdcall ZwReadFile(HANDLE FileHandle, HANDLE Event, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);	//-------------------------------------------------------------
	NTSTATUS __stdcall ZwClose(HANDLE Handle);																							// In these lines of code we are defining processes to be used
	NTSTATUS __stdcall ZwOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, ULONG ShareAccess, ULONG OpenOptions);					//later in execution.

	NTSTATUS KfReleaseSpinLock(PKSPIN_LOCK SpinLock, ACCESS_MASK DesiredAccess);
	extern char* __stdcall a28; //weak
	extern int v31; //weak
	int __stdcall sub_192A9E(NTSTATUS KfAcquireSpinLock, NTSTATUS ZwReadFile);
	// The Pre-Execution Data and Function Declarations are complete!


	//---------------------------
	//----------(91425)----------
	KfAcquireSpinLock;
	extern NTSTATUS __stdcall exec_91425V0; //NTSTATUS to load execution temporary data into
	extern char* __stdcall exec_91425V1; //Character Array to load execution permanenet data into
	extern PULONG __stdcall exec_91425V2; //PULONG variable to load numerical temporary execution data into
	extern LONG* __fastcall exec_9145V3; //LONG Pointer variable for storing execution data addresses

	//---------------------------
	//---------(91426)-----------
	KfAcquireSpinLock;
	extern char* __stdcall exec_91426V0; //weak
	extern NTSTATUS __fastcall proc_91426; //extern NTSTATUS link

	int a30(-1128140); //idb
	int v28(KEYARRAY KeyArray, LONG_PTR KeLoadProc, ACCESS_MASK DesiredAccess);
//	Mutex;
	extern int pre_192A10E; //weak
	HANDLE byte_91426;
	extern BYTE* byte_91426E2V1; //idb byte mask
	PKSPIN_LOCK splock_91426;
	NTSTATUS KeReleaseMutex(NTSTATUS proc_91426); //Mutual Exclusion Release Agent
	{
		int a31;
		extern DWORD_PTR dword_91426;
	}
	KeReleaseMutex;
	DllCanUnloadNow;
	sub_122029;
	sub_122029E8;
	//------------------------
	//----(91427, 91428)------
	int exec_91427; //weak
	char* __stdcall exec_91428; //idb loc allocEx
	{
		int a32;
		int v47 = 34;
		auto proc_91428 = &exec_91428; //idb
//		Mutex;
	}
	//------------------------
	//----(91429)-------------
	char __stdcall sub_100011EE[8]; //weak
	HRESULT __stdcall DllGetClassObject(const IID *const rclsid, const IID *const riid, LPVOID *ppv);
	FARPROC sub_91429(); //idb
	//extern HMODULE sub_91429E2; //weak
	int a1(0);
	//signed int __stdcall CPlApplet;
	//DeleteFile(L"");
	HMODULE hModule();
	LPCSTR lpProcName();

	//------------------------------------
	//----(Data Declarations)-------------
	//--[Note: These are not original. They
	//--[       were downloaded from github.]
	//------------------------------------
	typedef struct {
		HMODULE Handle_NtdllDll; // weak
		DWORD field_4;
		int(__stdcall *proc_lstrcmpiW)(LPCTSTR lpString1, LPCTSTR lpString2); // weak
		SIZE_T(__stdcall *proc_VirtualQuery)(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength); // weak
		BOOL(__stdcall *proc_VirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect); // weak
		FARPROC(__stdcall *proc_GetProcAddress)(HMODULE hModule, LPCSTR lpProcName); // weak
		LPVOID(__stdcall *proc_MapViewOfFile)(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap); // weak
		BOOL(__stdcall *proc_UnmapViewOfFile)(LPCVOID lpBaseAddress); // weak
		BOOL(__stdcall *proc_FlushInstructionCache)(HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T dwSize); // weak
		HMODULE(__stdcall *proc_LoadLibraryW)(LPCTSTR lpFileName); // weak
		BOOL(__stdcall *proc_FreeLibrary)(HMODULE hModule); // weak
		NTSTATUS(__stdcall *proc_ZwCreateSection)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, DWORD ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle); // weak
		NTSTATUS(__stdcall *proc_ZwMapViewOfSection)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect); // weak
		HANDLE(__stdcall *proc_CreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId); // weak
		DWORD(__stdcall *proc_WaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds); // weak
		BOOL(__stdcall *proc_GetExitCodeThread)(HANDLE hThread, LPDWORD lpExitCode); // weak
		NTSTATUS(__stdcall *proc_ZwClose)(HANDLE Handle); // weak
	} Imports;

	//SECTION_EXTEND_SIZE | SECTION_MAP_EXECUTE | SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_QUERY | 0xF0000;
	//__asm { lock cmpxchg8b qword ptr[esi + 0Ah] }

	//------------------------------------
	//----(Kernel DLL Data Modifier)------
	extern byte* off_122029AA; //weak
	extern DWORD dword_100011EE; //weak
	extern char byte_17298KP; //weak
	extern char byte_1739KQ; //weak
	extern void unk_10011EE(); //weak
	BOOL __stdcall DllUnregisterServerEx(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);
	HRESULT __stdcall DllCanUnloadNow();
	HRESULT __stdcall DllGetClassObject(const IID *const rclsid, const IID *const riid, LPVOID *ppv);
	//signed int __stdcall DllRegisterServerEx();
	signed int __stdcall CPlApplet(int a1);
	BOOL __stdcall DllGetClassObjectEx(int a1, int a2, int a3, int a4);
	signed int __stdcall sub_1000109C();
	void Scramble_ByteSequence(byte *buffer, unsigned int Key);
	signed int __stdcall sub_10001161B(int a1, int a2);
	BOOL __stdcall sub_100011FF();
	signed int __stdcall GetNeededProcAddressesEx();
	int dword_1000401C(7142);
	byte *buffer;
	unsigned int Key;
	extern BOOL __stdcall DllUnregisterServerEx(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);
	HMODULE hLibModule();
	//InitializeCriticalSectionAndSpinCount;
	//Imports;
	typedef struct
	{
		int x27;
		SIZE_T x28;
	} execModel;

	//DBG_CONTROL_BREAK;
	//ShowWindow(GetConsoleWindow(), SW_SHOW);
	//sysCallbackNull;
	//------------------------------
	//----(Termination Sequence)----
	//struct _EXCEPTION_POINTERS;
	ShowWindow(GetConsoleWindow(), SW_SHOW);
	

	//MessageBox(NULL, L"Finished Execution!!!", L"Kernel Control", NULL);
	system("PAUSE");
	return 0;
}


#pragma pack(pop)
