#include <windows.h>
#include <stdio.h>
#include "detours.h"
#include "mediana.h"

#define MAKE_PTR(Type, Base, Offset) ((Type)((DWORD)Base + (DWORD)(Offset)))

#pragma pack(push)
#pragma pack(1)
typedef struct {
	char opcode;
	ULONG_PTR offset;
} t_jmp;
#pragma pack(pop)

typedef BOOL (__stdcall *pfnLdrpCallInitRoutine)(LPVOID EntryPoint, LPVOID BaseAddress, ULONG Reason, LPVOID Context);
typedef BOOL (__fastcall *pfnBaseThreadInitThunk)(DWORD a1, LPVOID lpStartAddr, DWORD a3, DWORD a4);

static UCHAR LdrpCallInitRoutine_bytes[] = {
	0x55,                    //PUSH EBP                                 ; ntdll._LdrpCallInitRoutine@16(guessed Arg1,Arg2,Arg3,Arg4)
	0x8B, 0xEC,              //MOV EBP,ESP
	0x56,                    //PUSH ESI
	0x57,                    //PUSH EDI
	0x53,                    //PUSH EBX
	0x8B, 0xF4,              //MOV ESI,ESP
	0x33, 0xC0,              //XOR EAX, EAX    on Windows 10
	0xFF, 0x75, 0x14,        //PUSH DWORD PTR SS:[ARG.4]
	0xFF, 0x75, 0x10,        //PUSH DWORD PTR SS:[ARG.3]
	0xFF, 0x75, 0x0C,        //PUSH DWORD PTR SS:[ARG.2]
	0xFF, 0x55, 0x08,        //CALL DWORD PTR SS:[ARG.1]
	0x8B, 0xE6,              //MOV ESP,ESI
	0x5B,                    //POP EBX
	0x5F,                    //POP EDI
	0x5E,                    //POP ESI
	0x5D,                    //POP EBP
	0xC2,  0x10, 0x00,       //RETN 10
};

pfnLdrpCallInitRoutine lpLdrpCallInitRoutine = NULL;
pfnLdrpCallInitRoutine lpOrigLdrpCallInitRoutine = NULL;

pfnBaseThreadInitThunk lpOrigBaseThreadInitThunk = NULL;

static char *dll_status[] = {
	"DLL_PROCESS_DETACH",
	"DLL_PROCESS_ATTACH",
	"DLL_THREAD_ATTACH ",
	"DLL_THREAD_DETACH ",
};

BOOL __stdcall h_LdrpCallInitRoutine(LPVOID EntryPoint, LPVOID BaseAddress, ULONG Reason, LPVOID Context)
{
	CHAR name[MAX_PATH] = {0};
	GetModuleFileNameA(BaseAddress, name, sizeof(name));
	printf("%s %s\n Base: %p, EntryPoint: %p \n", dll_status[Reason], name, BaseAddress, EntryPoint);
	return lpOrigLdrpCallInitRoutine(EntryPoint, BaseAddress, Reason, Context);
}

BOOL __fastcall h_BaseThreadInitThunk(DWORD a1, LPVOID lpStartAddr, DWORD a3, DWORD a4)
{
	printf("New thread: %p\n", lpStartAddr);
	return lpOrigBaseThreadInitThunk(a1, lpStartAddr, a3, a4);
}

void SetHook(LPVOID lpApiFn, LPVOID lpHook, LPVOID *lpStub)
{
	if ((lpApiFn == NULL) || (lpHook == NULL) || (lpStub == NULL))
		return;
	t_jmp jmp  = { 0 };
	jmp.opcode = (CHAR)0xE9;
	jmp.offset = (ULONG_PTR)lpHook - (ULONG_PTR)lpApiFn - 5;

	struct INSTRUCTION instr;
	struct DISASM_INOUT_PARAMS params;
	uint8_t sf_prefixes[MAX_INSTRUCTION_LEN];

	params.arch        = ARCH_ALL;
	params.sf_prefixes = sf_prefixes;
	params.mode        = DISASSEMBLE_MODE_32;
	params.options     = DISASM_OPTION_APPLY_REL | DISASM_OPTION_OPTIMIZE_DISP;
	params.base        = (uint64_t)lpApiFn;

	unsigned int res;
	SIZE_T nStubLen = 0;
	uint8_t *lpCurPtr = (uint8_t *)lpApiFn;
	while (nStubLen < sizeof(t_jmp))
	{
		res          = medi_disassemble(lpCurPtr, &instr, &params);
		lpCurPtr    += res;
		params.base += res;
		nStubLen    += res;
	}

	LPVOID lpWrap = (LPVOID)malloc(nStubLen + sizeof(t_jmp));
	if (lpWrap == NULL)
		return;

	memcpy(lpWrap, lpApiFn, nStubLen);

	t_jmp jmpret  = { 0 };
	jmpret.opcode = (CHAR)0xE9;
	jmpret.offset = (ULONG_PTR)lpApiFn + nStubLen - (ULONG_PTR)lpWrap - nStubLen - 5;

	memcpy((LPVOID) ((ULONG_PTR)lpWrap + nStubLen), &jmpret, sizeof(t_jmp));

	DWORD dwOldProt = 0;
	VirtualProtect(lpWrap, nStubLen + sizeof(t_jmp), PAGE_EXECUTE_READWRITE, &dwOldProt);

	VirtualProtect(lpApiFn, sizeof(t_jmp), PAGE_EXECUTE_READWRITE, &dwOldProt);
	memcpy(lpApiFn, &jmp, sizeof(jmp));
	VirtualProtect(lpApiFn, sizeof(t_jmp), dwOldProt, &dwOldProt);
	*lpStub = lpWrap;

	FlushInstructionCache(GetCurrentProcess(), lpApiFn, sizeof(jmp));
	return;
}

LPVOID Find_Memory(LPVOID lpData, SIZE_T nDataSize, LPVOID lpSrch, SIZE_T nSrchSize)
{
	CHAR *pos = (CHAR *)lpData;
	CHAR *limit = (CHAR *)((DWORD)lpData + nDataSize - nSrchSize);
	while (pos != limit) {
		if (!memcmp(pos, lpSrch, nSrchSize))
			return pos;
		pos++;
	}
	return NULL;
}

LPVOID Find_Call_LdrpCallInitRoutine(void)
{
	LPVOID hNtdll = GetModuleHandle("ntdll");
	printf("ntdll: %p\n", hNtdll);
	PIMAGE_DOS_HEADER lpDosHeader = (PIMAGE_DOS_HEADER)hNtdll;
	if (lpDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	PIMAGE_NT_HEADERS lpNtHeaders = MAKE_PTR(PIMAGE_NT_HEADERS, hNtdll, lpDosHeader->e_lfanew);
	if (lpNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	PIMAGE_SECTION_HEADER lpSections = MAKE_PTR(PIMAGE_SECTION_HEADER, &lpNtHeaders->OptionalHeader, lpNtHeaders->FileHeader.SizeOfOptionalHeader);
	LPVOID lpSectionStart = MAKE_PTR(LPVOID, hNtdll, lpSections[0].VirtualAddress);
	SIZE_T nSectionSize   = lpSections[0].SizeOfRawData;

	printf("section: %p %x\n", lpSectionStart, nSectionSize);

	LPVOID lpCallPtr = Find_Memory(lpSectionStart, nSectionSize, LdrpCallInitRoutine_bytes, sizeof(LdrpCallInitRoutine_bytes));
	if (!lpCallPtr)
		return NULL;
	return lpCallPtr;
}

int main(int argc, char **argv)
{
	lpLdrpCallInitRoutine = Find_Call_LdrpCallInitRoutine();
	printf("LdrpCallInitRoutine: %p\n", lpLdrpCallInitRoutine);
	if (!lpLdrpCallInitRoutine)
		return EXIT_FAILURE;

	SetHook(lpLdrpCallInitRoutine, h_LdrpCallInitRoutine, (LPVOID *)&lpOrigLdrpCallInitRoutine);
	SetHook(GetProcAddress(GetModuleHandle("kernel32"), "BaseThreadInitThunk"), h_BaseThreadInitThunk, (LPVOID *)&lpOrigBaseThreadInitThunk);
	

	puts("LoadLibrary(ws2_32.dll) ->]");
	printf("%p\n", LoadLibrary("ws2_32.dll"));
	puts("LoadLibrary(ws2_32.dll) [->");

	HANDLE hThread = CreateThread(0, 0, Sleep, NULL, 0, NULL);
	Sleep(1000);
	WaitForDebugEvent(hThread, INFINITE);
	CloseHandle(hThread);

	return EXIT_SUCCESS;
}
