#pragma once
#include <stdio.h>
#include <windows.h>
#include <dbghelp.h>
#include "nyx_api.h"

#pragma comment(lib, "dbghelp.lib")

char fuzz_path[256];
char callstack_buffer[65536];
char fuzz_buffer[65536];

int pos = 0;

static void panic(void) {
    kAFL_hypercall(HYPERCALL_KAFL_PANIC, (uintptr_t)0x1);
    while (1) {
        
    }; /* halt */
}

void throw_callstack() {    
    kafl_dump_file_t callstack_dump = {
      .file_name_str_ptr = "callstack",
      .data_ptr = callstack_buffer,
      .bytes = pos,
      .append = 0
    };
    hprintf("callstack dump hypercall\n");
    kAFL_hypercall(HYPERCALL_KAFL_DUMP_FILE, (uintptr_t)&callstack_dump);

    FILE *fp = fopen(fuzz_path, "rb");
    if(fp == NULL)
        habort("fopen failed..\n");
    fseek(fp, 0, SEEK_END);
    int size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    fread(fuzz_buffer, 1, size, fp);

    kafl_dump_file_t crash_dump = {
        .file_name_str_ptr = "crash",
        .data_ptr = fuzz_buffer,
        .bytes = size,
        .append = 0
    };
    hprintf("crash dump hypercall\n");
    kAFL_hypercall(HYPERCALL_KAFL_DUMP_FILE, (uintptr_t)&crash_dump);
}

BOOL InitializeSym()
{
    if (!SymInitialize(GetCurrentProcess(), NULL, TRUE))
    {
        printf("SymInitialize Failed..\n");
        return FALSE;
    }

    DWORD options = SymGetOptions();
    options |= SYMOPT_LOAD_LINES | SYMOPT_UNDNAME;
    SymSetOptions(options);

    return TRUE;
}

#ifdef __X64_HARNESS__
void PrintSymbolInfo(DWORD64 address)
{
    IMAGEHLP_MODULE64 moduleInfo = { 0 };
    moduleInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);

    if (!SymGetModuleInfo64(GetCurrentProcess(), address, &moduleInfo))
    {
#ifdef __CRASH_DEBUG__
        printf("SymGetModuleInfo64 Failed.. (0x%llx)\n", address);
#endif
        pos += sprintf(callstack_buffer + pos, "SymGetModuleInfo64 Failed.. (0x%llx)\n", address);
        return;
    }

    DWORD MAX_SYMBOL_NAME_LEN = 256;
    BYTE symbolBuffer[sizeof(SYMBOL_INFO) + MAX_SYMBOL_NAME_LEN];
    PSYMBOL_INFO symbol = (PSYMBOL_INFO)symbolBuffer;
    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbol->MaxNameLen = MAX_SYMBOL_NAME_LEN;

    if (!SymFromAddr(GetCurrentProcess(), address, NULL, symbol))
    {
#ifdef __CRASH_DEBUG__
        printf("[UC] SymFromAddr Failed.. (0x%llx)\n", address);
#endif
        pos += sprintf(callstack_buffer + pos, "SymFromAddr Failed.. (0x%llx)\n", address);
        return;
    }

#ifdef __CRASH_DEBUG__
    printf("[UC] %s!%s+0x%lx (0x%llx)\n", moduleInfo.ModuleName, symbol->Name, address - symbol->Address, address);
#endif
    pos += sprintf(callstack_buffer + pos, "%s!%s+0x%lx (0x%llx)\n", moduleInfo.ModuleName, symbol->Name, address - symbol->Address, address);
}
#endif

#ifdef __X86_HARNESS__
void PrintSymbolInfo(DWORD address)
{
    IMAGEHLP_MODULE moduleInfo = { 0 };
    moduleInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULE);

    if (!SymGetModuleInfo(GetCurrentProcess(), address, &moduleInfo))
    {
#ifdef __CRASH_DEBUG__
        printf("[UC] SymGetModuleInfo Failed.. (0x%lx)\n", address);
#endif
        pos += sprintf(callstack_buffer + pos, "SymGetModuleInfo Failed.. (0x%lx)\n", address);
        return;
    }

    DWORD MAX_SYMBOL_NAME_LEN = 256;
    BYTE symbolBuffer[sizeof(IMAGEHLP_SYMBOL) + 256];
    PIMAGEHLP_SYMBOL symbol = (PIMAGEHLP_SYMBOL)symbolBuffer;
    symbol->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL);
    symbol->MaxNameLength = MAX_SYMBOL_NAME_LEN;

    DWORD displacement = 0;
    if (!SymGetSymFromAddr(GetCurrentProcess(), address, &displacement, symbol))
    {
#ifdef __CRASH_DEBUG__
        printf("[UC] SymGetSymFromAddr Failed.. (0x%lx)\n", address);
#endif
        pos += sprintf(callstack_buffer + pos, "SymGetSymFromAddr Failed.. (0x%lx)\n", address);
        return;
    }

#ifdef __CRASH_DEBUG__
    printf("[UC] %s!%s+0x%lx (0x%lx)\n", moduleInfo.ModuleName, symbol->Name, address - symbol->Address, address);
#endif
    pos += sprintf(callstack_buffer + pos, "%s!%s+0x%lx (0x%lx)\n", moduleInfo.ModuleName, symbol->Name, address - symbol->Address, address);
}
#endif

void PrintCallStack(CONTEXT* context)
{
    BOOL res = 0;

#ifdef __X64_HARNESS__
    STACKFRAME64 stackFrame = { 0 };
    stackFrame.AddrPC.Offset = context->Rip;
    stackFrame.AddrPC.Mode = AddrModeFlat;
    stackFrame.AddrFrame.Offset = context->Rbp;
    stackFrame.AddrFrame.Mode = AddrModeFlat;
    stackFrame.AddrStack.Offset = context->Rsp;
    stackFrame.AddrStack.Mode = AddrModeFlat;
#endif

#ifdef __X86_HARNESS__
    STACKFRAME stackFrame = { 0 };
    stackFrame.AddrPC.Offset = context->Eip;
    stackFrame.AddrPC.Mode = AddrModeFlat;
    stackFrame.AddrFrame.Offset = context->Ebp;
    stackFrame.AddrFrame.Mode = AddrModeFlat;
    stackFrame.AddrStack.Offset = context->Esp;
    stackFrame.AddrStack.Mode = AddrModeFlat;
#endif

#ifdef __X64_HARNESS__
    for (int i = 0; i < 30; i++) {
        res = StackWalk64(IMAGE_FILE_MACHINE_AMD64, GetCurrentProcess(), GetCurrentThread(), &stackFrame, context, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL);
        if (!res)
            return;
        PrintSymbolInfo(stackFrame.AddrPC.Offset);
    }
#endif

#ifdef __X86_HARNESS__
    for (int i = 0; i < 30; i++) {
        res = StackWalk(IMAGE_FILE_MACHINE_I386, GetCurrentProcess(), GetCurrentThread(), &stackFrame, context, NULL, SymFunctionTableAccess, SymGetModuleBase, NULL);
        if (!res)
            return;
        PrintSymbolInfo(stackFrame.AddrPC.Offset);
    }
#endif
}

LONG MyExceptionHandler(PEXCEPTION_POINTERS pExceptionPtrs) {
    DWORD exception_code = pExceptionPtrs->ExceptionRecord->ExceptionCode;
    if ((exception_code == EXCEPTION_ACCESS_VIOLATION) ||
        (exception_code == EXCEPTION_ILLEGAL_INSTRUCTION) ||
        //(exception_code == STATUS_HEAP_CORRUPTION) ||
        (exception_code == 0xc0000374) ||
        (exception_code == 0xc00000fd) ||
        (exception_code == STATUS_STACK_BUFFER_OVERRUN) ||
        (exception_code == STATUS_FATAL_APP_EXIT))
    {
#ifdef __CRASH_DEBUG__
        printf("[UC] **************************************************\n");
        printf("[UC] *                                                *\n");
        printf("[UC] *              !! Crash Detected !!              *\n");
        printf("[UC] *                                                *\n");
        printf("[UC] **************************************************\n\n");

        printf("[UC] [#] Crash Code - %p\n", pExceptionPtrs->ExceptionRecord->ExceptionCode);
        printf("[UC] [#] The contents of the CALLSTACK are as follows..\n\n");
#endif
        pos += sprintf(callstack_buffer + pos, "**************************************************\n");
        pos += sprintf(callstack_buffer + pos, "*                                                *\n");
        pos += sprintf(callstack_buffer + pos, "*              !! Crash Detected !!              *\n");
        pos += sprintf(callstack_buffer + pos, "*                                                *\n");
        pos += sprintf(callstack_buffer + pos, "**************************************************\n\n");
        pos += sprintf(callstack_buffer + pos, "[#] Crash Code - %p\n", pExceptionPtrs->ExceptionRecord->ExceptionCode);
        pos += sprintf(callstack_buffer + pos, "[#] The contents of the CALLSTACK are as follows..\n\n");

#ifdef __X64_HARNESS__
        CONTEXT* pContext = pExceptionPtrs->ContextRecord;
#ifdef __CRASH_DEBUG__
        printf("[UC] ====================REGISTERS====================\n");
        printf("[UC] RIP: 0x%llx\n", pContext->Rip);
        printf("[UC] RAX: 0x%-20llx RBX: 0x%-20llx RCX: 0x%-20llx RDX: 0x%-20llx\n", pContext->Rax, pContext->Rbx, pContext->Rcx, pContext->Rdx);
        printf("[UC] R8:  0x%-20llx  R9: 0x%-20llx R10: 0x%-20llx R11: 0x%-20llx\n", pContext->R8, pContext->R9, pContext->R10, pContext->R11);
        printf("[UC] R12: 0x%-20llx R13: 0x%-20llx R14: 0x%-20llx R15: 0x%-20llx\n", pContext->R12, pContext->R13, pContext->R14, pContext->R15);
        printf("[UC] RSP: 0x%-20llx RBP: 0x%-20llx RSI: 0x%-20llx RDI: 0x%-20llx\n", pContext->Rsp, pContext->Rbp, pContext->Rsi, pContext->Rdi);
        printf("[UC] ====================CALLSTACK====================\n");
#endif
        pos += sprintf(callstack_buffer + pos, "====================REGISTERS====================\n");
        pos += sprintf(callstack_buffer + pos, "RIP: 0x%llx\n", pContext->Rip);
        pos += sprintf(callstack_buffer + pos, "RAX: 0x%-20llx RBX: 0x%-20llx RCX: 0x%-20llx RDX: 0x%-20llx\n", pContext->Rax, pContext->Rbx, pContext->Rcx, pContext->Rdx);
        pos += sprintf(callstack_buffer + pos, "R8:  0x%-20llx  R9: 0x%-20llx R10: 0x%-20llx R11: 0x%-20llx\n", pContext->R8, pContext->R9, pContext->R10, pContext->R11);
        pos += sprintf(callstack_buffer + pos, "R12: 0x%-20llx R13: 0x%-20llx R14: 0x%-20llx R15: 0x%-20llx\n", pContext->R12, pContext->R13, pContext->R14, pContext->R15);
        pos += sprintf(callstack_buffer + pos, "RSP: 0x%-20llx RBP: 0x%-20llx RSI: 0x%-20llx RDI: 0x%-20llx\n", pContext->Rsp, pContext->Rbp, pContext->Rsi, pContext->Rdi);
        pos += sprintf(callstack_buffer + pos, "====================CALLSTACK====================\n");
#endif

#ifdef __X86_HARNESS__
        CONTEXT* pContext = pExceptionPtrs->ContextRecord;
#ifdef __CRASH__DEBUG__
        printf("[UC] ====================REGISTERS====================\n");
        printf("[UC] EIP: 0x%lx\n", pContext->Eip);
        printf("[UC] EAX: 0x%-20lx EBX: 0x%-20lx ECX: 0x%-20lx EDX: 0x%-20lx\n", pContext->Eax, pContext->Ebx, pContext->Ecx, pContext->Edx);
        printf("[UC] ESI: 0x%-20lx EDI: 0x%-20lx EBP: 0x%-20lx ESP: 0x%-20lx\n", pContext->Esi, pContext->Edi, pContext->Ebp, pContext->Esp);
        printf("[UC] ====================CALLSTACK====================\n");
#endif
        pos += sprintf(callstack_buffer + pos, "====================REGISTERS====================\n");
        pos += sprintf(callstack_buffer + pos, "EIP: 0x%lx\n", pContext->Eip);
        pos += sprintf(callstack_buffer + pos, "EAX: 0x%-20lx EBX: 0x%-20lx ECX: 0x%-20lx EDX: 0x%-20lx\n", pContext->Eax, pContext->Ebx, pContext->Ecx, pContext->Edx);
        pos += sprintf(callstack_buffer + pos, "ESI: 0x%-20lx EDI: 0x%-20lx EBP: 0x%-20lx ESP: 0x%-20lx\n", pContext->Esi, pContext->Edi, pContext->Ebp, pContext->Esp);
        pos += sprintf(callstack_buffer + pos, "====================CALLSTACK====================\n");
#endif

        PrintCallStack(pContext);
        pos += sprintf(callstack_buffer + pos, "\n[#] Done.\n");

        //save_callstack();
        throw_callstack();
        
        panic();

        return EXCEPTION_EXECUTE_HANDLER;
    }
    else {
        return TRUE;
    }

}

void init_uc(char *f_path) {
    InitializeSym();
    memset(fuzz_path, 0, sizeof(fuzz_path));
    memset(fuzz_buffer, 0, sizeof(fuzz_buffer));
    memset(callstack_buffer, 0, sizeof(callstack_buffer));

    memcpy(fuzz_path, f_path, strlen(f_path));

    if (AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)MyExceptionHandler) == 0)
    {
        printf("WARNING: Cannot add veh handler %u\n", (UINT32)GetLastError());
    }
}