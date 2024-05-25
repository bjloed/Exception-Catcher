#define _CRT_SECURE_NO_WARNINGS
#define __X86_HARNESS__
#include <stdio.h>
#include <windows.h>
#include <dbghelp.h>
#include "UC.h"

#pragma comment(lib, "dbghelp.lib")

#define PAYLOAD_SIZE 128 * 1024
#define PE_CODE_SECTION_NAME ".text"

#define FUZZ_PATH "C:\\Users\\vagrant\\fuzz.bmp"

typedef int(WINAPI* ImportGR)(int, unsigned char*, DWORD*, int);

void submit_ip_ranges(HMODULE t1, HMODULE t2) {
    HMODULE pts[2] = { t1, t2 };

    hprintf("Target: %p, %p\n", pts[0], pts[1]);

    for (int i = 0; i < 2; i++) {
        IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)pts[i];
        IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)pts[i] + dosHeader->e_lfanew);
        DWORD dllSize = ntHeaders->OptionalHeader.SizeOfImage;

        hprintf("NT header: %p, dllSize: %p\n", ntHeaders, dllSize);

        uint64_t buffer[3] = { 0 };
        buffer[0] = (uint32_t)pts[i];
        buffer[1] = (uint32_t)pts[i] + dllSize;
        buffer[2] = i;
        kAFL_hypercall(HYPERCALL_KAFL_RANGE_SUBMIT, (uint64_t)buffer);

        hprintf("Lock Range: %p-%p\n", buffer[0], buffer[0] + dllSize);

        if (!VirtualLock(buffer[0], dllSize)) {
            hprintf("Error: %d\n", GetLastError());
            habort("Failed to lock .text section in resident memory\n");
        }
    }
}

kAFL_payload* kafl_agent_init(void) {
    // initial fuzzer handshake
    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);

    // submit mode
    kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);

    // get host config
    host_config_t host_config = { 0 };
    kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);
    hprintf("[host_config] bitmap sizes = <0x%x,0x%x>\n", host_config.bitmap_size, host_config.ijon_bitmap_size);
    hprintf("[host_config] payload size = %dKB\n", host_config.payload_buffer_size / 1024);
    hprintf("[host_config] worker id = %02u\n", host_config.worker_id);

    // allocate buffer
    hprintf("[+] Allocating buffer for kAFL_payload struct\n");
    kAFL_payload* payload_buffer = (kAFL_payload*)VirtualAlloc(0, host_config.payload_buffer_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    // ensure really present in resident pages
    if (!VirtualLock(payload_buffer, host_config.payload_buffer_size)) {
        habort("[+] WARNING: Virtuallock failed to lock payload buffer\n");
    }

    // submit buffer
    hprintf("[+] Submitting buffer address to hypervisor...\n");
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (UINT64)payload_buffer);

    // filters
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);

    // submit agent config
    agent_config_t agent_config = {
        .agent_magic = NYX_AGENT_MAGIC,
        .agent_version = NYX_AGENT_VERSION,
    };
    kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_config);

    return payload_buffer;
}


int main(int argc, char** argv) {
    hprintf("[+] Starting... %s\n", argv[0]);

    hprintf("[+] Creating snapshot...\n");
    kAFL_hypercall(HYPERCALL_KAFL_LOCK, 0);

    kAFL_payload* payload_buffer = kafl_agent_init();

    kAFL_ranges* range_buffer = (kAFL_ranges*)VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    memset(range_buffer, 0xff, 0x1000);

    hprintf("[+] range buffer %lx...\n", (UINT64)range_buffer);
    kAFL_hypercall(HYPERCALL_KAFL_USER_RANGE_ADVISE, (UINT64)range_buffer);

    if (!SetProcessWorkingSetSize((HANDLE)-1, 1 << 25 , 1 << 31))
    {
        hprintf("[-] Err increasing min and max working sizes: %u\n", (UINT32)GetLastError());
    }

    init_uc(FUZZ_PATH); //set init_uc(FUZZ_PATH)

    submit_ip_ranges(0, 0);

    kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
    /* FUZZ */
    FILE* fp = fopen(FUZZ_PATH, "rb+");
    fwrite((unsigned char *)payload_buffer->data, 1, (DWORD)payload_buffer->size, fp);
    fclose(fp);

    /*
        FUZZ FUNCITON ex) FUZZ(payload_buffer->data, payload_buffer->size);
    */

    /* FUZZ */
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    return 0;
}