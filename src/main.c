#include <windows.h>
#include <winevt.h>
#include <stdio.h>
#include <time.h>

#pragma comment(lib, "wevtapi.lib")

#define MAX_IP 100
#define THRESHOLD 5
#define TIME_WINDOW 30

typedef struct {
    char ip[64];
    int fail_count;
    time_t first_time;
} IPStats;

IPStats ip_list[MAX_IP];
int ip_count = 0;

// 🔥 DEBUG: in lỗi Windows
void print_error(const char* msg) {
    DWORD err = GetLastError();
    LPVOID buffer;

    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        err,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&buffer,
        0,
        NULL
    );

    printf("[ERROR] %s | Code: %lu | Message: %s\n", msg, err, (char*)buffer);
    LocalFree(buffer);
}

IPStats* get_ip(const char* ip) {
    for (int i = 0; i < ip_count; i++) {
        if (strcmp(ip_list[i].ip, ip) == 0)
            return &ip_list[i];
    }

    if (ip_count < MAX_IP) {
        strcpy(ip_list[ip_count].ip, ip);
        ip_list[ip_count].fail_count = 0;
        ip_list[ip_count].first_time = time(NULL);
        return &ip_list[ip_count++];
    }

    return NULL;
}

void process_ip(const char* ip) {
    if (strcmp(ip, "-") == 0) return;

    IPStats* stat = get_ip(ip);
    if (!stat) return;

    time_t now = time(NULL);

    if (difftime(now, stat->first_time) > TIME_WINDOW) {
        stat->fail_count = 0;
        stat->first_time = now;
    }

    stat->fail_count++;

    printf("[FAIL] IP: %s | Count: %d\n", ip, stat->fail_count);

    if (stat->fail_count >= THRESHOLD) {
        printf(">>> BRUTE DETECTED: %s <<<\n", ip);
    }
}

void parse_event_xml(const wchar_t* xml) {
    char buffer[4096];
    wcstombs(buffer, xml, sizeof(buffer));

    char* ip_pos = strstr(buffer, "Source Network Address");
    if (!ip_pos) return;

    char* value = strstr(ip_pos, "<Data>");
    if (!value) return;

    value += 6;
    char* end = strstr(value, "</Data>");
    if (!end) return;

    char ip[64] = {0};
    strncpy(ip, value, end - value);

    process_ip(ip);
}

int main() {
    printf("[DEBUG] Starting AegisRDP...\n");

    EVT_HANDLE hResults = NULL;
    EVT_HANDLE hEvents[10];
    DWORD returned = 0;

    LPCWSTR query = L"*[System[(EventID=4625)]]";

    hResults = EvtQuery(NULL, L"Security", query, EvtQueryReverseDirection);
    if (!hResults) {
        print_error("EvtQuery failed");
        return 1;
    }

    printf("[DEBUG] Query success, waiting for events...\n");

    while (1) {
        if (!EvtNext(hResults, 10, hEvents, INFINITE, 0, &returned)) {
            DWORD err = GetLastError();

            if (err != ERROR_NO_MORE_ITEMS) {
                print_error("EvtNext failed");
            }

            Sleep(1000);
            continue;
        }

        for (DWORD i = 0; i < returned; i++) {
            DWORD bufferUsed = 0;
            DWORD propCount = 0;

            if (!EvtRender(NULL, hEvents[i], EvtRenderEventXml, 0, NULL, &bufferUsed, &propCount)) {
                if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
                    print_error("EvtRender size query failed");
                    EvtClose(hEvents[i]);
                    continue;
                }
            }

            wchar_t* buffer = (wchar_t*)malloc(bufferUsed);
            if (!buffer) {
                printf("[ERROR] Memory allocation failed\n");
                EvtClose(hEvents[i]);
                continue;
            }

            if (!EvtRender(NULL, hEvents[i], EvtRenderEventXml, bufferUsed, buffer, &bufferUsed, &propCount)) {
                print_error("EvtRender failed");
                free(buffer);
                EvtClose(hEvents[i]);
                continue;
            }

            parse_event_xml(buffer);

            free(buffer);
            EvtClose(hEvents[i]);
        }
    }

    EvtClose(hResults);
    return 0;
}