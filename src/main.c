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
    if (strcmp(ip, "-") == 0) return; // ignore local

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
    EVT_HANDLE hResults = NULL;
    EVT_HANDLE hEvents[10];
    DWORD returned = 0;

    LPCWSTR query = L"*[System[(EventID=4625)]]";

    hResults = EvtQuery(NULL, L"Security", query, EvtQueryReverseDirection);
    if (!hResults) {
        printf("Failed to query events\n");
        return 1;
    }

    while (1) {
        if (!EvtNext(hResults, 10, hEvents, INFINITE, 0, &returned)) {
            Sleep(1000);
            continue;
        }

        for (DWORD i = 0; i < returned; i++) {
            DWORD bufferSize = 0;
            DWORD bufferUsed = 0;
            DWORD propCount = 0;

            EvtRender(NULL, hEvents[i], EvtRenderEventXml, 0, NULL, &bufferUsed, &propCount);

            wchar_t* buffer = (wchar_t*)malloc(bufferUsed);
            if (!buffer) continue;

            if (EvtRender(NULL, hEvents[i], EvtRenderEventXml, bufferUsed, buffer, &bufferUsed, &propCount)) {
                parse_event_xml(buffer);
            }

            free(buffer);
            EvtClose(hEvents[i]);
        }
    }

    EvtClose(hResults);
    return 0;
}