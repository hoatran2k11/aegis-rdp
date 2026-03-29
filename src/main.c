#include <windows.h>
#include <winevt.h>
#include <stdio.h>
#include <time.h>

#pragma comment(lib, "wevtapi.lib")

#define MAX_IP 100
#define THRESHOLD 5
#define TIME_WINDOW 30

typedef struct
{
    char ip[64];
    int fail_count;
    time_t first_time;
} IPStats;

IPStats ip_list[MAX_IP];
int ip_count = 0;

// 🔥 DEBUG: in lỗi Windows
void print_error(const char *msg)
{
    DWORD err = GetLastError();
    LPVOID buffer;

    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        err,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&buffer,
        0,
        NULL);

    printf("[ERROR] %s | Code: %lu | Message: %s\n", msg, err, (char *)buffer);
    LocalFree(buffer);
}

IPStats *get_ip(const char *ip)
{
    for (int i = 0; i < ip_count; i++)
    {
        if (strcmp(ip_list[i].ip, ip) == 0)
            return &ip_list[i];
    }

    if (ip_count < MAX_IP)
    {
        strcpy(ip_list[ip_count].ip, ip);
        ip_list[ip_count].fail_count = 0;
        ip_list[ip_count].first_time = time(NULL);
        return &ip_list[ip_count++];
    }

    return NULL;
}

void process_ip(const char *ip)
{
    if (strcmp(ip, "-") == 0 || strlen(ip) == 0)
        return;

    IPStats *stat = get_ip(ip);
    if (!stat)
        return;

    time_t now = time(NULL);

    if (difftime(now, stat->first_time) > TIME_WINDOW)
    {
        stat->fail_count = 0;
        stat->first_time = now;
    }

    stat->fail_count++;
    printf("[FAIL] IP: %s | Count: %d\n", ip, stat->fail_count);

    if (stat->fail_count >= THRESHOLD)
    {
        printf(">>> BRUTE DETECTED: %s <<<\n", ip);
    }
}

// xử lý từng event callback
DWORD WINAPI EventCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID userContext, EVT_HANDLE hEvent)
{
    if (action == EvtSubscribeActionDeliver)
    {
        DWORD bufferUsed = 0, propCount = 0;
        if (!EvtRender(NULL, hEvent, EvtRenderEventXml, 0, NULL, &bufferUsed, &propCount))
        {
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
                return 0;
        }

        wchar_t *buffer = (wchar_t *)malloc(bufferUsed);
        if (!buffer)
            return 0;

        if (!EvtRender(NULL, hEvent, EvtRenderEventXml, bufferUsed, buffer, &bufferUsed, &propCount))
        {
            free(buffer);
            return 0;
        }

        // parse XML
        char xml_buffer[8192];
        wcstombs(xml_buffer, buffer, sizeof(xml_buffer));
        free(buffer);

        if (!strstr(xml_buffer, "Name=\"LogonType\">10"))
            return 0; // không phải RDP

        char *ip_pos = strstr(xml_buffer, "Name=\"IpAddress\"");
        if (!ip_pos)
            return 0;

        char *value = strstr(ip_pos, ">");
        if (!value)
            return 0;

        value += 1;
        char *end = strstr(value, "</Data>");
        if (!end)
            return 0;

        char ip[64] = {0};
        strncpy(ip, value, end - value);

        process_ip(ip);
    }
    return 0;
}

int main()
{
    printf("[DEBUG] Starting AegisRDP (live capture)...\n");

    LPCWSTR query = L"*[System[(EventID=4625)]]";

    EVT_HANDLE hSub = EvtSubscribe(
        NULL,
        NULL,
        L"Security",
        query,
        NULL,
        NULL,
        (EVT_SUBSCRIBE_CALLBACK)EventCallback,
        EvtSubscribeToFutureEvents
    );

    if (!hSub)
    {
        print_error("EvtSubscribe failed");
        return 1;
    }

    printf("[DEBUG] Listening for new RDP failure events...\n");

    // vòng lặp giữ chương trình chạy
    while (1)
        Sleep(1000);

    EvtClose(hSub);
    return 0;
}