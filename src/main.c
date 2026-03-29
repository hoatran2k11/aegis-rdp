#include <windows.h>
#include <winevt.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "wevtapi.lib")

#define MAX_IP 100
#define MAX_FAILS 100
#define THRESHOLD 5
#define TIME_WINDOW 60

typedef struct {
    char ip[64];
    time_t fails[MAX_FAILS];
    int fail_count;
} IPStats;

IPStats ip_list[MAX_IP];
int ip_count = 0;

void print_error(const char *msg)
{
    DWORD err = GetLastError();
    LPVOID buffer;

    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&buffer, 0, NULL);

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
        return &ip_list[ip_count++];
    }
    return NULL;
}

void process_ip(const char *ip)
{
    if (!ip || strcmp(ip, "-") == 0 || strlen(ip) == 0)
        return;

    IPStats *stat = get_ip(ip);
    if (!stat)
        return;

    time_t now = time(NULL);

    if (stat->fail_count < MAX_FAILS)
        stat->fails[stat->fail_count++] = now;
    else
    {
        memmove(stat->fails, stat->fails + 1, sizeof(time_t) * (MAX_FAILS - 1));
        stat->fails[MAX_FAILS - 1] = now;
    }

    int valid_count = 0;
    for (int i = 0; i < stat->fail_count; i++)
    {
        if (difftime(now, stat->fails[i]) <= TIME_WINDOW)
            stat->fails[valid_count++] = stat->fails[i];
    }
    stat->fail_count = valid_count;

    printf("[FAIL] IP: %s | Count in window: %d\n", ip, stat->fail_count);

    if (stat->fail_count >= THRESHOLD)
        printf(">>> BRUTE DETECTED: %s <<<\n", ip);
}

DWORD render_event_xml(EVT_HANDLE hEvent, char **xml_buffer)
{
    DWORD bufferUsed = 0, propCount = 0;

    if (!EvtRender(NULL, hEvent, EvtRenderEventXml, 0, NULL, &bufferUsed, &propCount))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            return 1;
    }

    wchar_t *wbuffer = (wchar_t *)malloc(bufferUsed);
    if (!wbuffer)
        return 2;

    if (!EvtRender(NULL, hEvent, EvtRenderEventXml, bufferUsed, wbuffer, &bufferUsed, &propCount))
    {
        free(wbuffer);
        return 3;
    }

    *xml_buffer = (char *)malloc(bufferUsed * 2);
    if (!(*xml_buffer))
    {
        free(wbuffer);
        return 4;
    }

    wcstombs(*xml_buffer, wbuffer, bufferUsed * 2);
    free(wbuffer);
    return 0;
}

DWORD WINAPI EventCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID userContext, EVT_HANDLE hEvent)
{
    UNREFERENCED_PARAMETER(userContext);

    if (action == EvtSubscribeActionError)
    {
        DWORD status = (DWORD)(uintptr_t)hEvent;
        if (status == ERROR_EVT_QUERY_RESULT_STALE)
            printf("[ERROR] Subscription callback: Event records missing.\n");
        else
            printf("[ERROR] Subscription callback Win32 error: %lu\n", status);
        return status;
    }
    else if (action == EvtSubscribeActionDeliver)
    {
        char *xml = NULL;
        if (render_event_xml(hEvent, &xml) != 0)
            return 1;

        if (!strstr(xml, "Name=\"LogonType\">10"))
        {
            free(xml);
            return 0;
        }

        char *ip_pos = strstr(xml, "Name=\"IpAddress\"");
        if (!ip_pos)
        {
            free(xml);
            return 0;
        }

        char *value = strchr(ip_pos, '>');
        if (!value)
        {
            free(xml);
            return 0;
        }
        value += 1;

        char *end = strstr(value, "</Data>");
        if (!end)
        {
            free(xml);
            return 0;
        }

        char ip[64] = {0};
        strncpy(ip, value, end - value);
        ip[end - value] = '\0';

        process_ip(ip);
        free(xml);
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
    while (1)
        Sleep(1000);

    EvtClose(hSub);
    return 0;
}