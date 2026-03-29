#include <windows.h>
#include <winevt.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#pragma comment(lib, "wevtapi.lib")

#define BRUTE_THRESHOLD 5
#define TIME_WINDOW 60 

typedef struct {
    char ip[46];
    int count;
    time_t lastSeen;
} AttackTracker;

AttackTracker tracker[100];
int trackerCount = 0;

void ExecuteBlock(const char* ip) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "netsh advfirewall firewall add rule name=\"AegisRDP_Block_%s\" dir=in action=block remoteip=%s", ip, ip);
    if (system(cmd) == 0) {
        printf("[+] BLOCK APPLIED: %s\n", ip);
    }
}

void LogFailure(const char* ip) {
    time_t now = time(NULL);
    for (int i = 0; i < trackerCount; i++) {
        if (strcmp(tracker[i].ip, ip) == 0) {
            if (difftime(now, tracker[i].lastSeen) > TIME_WINDOW) tracker[i].count = 1;
            else tracker[i].count++;

            tracker[i].lastSeen = now;
            printf("[FAIL] IP: %s | Count: %d\n", ip, tracker[i].count);

            if (tracker[i].count >= BRUTE_THRESHOLD) {
                printf("\n>>> BRUTE DETECTED: %s <<<\n", ip);
                ExecuteBlock(ip);
                tracker[i].count = 0; // Reset after block
            }
            return;
        }
    }

    if (trackerCount < 100) {
        strcpy(tracker[trackerCount].ip, ip);
        tracker[trackerCount].count = 1;
        tracker[trackerCount].lastSeen = now;
        trackerCount++;
        printf("[FAIL] IP: %s | Count: 1\n", ip);
    }
}

DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent) {
    if (action == EvtSubscribeActionDeliver) {
        DWORD bufferUsed = 0, propertyCount = 0;
        EvtRender(NULL, hEvent, EvtRenderEventXml, 0, NULL, &bufferUsed, &propertyCount);
        
        LPWSTR xmlBuffer = (LPWSTR)malloc(bufferUsed);
        if (xmlBuffer && EvtRender(NULL, hEvent, EvtRenderEventXml, bufferUsed, xmlBuffer, &bufferUsed, &propertyCount)) {
            char* narrowXml = (char*)malloc(bufferUsed);
            wcstombs(narrowXml, xmlBuffer, bufferUsed);

            char* ipField = strstr(narrowXml, "IpAddress\">");
            if (ipField) {
                ipField += 11;
                char extractedIp[46] = {0};
                for (int i = 0; ipField[i] != '<' && i < 45; i++) extractedIp[i] = ipField[i];
                if (strlen(extractedIp) > 0 && strcmp(extractedIp, "-") != 0) LogFailure(extractedIp);
            }
            free(narrowXml);
        }
        if (xmlBuffer) free(xmlBuffer);
    }
    return 0;
}

int main() {
    EVT_HANDLE hSubscription = NULL;

    printf("========================================\n");
    printf("   AegisRDP v0.1.1-alpha\n");
    printf("   Author: Hoa Tran | 2026\n");
    printf("========================================\n");

    hSubscription = EvtSubscribe(NULL, NULL, L"Security", L"Event[System[(EventID=4625)]]", 
                                 NULL, NULL, (EVT_SUBSCRIBE_CALLBACK)SubscriptionCallback, 
                                 EvtSubscribeToFutureEvents);

    if (hSubscription == NULL) {
        printf("[-] Failed to subscribe to events. Error: %lu\n", GetLastError());
        return 1;
    }

    printf("[*] Real-time monitoring active. Press Ctrl+C to stop.\n");

    while (1) Sleep(1000); 

    EvtClose(hSubscription);
    return 0;
}