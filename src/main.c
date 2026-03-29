#include <windows.h>
#include <winevt.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#pragma comment(lib, "wevtapi.lib")

#define THRESHOLD 5
#define TIME_WINDOW 60
#define MAX_IP 100
#define MAX_FAILS 100

typedef struct {
    char ip[46];
    time_t timestamps[MAX_FAILS];
    int numTimestamps;
} IPTracker;

IPTracker trackers[MAX_IP];
int numTrackers = 0;

void LogFailure(const char* ip) {
    time_t now = time(NULL);
    int found = -1;
    for (int i = 0; i < numTrackers; i++) {
        if (strcmp(trackers[i].ip, ip) == 0) {
            found = i;
            break;
        }
    }
    if (found == -1) {
        if (numTrackers < MAX_IP) {
            strcpy(trackers[numTrackers].ip, ip);
            trackers[numTrackers].numTimestamps = 0;
            found = numTrackers++;
        } else {
            // Max IPs reached, ignore new IP
            return;
        }
    }
    IPTracker *t = &trackers[found];
    // Remove outdated timestamps
    int j = 0;
    for (int i = 0; i < t->numTimestamps; i++) {
        if (difftime(now, t->timestamps[i]) <= TIME_WINDOW) {
            t->timestamps[j++] = t->timestamps[i];
        }
    }
    t->numTimestamps = j;
    // Add new timestamp
    if (t->numTimestamps < MAX_FAILS) {
        t->timestamps[t->numTimestamps++] = now;
    } else {
        // Shift and add (replace oldest)
        for (int i = 1; i < MAX_FAILS; i++) {
            t->timestamps[i - 1] = t->timestamps[i];
        }
        t->timestamps[MAX_FAILS - 1] = now;
    }
    printf("[FAIL] IP: %s | Count: %d\n", ip, t->numTimestamps);
    if (t->numTimestamps >= THRESHOLD) {
        printf(">>> BRUTE DETECTED: %s <<<\n", ip);
    }
}

DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent) {
    if (action == EvtSubscribeActionDeliver) {
        DWORD bufferUsed = 0, propertyCount = 0;
        if (!EvtRender(NULL, hEvent, EvtRenderEventXml, 0, NULL, &bufferUsed, &propertyCount)) {
            // Error in EvtRender, skip
            return 0;
        }
        LPWSTR xmlBuffer = (LPWSTR)malloc(bufferUsed * sizeof(WCHAR));
        if (!xmlBuffer) {
            // Memory allocation failure
            return 0;
        }
        if (!EvtRender(NULL, hEvent, EvtRenderEventXml, bufferUsed, xmlBuffer, &bufferUsed, &propertyCount)) {
            free(xmlBuffer);
            return 0;
        }
        // Convert to narrow string
        size_t narrowSize = wcstombs(NULL, xmlBuffer, 0) + 1;
        char *xml = (char*)malloc(narrowSize);
        if (!xml) {
            free(xmlBuffer);
            return 0;
        }
        wcstombs(xml, xmlBuffer, narrowSize);
        free(xmlBuffer);
        // Parse LogonType
        char *logonTypeField = strstr(xml, "<Data Name=\"LogonType\">");
        if (!logonTypeField) {
            free(xml);
            return 0;
        }
        logonTypeField += strlen("<Data Name=\"LogonType\">");
        char logonTypeStr[10] = {0};
        int k = 0;
        while (*logonTypeField != '<' && k < 9) {
            logonTypeStr[k++] = *logonTypeField++;
        }
        int logonType = atoi(logonTypeStr);
        if (logonType != 10) {
            free(xml);
            return 0;
        }
        // Parse IpAddress
        char *ipField = strstr(xml, "<Data Name=\"IpAddress\">");
        if (!ipField) {
            free(xml);
            return 0;
        }
        ipField += strlen("<Data Name=\"IpAddress\">");
        char ip[46] = {0};
        k = 0;
        while (*ipField != '<' && k < 45) {
            ip[k++] = *ipField++;
        }
        if (strlen(ip) == 0 || strcmp(ip, "-") == 0) {
            free(xml);
            return 0;
        }
        LogFailure(ip);
        free(xml);
    }
    return 0;
}

int main() {
    EVT_HANDLE hSubscription = NULL;

    printf("========================================\n");
    printf("   AegisRDP v0.1.0-alpha\n");
    printf("   Author: Hoa Tran | 2026\n");
    printf("========================================\n");

    hSubscription = EvtSubscribe(NULL, NULL, L"Security", L"Event[System[(EventID=4625)]]", 
                                 NULL, NULL, (EVT_SUBSCRIBE_CALLBACK)SubscriptionCallback, 
                                 EvtSubscribeToFutureEvents);

    if (hSubscription == NULL) {
        DWORD err = GetLastError();
        LPVOID msgBuf;
        if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                          NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&msgBuf, 0, NULL)) {
            printf("[-] EvtSubscribe failed: %s\n", (char*)msgBuf);
            LocalFree(msgBuf);
        } else {
            printf("[-] EvtSubscribe failed with error code: %lu\n", err);
        }
        return 1;
    }

    printf("[*] Real-time monitoring active. Press Ctrl+C to stop.\n");

    while (1) Sleep(1000); 

    EvtClose(hSubscription);
    return 0;
}