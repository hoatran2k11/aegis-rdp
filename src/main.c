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

static int ExtractXmlElementValue(const char *xml, const char *tag, char *out, int outSize) {
    if (!xml || !tag || !out || outSize <= 0) return 0;
    char openTag[128];
    char closeTag[128];
    snprintf(openTag, sizeof(openTag), "<%s", tag);
    snprintf(closeTag, sizeof(closeTag), "</%s>", tag);

    const char *start = strstr(xml, openTag);
    if (!start) return 0;
    start = strchr(start, '>');
    if (!start) return 0;
    start++;

    const char *end = strstr(start, closeTag);
    if (!end) return 0;

    int len = (int)(end - start);
    if (len >= outSize) len = outSize - 1;
    memcpy(out, start, len);
    out[len] = '\0';
    return len;
}

static int ExtractXmlDataValue(const char *xml, const char *name, char *out, int outSize) {
    if (!xml || !name || !out || outSize <= 0) return 0;
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "<Data Name=\"%s\">", name);

    const char *start = strstr(xml, pattern);
    if (!start) return 0;
    start += strlen(pattern);

    const char *end = strchr(start, '<');
    if (!end) return 0;

    int len = (int)(end - start);
    if (len >= outSize) len = outSize - 1;
    memcpy(out, start, len);
    out[len] = '\0';
    return len;
}

void LogFailure(const char* ip, int logonType) {
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
            printf("[WARN] MAX_IP reached, ignoring new IP %s\n", ip);
            return;
        }
    }

    IPTracker *t = &trackers[found];

    int oldCount = t->numTimestamps;
    int j = 0;
    for (int i = 0; i < t->numTimestamps; i++) {
        if (difftime(now, t->timestamps[i]) <= TIME_WINDOW) {
            t->timestamps[j++] = t->timestamps[i];
        }
    }
    t->numTimestamps = j;

    if (oldCount != t->numTimestamps) {
        printf("[DEBUG] %s old timestamps removed for %s. kept=%d\n", ip, ip, t->numTimestamps);
    }

    double delta = 0;
    if (t->numTimestamps > 0) {
        delta = difftime(now, t->timestamps[t->numTimestamps - 1]);
    }

    if (t->numTimestamps < MAX_FAILS) {
        t->timestamps[t->numTimestamps++] = now;
    } else {
        memmove(t->timestamps, t->timestamps + 1, sizeof(time_t) * (MAX_FAILS - 1));
        t->timestamps[MAX_FAILS - 1] = now;
    }

    int currentCount = t->numTimestamps;
    printf("[FAIL] IP: %s | Count: %d | LogonType: %d | Delta: %.0f sec\n", ip, currentCount, logonType, delta);

    if (currentCount >= THRESHOLD) {
        printf(">>> BRUTE DETECTED: %s <<<\n", ip);
    } else {
        printf("[INFO] Below threshold (%d/%d) for %s\n", currentCount, THRESHOLD, ip);
    }
}

DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent) {
    if (action != EvtSubscribeActionDeliver) {
        return 0;
    }

    DWORD bufferUsed = 0, propertyCount = 0;
    if (!EvtRender(NULL, hEvent, EvtRenderEventXml, 0, NULL, &bufferUsed, &propertyCount)) {
        DWORD error = GetLastError();
        if (error != ERROR_INSUFFICIENT_BUFFER) {
            printf("[ERROR] EvtRender (size query) failed: %lu\n", error);
            return 0;
        }
    }

    LPWSTR xmlBuffer = (LPWSTR)malloc(bufferUsed * sizeof(WCHAR));
    if (!xmlBuffer) {
        printf("[ERROR] Out of memory allocating XML buffer (%u chars)\n", bufferUsed);
        return 0;
    }

    if (!EvtRender(NULL, hEvent, EvtRenderEventXml, bufferUsed, xmlBuffer, &bufferUsed, &propertyCount)) {
        DWORD error = GetLastError();
        printf("[ERROR] EvtRender failed: %lu\n", error);
        free(xmlBuffer);
        return 0;
    }

    size_t narrowSize = wcstombs(NULL, xmlBuffer, 0) + 1;
    char *xml = (char*)malloc(narrowSize);
    if (!xml) {
        printf("[ERROR] Out of memory converting XML to UTF-8\n");
        free(xmlBuffer);
        return 0;
    }
    wcstombs(xml, xmlBuffer, narrowSize);
    free(xmlBuffer);

    printf("[DEBUG] Received event XML:\n%s\n", xml);

    char eventId[16] = {0};
    if (ExtractXmlElementValue(xml, "EventID", eventId, sizeof(eventId)) > 0) {
        printf("[DEBUG] EventID parsed: %s\n", eventId);
    } else {
        printf("[WARN] EventID missing from XML, raw event follows for analysis:\n%s\n", xml);
    }

    char logonTypeStr[10] = {0};
    if (!ExtractXmlDataValue(xml, "LogonType", logonTypeStr, sizeof(logonTypeStr))) {
        printf("[WARN] LogonType missing from XML, raw event follows:\n%s\n", xml);
        free(xml);
        return 0;
    }

    char ip[46] = {0};
    ExtractXmlDataValue(xml, "IpAddress", ip, sizeof(ip));

    if (strlen(ip) == 0 || strcmp(ip, "-") == 0) {
        printf("[WARN] IpAddress invalid/missing ('%s') in event, raw XML:\n%s\n", ip, xml);
        free(xml);
        return 0;
    }

    int logonType = atoi(logonTypeStr);
    if (logonType != 3 && logonType != 10) {
        printf("[DEBUG] LogonType %d not 3 or 10, ignoring (IP=%s)\n", logonType, ip);
        free(xml);
        return 0;
    }

    LogFailure(ip, logonType);
    free(xml);
    return 0;
}

int main(int argc, char *argv[]) {
    EVT_HANDLE hSubscription = NULL;
    DWORD flags = EvtSubscribeToFutureEvents;

    if (argc > 1 && strcmp(argv[1], "--start-oldest") == 0) {
        flags = EvtSubscribeStartAtOldestRecord;
        printf("[INFO] Running with EvtSubscribeStartAtOldestRecord (debug mode)\n");
    }

    printf("========================================\n");
    printf("   AegisRDP v0.1.0-alpha\n");
    printf("   Author: Hoa Tran | 2026\n");
    printf("========================================\n");

    hSubscription = EvtSubscribe(NULL, NULL, L"Security", L"Event[System[(EventID=4625)]]", 
                                 NULL, NULL, (EVT_SUBSCRIBE_CALLBACK)SubscriptionCallback, 
                                 flags);

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

    while (1) {
        Sleep(1000);
    }

    EvtClose(hSubscription);
    return 0;
}