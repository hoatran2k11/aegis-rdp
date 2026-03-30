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

#define DEBUG_LOG(fmt, ...) \
    do { if (DEBUG_MODE) printf("[DEBUG] " fmt, ##__VA_ARGS__); } while (0)

int DEBUG_MODE = 0;

const char* LOG_FILE = "aegis-rdp.log";
char* whitelist[] = {"127.0.0.1", "192.168.1.1", NULL};

typedef struct {
    char ip[46];
    time_t timestamps[MAX_FAILS];
    int numTimestamps;
} IPTracker;

IPTracker trackers[MAX_IP];
int numTrackers = 0;

char blockedIPs[MAX_IP][46];
int numBlocked = 0;

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
    const char *dataTag = strstr(xml, "<Data Name=");
    if (!dataTag) return 0;
    const char *quote = dataTag + 11; // after <Data Name=
    char quoteChar = *quote;
    if (quoteChar != '"' && quoteChar != '\'') return 0;
    const char *nameStart = quote + 1;
    const char *nameEnd = strchr(nameStart, quoteChar);
    if (!nameEnd) return 0;
    int nameLen = (int)(nameEnd - nameStart);
    if (nameLen != (int)strlen(name) || strncmp(nameStart, name, nameLen) != 0) return 0;
    const char *valueStart = nameEnd + 1;
    if (*valueStart != '>') return 0;
    valueStart++;
    const char *valueEnd = strstr(valueStart, "</Data>");
    if (!valueEnd) return 0;
    int len = (int)(valueEnd - valueStart);
    if (len >= outSize) len = outSize - 1;
    memcpy(out, valueStart, len);
    out[len] = '\0';
    return len;
}

char* extract_value(const char* xml, const char* key) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "Name=\"%s\"", key);
    const char* pos = strstr(xml, pattern);
    if (!pos) {
        snprintf(pattern, sizeof(pattern), "Name='%s'", key);
        pos = strstr(xml, pattern);
        if (!pos) return NULL;
    }
    pos = strchr(pos, '>');
    if (!pos) return NULL;
    pos++;
    const char* end = strstr(pos, "</Data>");
    if (!end) return NULL;
    size_t len = end - pos;
    char* value = malloc(len + 1);
    if (!value) return NULL;
    memcpy(value, pos, len);
    value[len] = '\0';
    return value;
}

int is_whitelisted(const char* ip) {
    // Whitelist check: prevent blocking of trusted IPs
    for (int i = 0; whitelist[i] != NULL; i++) {
        if (strcmp(ip, whitelist[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

void log_to_file(const char* message) {
    // File logging: append all fails and blocks to log file
    FILE* f = fopen(LOG_FILE, "a");
    if (f) {
        time_t now = time(NULL);
        char time_str[26];
        ctime_s(time_str, sizeof(time_str), &now);
        time_str[strlen(time_str) - 1] = '\0'; // Remove newline
        fprintf(f, "[%s] %s\n", time_str, message);
        fclose(f);
    }
}

void block_ip(const char* ip) {
    for (int i = 0; i < numBlocked; i++) {
        if (strcmp(blockedIPs[i], ip) == 0) {
            printf("[INFO] IP %s already blocked, skipping\n", ip);
            return;
        }
    }

    if (numBlocked < MAX_IP) {
        strcpy(blockedIPs[numBlocked++], ip);
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "netsh advfirewall firewall add rule name=\"AegisRDP_Block_%s\" dir=in action=block remoteip=%s", ip, ip);
    if (system(cmd) == 0) {
        printf("[+] BLOCK APPLIED: %s\n", ip);
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "BLOCKED IP: %s", ip);
        log_to_file(log_msg);
    } else {
        printf("[-] Failed to block IP: %s\n", ip);
    }
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
        DEBUG_LOG("%s old timestamps removed for %s. kept=%d\n", ip, ip, t->numTimestamps);
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

    char fail_msg[256];
    snprintf(fail_msg, sizeof(fail_msg), "FAIL IP: %s | Count: %d | LogonType: %d", ip, currentCount, logonType);
    log_to_file(fail_msg);

    if (currentCount >= THRESHOLD) {
        printf(">>> BRUTE DETECTED: %s <<<\n", ip);
        if (!is_whitelisted(ip)) {
            block_ip(ip);
        } else {
            printf("[INFO] IP %s is whitelisted, not blocking\n", ip);
        }
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

    DEBUG_LOG("Received event XML:\n%s\n", xml);

    char eventId[16] = {0};
    if (ExtractXmlElementValue(xml, "EventID", eventId, sizeof(eventId)) > 0) {
        DEBUG_LOG("EventID parsed: %s\n", eventId);
    } else {
        printf("[WARN] EventID missing from XML, raw event follows for analysis:\n%s\n", xml);
    }

    int logonType;
    char ip[46] = {0};
    char targetUser[128] = {0};

    char* logonTypeStr = extract_value(xml, "LogonType");
    if (!logonTypeStr) {
        printf("[WARN] LogonType missing\n");
        free(xml);
        return 0;
    }
    logonType = atoi(logonTypeStr);
    free(logonTypeStr);

    char* ipStr = extract_value(xml, "IpAddress");
    if (!ipStr) {
        printf("[WARN] IpAddress missing\n");
        free(xml);
        return 0;
    }
    strncpy(ip, ipStr, sizeof(ip) - 1);
    free(ipStr);

    char* userStr = extract_value(xml, "TargetUserName");
    if (userStr) {
        strncpy(targetUser, userStr, sizeof(targetUser) - 1);
        free(userStr);
    }

    if (logonType == -1) {
        free(xml);
        return 0;
    }

    if (strlen(ip) == 0 || strcmp(ip, "-") == 0) {
        printf("[WARN] IpAddress invalid/missing ('%s') in event, raw XML:\n%s\n", ip, xml);
        free(xml);
        return 0;
    }

    DEBUG_LOG("Parsed LogonType: %d, IP: '%s', TargetUserName: '%s'\n", logonType, ip, targetUser);
    if (logonType != 3 && logonType != 10) {
        DEBUG_LOG("LogonType %d not 3 or 10, ignoring (IP=%s)\n", logonType, ip);
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

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--debug") == 0) {
            DEBUG_MODE = 1;
        } else if (strcmp(argv[i], "--start-oldest") == 0) {
            flags = EvtSubscribeStartAtOldestRecord;
            printf("[INFO] Running with EvtSubscribeStartAtOldestRecord (debug mode)\n");
        }
    }

    printf("========================================\n");
    printf("   AegisRDP v0.2.0-alpha\n");
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