#include <windows.h>
#include <winevt.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#pragma comment(lib, "wevtapi.lib")

#define THRESHOLD 5
#define TIME_WINDOW 60
#define LONG_THRESHOLD 10
#define LONG_WINDOW 300
#define BLOCK_DURATION 600
#define MAX_IP 100
#define MAX_FAILS 100

#define DEBUG_LOG(fmt, ...) \
    do { if (DEBUG_MODE) printf("[DEBUG] " fmt, ##__VA_ARGS__); } while (0)

int DEBUG_MODE = 0;
int DRY_RUN = 0;
int threshold = THRESHOLD;
int time_window = TIME_WINDOW;
int long_threshold = LONG_THRESHOLD;
int long_window = LONG_WINDOW;

const char* LOG_FILE = "aegis-rdp.log";
char* whitelist[] = {"127.0.0.1", "192.168.1.1", NULL};

typedef struct {
    char ip[46];
    time_t timestamps[MAX_FAILS];
    int numTimestamps;
    int isBlocked;
    int blockedSkipCount;
    time_t blockedAt;
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
    const char *pos = xml;
    size_t name_len = strlen(name);
    while ((pos = strstr(pos, "<Data Name=")) != NULL) {
        const char *quote = pos + 11; /* after <Data Name= */
        char quoteChar = *quote;
        if (quoteChar != '"' && quoteChar != '\'') { pos += 10; continue; }
        const char *nameStart = quote + 1;
        const char *nameEnd = strchr(nameStart, quoteChar);
        if (!nameEnd) break;
        int nameLen = (int)(nameEnd - nameStart);
        if (nameLen == (int)name_len && strncmp(nameStart, name, nameLen) == 0) {
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
        pos = nameEnd + 1;
    }
    return 0;
}

/* removed unsafe extract_value (used malloc). Use ExtractXmlDataValue() which writes into caller buffers. */

int is_whitelisted(const char* ip) {
    for (int i = 0; whitelist[i] != NULL; i++) {
        if (strcmp(ip, whitelist[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

void log_to_file(const char* message) {
    FILE* f = fopen(LOG_FILE, "a");
    if (f) {
        time_t now = time(NULL);
        struct tm tmv;
        localtime_s(&tmv, &now);
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tmv);
        fprintf(f, "[%s] %s\n", time_str, message);
        fflush(f);
        fclose(f);
    }
}

static int firewall_rule_exists(const char* ip) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "netsh advfirewall firewall show rule name=\"AegisRDP_Block_%s\" >nul 2>&1", ip);
    int rc = system(cmd);
    return rc == 0;
}

static int firewall_add_block(const char* ip) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "netsh advfirewall firewall add rule name=\"AegisRDP_Block_%s\" dir=in action=block remoteip=%s >nul 2>&1", ip, ip);
    return system(cmd) == 0;
}

void block_ip(const char* ip) {
    if (firewall_rule_exists(ip)) {
        for (int i = 0; i < numBlocked; i++) {
            if (strcmp(blockedIPs[i], ip) == 0) return;
        }
        if (numBlocked < MAX_IP) { strcpy_s(blockedIPs[numBlocked], sizeof(blockedIPs[0]), ip); numBlocked++; }
        printf("[INFO] Firewall rule already exists for %s\n", ip);
        return;
    }

    if (DRY_RUN) {
        printf("[DRY-RUN] Would block IP: %s\n", ip);
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "EVENT=DRY_BLOCK IP=%s", ip);
        log_to_file(log_msg);
        if (numBlocked < MAX_IP) { strcpy_s(blockedIPs[numBlocked], sizeof(blockedIPs[0]), ip); numBlocked++; }
        return;
    }

    if (firewall_add_block(ip)) {
        if (numBlocked < MAX_IP) { strcpy_s(blockedIPs[numBlocked], sizeof(blockedIPs[0]), ip); numBlocked++; }
        printf("[+] BLOCK APPLIED: %s\n", ip);
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "EVENT=BLOCK IP=%s REASON=UNKNOWN", ip);
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
            strncpy_s(trackers[numTrackers].ip, sizeof(trackers[numTrackers].ip), ip, _TRUNCATE);
            trackers[numTrackers].numTimestamps = 0;
            trackers[numTrackers].isBlocked = 0;
            trackers[numTrackers].blockedSkipCount = 0;
            trackers[numTrackers].blockedAt = 0;
            found = numTrackers++;
        } else {
            printf("[WARN] MAX_IP reached, ignoring new IP %s\n", ip);
            return;
        }
    }

    IPTracker *t = &trackers[found];

    if (t->isBlocked) {
        if (t->blockedAt != 0 && difftime(now, t->blockedAt) >= BLOCK_DURATION) {
            // cooldown expired: allow re-detection
            t->isBlocked = 0;
            t->blockedSkipCount = 0;
            t->blockedAt = 0;
            t->numTimestamps = 0;
            DEBUG_LOG("Unblocked %s after cooldown\n", ip);
        } else {
            if (is_whitelisted(ip)) return;
            t->blockedSkipCount++;
            if (t->blockedSkipCount == 1) {
                printf("[INFO] IP %s already blocked, ignoring further attempts\n", ip);
            } else if (t->blockedSkipCount % 10 == 0) {
                printf("[INFO] IP %s already blocked, ignored %d attempts so far\n", ip, t->blockedSkipCount);
            }
            return;
        }
    }

    // prune timestamps older than long_window (we keep history for slow detection)
    int j = 0;
    for (int i = 0; i < t->numTimestamps; i++) {
        if (difftime(now, t->timestamps[i]) <= long_window) {
            t->timestamps[j++] = t->timestamps[i];
        }
    }
    t->numTimestamps = j;

    if (t->numTimestamps < MAX_FAILS) {
        t->timestamps[t->numTimestamps++] = now;
    } else {
        memmove(t->timestamps, t->timestamps + 1, sizeof(time_t) * (MAX_FAILS - 1));
        t->timestamps[MAX_FAILS - 1] = now;
    }

    // compute fast and slow counts
    int fastCount = 0;
    int slowCount = 0;
    for (int i = 0; i < t->numTimestamps; i++) {
        double d = difftime(now, t->timestamps[i]);
        if (d <= time_window) fastCount++;
        if (d <= long_window) slowCount++;
    }

    printf("[FAIL] IP=%s COUNT=%d TYPE=%d\n", ip, fastCount, logonType);
    char fail_msg[256];
    snprintf(fail_msg, sizeof(fail_msg), "EVENT=FAIL IP=%s COUNT=%d TYPE=%d", ip, fastCount, logonType);
    log_to_file(fail_msg);

    int triggered = 0;
    const char *reason = NULL;
    if (fastCount >= threshold) { triggered = 1; reason = "FAST_BRUTE"; }
    else if (slowCount >= long_threshold) { triggered = 1; reason = "SLOW_BRUTE"; }

    if (triggered) {
        printf(">>> BRUTE DETECTED: %s <<<\n", ip);
        if (!is_whitelisted(ip)) {
            t->isBlocked = 1;
            t->blockedAt = now;
            t->blockedSkipCount = 0;
            block_ip(ip);
            char log_msg[256];
            snprintf(log_msg, sizeof(log_msg), "EVENT=BLOCK IP=%s REASON=%s", ip, reason);
            log_to_file(log_msg);
        } else {
            printf("[INFO] IP %s is whitelisted, not blocking\n", ip);
            char log_msg[256];
            snprintf(log_msg, sizeof(log_msg), "EVENT=BLOCK_SKIPPED IP=%s REASON=%s", ip, reason);
            log_to_file(log_msg);
        }
    } else {
        printf("[INFO] Below threshold (%d/%d) for %s\n", fastCount, threshold, ip);
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

    char logonTypeBuf[16] = {0};
    if (ExtractXmlDataValue(xml, "LogonType", logonTypeBuf, sizeof(logonTypeBuf)) <= 0) {
        printf("[WARN] LogonType missing\n");
        free(xml);
        return 0;
    }
    logonType = atoi(logonTypeBuf);

    char ipBuf[46] = {0};
    if (ExtractXmlDataValue(xml, "IpAddress", ipBuf, sizeof(ipBuf)) <= 0) {
        printf("[WARN] IpAddress missing\n");
        free(xml);
        return 0;
    }
    strncpy_s(ip, sizeof(ip), ipBuf, _TRUNCATE);

    char userBuf[128] = {0};
    if (ExtractXmlDataValue(xml, "TargetUserName", userBuf, sizeof(userBuf)) > 0) {
        strncpy_s(targetUser, sizeof(targetUser), userBuf, _TRUNCATE);
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
            printf("[INFO] Running with EvtSubscribeStartAtOldestRecord\n");
        } else if (strcmp(argv[i], "--threshold") == 0 && i + 1 < argc) {
            threshold = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--window") == 0 && i + 1 < argc) {
            time_window = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--dry-run") == 0) {
            DRY_RUN = 1;
        }
    }

    printf("========================================\n");
    printf("   AegisRDP v0.3.0-alpha\n");
    printf("   Author: Hoa Tran | 2026\n");
    printf("========================================\n");
    printf("[INFO] threshold=%d window=%d long_threshold=%d long_window=%d dry-run=%s\n", threshold, time_window, long_threshold, long_window, DRY_RUN?"yes":"no");

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