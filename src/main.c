#include <windows.h>
#include <winevt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "wevtapi.lib")

#include "include/config.h"
#include "include/event.h"
#include "include/detector.h"

char* whitelist[] = {"127.0.0.1", "192.168.1.1", NULL};

int main(int argc, char *argv[]) {
    EVT_HANDLE hSubscription = NULL;
    DWORD flags = EvtSubscribeToFutureEvents;

    Config cfg = {
        .threshold = THRESHOLD,
        .time_window = TIME_WINDOW,
        .long_threshold = LONG_THRESHOLD,
        .long_window = LONG_WINDOW,
        .block_duration = BLOCK_DURATION,
        .dry_run = 0,
        .debug_mode = 0,
        .stats_interval = STATS_INTERVAL,
        .log_file = LOG_FILE
    };

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--debug") == 0) {
            cfg.debug_mode = 1;
        } else if (strcmp(argv[i], "--start-oldest") == 0) {
            flags = EvtSubscribeStartAtOldestRecord;
            printf("[INFO] Running with EvtSubscribeStartAtOldestRecord\n");
        } else if (strcmp(argv[i], "--threshold") == 0 && i + 1 < argc) {
            cfg.threshold = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--window") == 0 && i + 1 < argc) {
            cfg.time_window = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--long-threshold") == 0 && i + 1 < argc) {
            cfg.long_threshold = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--long-window") == 0 && i + 1 < argc) {
            cfg.long_window = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--dry-run") == 0) {
            cfg.dry_run = 1;
        }
    }

    printf("========================================\n");
    printf("   AegisRDP v0.3.0-alpha\n");
    printf("   Author: Hoa Tran | 2026\n");
    printf("========================================\n");
    printf("[INFO] threshold=%d window=%d long_threshold=%d long_window=%d dry-run=%s debug=%s\n",
           cfg.threshold, cfg.time_window, cfg.long_threshold, cfg.long_window,
           cfg.dry_run ? "yes" : "no", cfg.debug_mode ? "yes" : "no");

    SetEventConfig(&cfg);

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
