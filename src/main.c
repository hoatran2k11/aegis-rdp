#include <windows.h>
#include <winevt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <process.h>

#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "advapi32.lib")

#include "include/config.h"
#include "include/config_loader.h"
#include "include/event.h"
#include "include/detector.h"
#include "include/firewall.h"

static SERVICE_STATUS g_ServiceStatus = {0};
static SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
static HANDLE g_ServiceStopEvent = INVALID_HANDLE_VALUE;
static HANDLE g_UnblockThread = NULL;
static Config g_cfg = {0};
static EVT_HANDLE g_hSubscription = NULL;

VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv);
VOID WINAPI ServiceCtrlHandler(DWORD);
void ReportServiceEvent(WORD type, DWORD id, const char* msg);
DWORD WINAPI UnblockThreadProc(LPVOID lpParam);
void CleanupStaleFirewallRules(const Config* cfg);

int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "--service") == 0) {
        SERVICE_TABLE_ENTRY ServiceTable[] = {
            {"AegisRDP", (LPSERVICE_MAIN_FUNCTION)ServiceMain},
            {NULL, NULL}
        };
        
        if (!StartServiceCtrlDispatcher(ServiceTable)) {
            ReportServiceEvent(EVENTLOG_ERROR_TYPE, 0, "StartServiceCtrlDispatcher failed");
            return 1;
        }
        return 0;
    }

    return RunConsoleMode(argc, argv);
}

int RunConsoleMode(int argc, char *argv[]) {
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
        .log_file = LOG_FILE,
        .whitelist_count = 0
    };

    ensure_config_exists("config.ini");
    load_config_from_ini(&cfg, "config.ini");

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

    printf("    _               _   ____  ____  ____  \n");
    printf("   / \\   ___  __ _(_)___|  _ \\|  _ \\|  _ \\ \n");
    printf("  / _ \\ / _ \\/ _` | / __| |_) | | | | |_) |\n");
    printf(" / ___ \\  __/ (_| | \\__ \\  _ <| |_| |  __/ \n");
    printf("/_/   \\_\\___|\\__, |_|___/_| \\_\\____/|_|    \n");
    printf("             |___/                         \n");
    printf("===========================================\n");
    printf("   AegisRDP v0.3.0-RC\n");
    printf("   Author: Hoa Tran | 2026\n");
    printf("===========================================\n");
    printf("[INFO] threshold=%d window=%d long_threshold=%d long_window=%d dry-run=%s debug=%s\n",
           cfg.threshold, cfg.time_window, cfg.long_threshold, cfg.long_window,
           cfg.dry_run ? "yes" : "no", cfg.debug_mode ? "yes" : "no");

    SetEventConfig(&cfg);
    CleanupStaleFirewallRules(&cfg);

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

    g_UnblockThread = CreateThread(NULL, 0, UnblockThreadProc, &cfg, 0, NULL);
    if (g_UnblockThread == NULL) {
        printf("[-] Failed to create unblock thread\n");
        EvtClose(hSubscription);
        return 1;
    }

    time_t last_gc = time(NULL);
    while (1) {
        Sleep(1000);
        
        time_t now = time(NULL);
        if (difftime(now, last_gc) >= 300) {
            garbage_collect_old_entries(&cfg);
            last_gc = now;
        }
    }

    if (g_UnblockThread) {
        TerminateThread(g_UnblockThread, 0);
        CloseHandle(g_UnblockThread);
    }
    EvtClose(hSubscription);
    return 0;
}

VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv) {
    DWORD Status = E_FAIL;

    g_StatusHandle = RegisterServiceCtrlHandler("AegisRDP", ServiceCtrlHandler);
    if (g_StatusHandle == NULL) {
        ReportServiceEvent(EVENTLOG_ERROR_TYPE, 0, "RegisterServiceCtrlHandler failed");
        goto EXIT;
    }

    ZeroMemory(&g_ServiceStatus, sizeof(g_ServiceStatus));
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;

    if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE) {
        ReportServiceEvent(EVENTLOG_ERROR_TYPE, 0, "SetServiceStatus failed");
        goto EXIT;
    }

    g_cfg.threshold = THRESHOLD;
    g_cfg.time_window = TIME_WINDOW;
    g_cfg.long_threshold = LONG_THRESHOLD;
    g_cfg.long_window = LONG_WINDOW;
    g_cfg.block_duration = BLOCK_DURATION;
    g_cfg.dry_run = 0;
    g_cfg.debug_mode = 0;
    g_cfg.stats_interval = STATS_INTERVAL;
    g_cfg.log_file = LOG_FILE;
    g_cfg.whitelist_count = 0;

    ensure_config_exists("config.ini");
    load_config_from_ini(&g_cfg, "config.ini");

    SetEventConfig(&g_cfg);
    CleanupStaleFirewallRules(&g_cfg);

    g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_ServiceStopEvent == NULL) {
        ReportServiceEvent(EVENTLOG_ERROR_TYPE, 0, "CreateEvent failed");
        g_ServiceStatus.dwControlsAccepted = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = GetLastError();
        g_ServiceStatus.dwCheckPoint = 1;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        goto EXIT;
    }

    g_hSubscription = EvtSubscribe(NULL, NULL, L"Security", L"Event[System[(EventID=4625)]]",
                                   NULL, NULL, (EVT_SUBSCRIBE_CALLBACK)SubscriptionCallback,
                                   EvtSubscribeToFutureEvents);

    if (g_hSubscription == NULL) {
        ReportServiceEvent(EVENTLOG_ERROR_TYPE, 0, "EvtSubscribe failed");
        goto EXIT;
    }

    g_UnblockThread = CreateThread(NULL, 0, UnblockThreadProc, &g_cfg, 0, NULL);
    if (g_UnblockThread == NULL) {
        ReportServiceEvent(EVENTLOG_ERROR_TYPE, 0, "CreateThread failed");
        goto EXIT;
    }

    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;

    if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE) {
        ReportServiceEvent(EVENTLOG_ERROR_TYPE, 0, "SetServiceStatus failed");
        goto EXIT;
    }

    ReportServiceEvent(EVENTLOG_INFORMATION_TYPE, 0, "AegisRDP service started successfully");

    time_t last_gc = time(NULL);
    while (WaitForSingleObject(g_ServiceStopEvent, 1000) != WAIT_OBJECT_0) {
        time_t now = time(NULL);
        if (difftime(now, last_gc) >= 300) {
            garbage_collect_old_entries(&g_cfg);
            last_gc = now;
        }
    }

    Status = NO_ERROR;

EXIT:
    if (g_UnblockThread) {
        TerminateThread(g_UnblockThread, 0);
        CloseHandle(g_UnblockThread);
        g_UnblockThread = NULL;
    }
    if (g_hSubscription) {
        EvtClose(g_hSubscription);
        g_hSubscription = NULL;
    }
    if (g_ServiceStopEvent) {
        CloseHandle(g_ServiceStopEvent);
        g_ServiceStopEvent = NULL;
    }

    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = (Status == NO_ERROR) ? SERVICE_STOPPED : SERVICE_STOP_PENDING;
    g_ServiceStatus.dwWin32ExitCode = Status;
    g_ServiceStatus.dwCheckPoint = 1;

    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

VOID WINAPI ServiceCtrlHandler(DWORD CtrlCode) {
    switch (CtrlCode) {
        case SERVICE_CONTROL_STOP:
            ReportServiceEvent(EVENTLOG_INFORMATION_TYPE, 0, "Service stop requested");

            g_ServiceStatus.dwControlsAccepted = 0;
            g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            g_ServiceStatus.dwWin32ExitCode = 0;
            g_ServiceStatus.dwCheckPoint = 4;

            SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

            SetEvent(g_ServiceStopEvent);
            break;

        default:
            break;
    }
}

void ReportServiceEvent(WORD type, DWORD id, const char* msg) {
    HANDLE hEventSource = RegisterEventSource(NULL, "AegisRDP");
    if (hEventSource) {
        const char* strings[1] = {msg};
        ReportEvent(hEventSource, type, 0, id, NULL, 1, 0, strings, NULL);
        DeregisterEventSource(hEventSource);
    }
}

DWORD WINAPI UnblockThreadProc(LPVOID lpParam) {
    Config* cfg = (Config*)lpParam;
    while (1) {
        Sleep(10000);
        check_and_unblock_expired_ips(cfg);
    }
    return 0;
}

void CleanupStaleFirewallRules(const Config* cfg) {
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "INFO: Cleanup of stale AegisRDP firewall rules completed");
    log_to_file(log_msg, cfg);
}