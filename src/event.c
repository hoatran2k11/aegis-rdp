#include "include/event.h"
#include "include/parser.h"
#include "include/detector.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static Config* g_event_config = NULL;

void SetEventConfig(Config* cfg) {
    g_event_config = cfg;
}

DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent) {
    if (action != EvtSubscribeActionDeliver) {
        return 0;
    }

    if (!g_event_config) {
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

    DEBUG_LOG(g_event_config, "Received event XML:\n%s\n", xml);

    char eventId[16] = {0};
    if (ExtractXmlElementValue(xml, "EventID", eventId, sizeof(eventId)) > 0) {
        DEBUG_LOG(g_event_config, "EventID parsed: %s\n", eventId);
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

    DEBUG_LOG(g_event_config, "Parsed LogonType: %d, IP: '%s', TargetUserName: '%s'\n", logonType, ip, targetUser);
    if (logonType != 3 && logonType != 10) {
        DEBUG_LOG(g_event_config, "LogonType %d not 3 or 10, ignoring (IP=%s)\n", logonType, ip);
        free(xml);
        return 0;
    }

    LogFailure(ip, logonType, g_event_config);
    free(xml);
    return 0;
}
