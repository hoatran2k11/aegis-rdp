#ifndef EVENT_H
#define EVENT_H

#include <windows.h>
#include <winevt.h>
#include "config.h"

DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent);

void SetEventConfig(Config* cfg);

#endif /* EVENT_H */
