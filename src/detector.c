#include "include/detector.h"
#include "include/firewall.h"
#include "include/logger.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>

typedef struct {
    char ip[46];
    time_t timestamps[MAX_FAILS];
    int numTimestamps;
    int isBlocked;
    int blockedSkipCount;
    time_t blockedAt;
    time_t lastSeen;
} IPTracker;

static IPTracker trackers[MAX_IP];
static int numTrackers = 0;
static int total_failures = 0;
static int total_blocked = 0;
static int unique_ips = 0;

static unsigned long ip_to_ulong(const char* ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) == 1) {
        return ntohl(addr.s_addr);
    }
    return 0;
}

static int is_ip_in_cidr(const char* ip, const char* cidr) {
    char network[46];
    int prefix_len;
    if (sscanf(cidr, "%[^/]/%d", network, &prefix_len) != 2) {
        return 0;
    }

    unsigned long ip_addr = ip_to_ulong(ip);
    unsigned long net_addr = ip_to_ulong(network);
    if (ip_addr == 0 || net_addr == 0) return 0;

    unsigned long mask = (prefix_len == 0) ? 0 : (~0UL << (32 - prefix_len));
    return (ip_addr & mask) == (net_addr & mask);
}

static int is_whitelisted(const char* ip, const Config* cfg) {
    if (!cfg) return 0;
    for (int i = 0; i < cfg->whitelist_count; i++) {
        if (cfg->whitelist[i]) {
            if (strcmp(ip, cfg->whitelist[i]) == 0) {
                return 1;
            }
            if (is_ip_in_cidr(ip, cfg->whitelist[i])) {
                return 1;
            }
        }
    }
    return 0;
}

void LogFailure(const char* ip, int logonType, Config* cfg) {
    if (!ip || !cfg) return;
    
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
            trackers[numTrackers].lastSeen = now;
            found = numTrackers++;
            unique_ips++;
        } else {
            printf("[WARN] MAX_IP reached, ignoring new IP %s\n", ip);
            return;
        }
    }

    IPTracker *t = &trackers[found];
    t->lastSeen = now;

    if (t->isBlocked) {
        if (t->blockedAt != 0 && difftime(now, t->blockedAt) >= cfg->block_duration) {
            t->isBlocked = 0;
            t->blockedSkipCount = 0;
            t->blockedAt = 0;
            t->numTimestamps = 0;
            unblock_ip(ip, cfg);
            DEBUG_LOG(cfg, "Unblocked %s after cooldown\n", ip);
        } else {
            if (is_whitelisted(ip, cfg)) return;
            t->blockedSkipCount++;
            if (t->blockedSkipCount == 1) {
                DEBUG_LOG(cfg, "[INFO] IP %s already blocked, ignoring further attempts\n", ip);
            } else if (t->blockedSkipCount % 10 == 0) {
                DEBUG_LOG(cfg, "[INFO] IP %s already blocked, ignored %d attempts so far\n", ip, t->blockedSkipCount);
            }
            return;
        }
    }

    int j = 0;
    for (int i = 0; i < t->numTimestamps; i++) {
        if (difftime(now, t->timestamps[i]) <= cfg->long_window) {
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

    int fastCount = 0;
    int slowCount = 0;
    for (int i = 0; i < t->numTimestamps; i++) {
        double d = difftime(now, t->timestamps[i]);
        if (d <= cfg->time_window) fastCount++;
        if (d <= cfg->long_window) slowCount++;
    }

    printf("[FAIL] IP=%s COUNT=%d TYPE=%d\n", ip, fastCount, logonType);
    char fail_msg[256];
    snprintf(fail_msg, sizeof(fail_msg), "FAIL IP=%s COUNT=%d TYPE=%d", ip, fastCount, logonType);
    log_to_file(fail_msg, cfg);
    total_failures++;
    if (total_failures % cfg->stats_interval == 0) {
        printf("[STATS] total_fail=%d blocked=%d unique_ip=%d\n", total_failures, total_blocked, unique_ips);
    }

    int triggered = 0;
    const char *reason = NULL;
    if (fastCount >= cfg->threshold) { triggered = 1; reason = "FAST_BRUTE"; }
    else if (slowCount >= cfg->long_threshold) { triggered = 1; reason = "SLOW_BRUTE"; }

    if (triggered) {
        if (reason && strcmp(reason, "FAST_BRUTE") == 0) {
            printf(">>> FAST BRUTE DETECTED: %s <<<\n", ip);
        } else if (reason && strcmp(reason, "SLOW_BRUTE") == 0) {
            printf(">>> SLOW BRUTE DETECTED: %s <<<\n", ip);
        } else {
            printf(">>> BRUTE DETECTED: %s <<<\n", ip);
        }

        if (!is_whitelisted(ip, cfg)) {
            t->isBlocked = 1;
            t->blockedAt = now;
            t->blockedSkipCount = 0;
            const char *type = (reason && strstr(reason, "FAST")) ? "fast" : "slow";
            block_ip(ip, type, cfg);
            total_blocked++;
        } else {
            printf("[INFO] IP %s is whitelisted, not blocking\n", ip);
            char log_msg[256];
            snprintf(log_msg, sizeof(log_msg), "BLOCK_SKIPPED IP=%s REASON=%s", ip, reason);
            log_to_file(log_msg, cfg);
        }
    } else {
        printf("[INFO] Below threshold (%d/%d) for %s\n", fastCount, cfg->threshold, ip);
    }
}

int get_total_failures(void) {
    return total_failures;
}

int get_total_blocked(void) {
    return total_blocked;
}

int get_unique_ips(void) {
    return unique_ips;
}

// Check and unblock IPs whose block duration has expired
void check_and_unblock_expired_ips(const Config* cfg) {
    if (!cfg) return;
    time_t now = time(NULL);
    
    for (int i = 0; i < numTrackers; i++) {
        IPTracker *t = &trackers[i];
        if (t->isBlocked && t->blockedAt != 0 && difftime(now, t->blockedAt) >= cfg->block_duration) {
            t->isBlocked = 0;
            t->blockedSkipCount = 0;
            t->blockedAt = 0;
            t->numTimestamps = 0;
            unblock_ip(t->ip, cfg);
            DEBUG_LOG(cfg, "Auto-unblocked %s after %d seconds\n", t->ip, cfg->block_duration);
        }
    }
}

void garbage_collect_old_entries(const Config* cfg) {
    if (!cfg) return;
    time_t now = time(NULL);
    const time_t max_age = 24 * 60 * 60;
    
    for (int i = 0; i < numTrackers; ) {
        IPTracker *t = &trackers[i];
        if (!t->isBlocked && difftime(now, t->lastSeen) > max_age) {
            for (int j = i; j < numTrackers - 1; j++) {
                trackers[j] = trackers[j + 1];
            }
            numTrackers--;
            unique_ips--;
            DEBUG_LOG(cfg, "Garbage collected old entry for %s\n", t->ip);
        } else {
            i++;
        }
    }
}
