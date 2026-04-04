#include "include/firewall.h"
#include "include/logger.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static char blockedIPs[MAX_IP][46];
static int numBlocked = 0;

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

static int is_already_blocked(const char* ip) {
    for (int i = 0; i < numBlocked; i++) {
        if (strcmp(blockedIPs[i], ip) == 0) return 1;
    }
    return 0;
}

static void add_to_blocked_list(const char* ip) {
    if (numBlocked < MAX_IP && !is_already_blocked(ip)) {
        strcpy_s(blockedIPs[numBlocked], sizeof(blockedIPs[0]), ip);
        numBlocked++;
    }
}

void block_ip(const char* ip, const char* type, const Config* cfg) {
    if (!ip || !cfg) return;

    if (firewall_rule_exists(ip)) {
        add_to_blocked_list(ip);
        printf("[INFO] Firewall rule already exists for %s\n", ip);
        return;
    }

    if (cfg->dry_run) {
        printf("[DRY-RUN] Would block IP: %s\n", ip);
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "BLOCK IP=%s METHOD=firewall TYPE=%s (dry-run)", ip, type ? type : "unknown");
        log_to_file(log_msg, cfg);
        add_to_blocked_list(ip);
        return;
    }

    if (firewall_add_block(ip)) {
        add_to_blocked_list(ip);
        printf("[+] BLOCK APPLIED: %s\n", ip);
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "BLOCK IP=%s METHOD=firewall TYPE=%s", ip, type ? type : "unknown");
        log_to_file(log_msg, cfg);
    } else {
        printf("[-] Failed to block IP: %s\n", ip);
    }
}

int get_blocked_count(void) {
    return numBlocked;
}
