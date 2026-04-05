#ifndef FIREWALL_H
#define FIREWALL_H

#include "config.h"

void block_ip(const char* ip, const char* type, const Config* cfg);

void unblock_ip(const char* ip, const Config* cfg);

int get_blocked_count(void);

#endif /* FIREWALL_H */
