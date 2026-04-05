#ifndef DETECTOR_H
#define DETECTOR_H

#include "config.h"

void LogFailure(const char* ip, int logonType, Config* cfg);

int get_total_failures(void);

int get_total_blocked(void);

int get_unique_ips(void);

void check_and_unblock_expired_ips(const Config* cfg);

void garbage_collect_old_entries(const Config* cfg);

#endif /* DETECTOR_H */
