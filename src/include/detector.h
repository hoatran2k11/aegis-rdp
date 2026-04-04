#ifndef DETECTOR_H
#define DETECTOR_H

#include "config.h"

void LogFailure(const char* ip, int logonType, Config* cfg);

int get_total_failures(void);

int get_total_blocked(void);

int get_unique_ips(void);

#endif /* DETECTOR_H */
