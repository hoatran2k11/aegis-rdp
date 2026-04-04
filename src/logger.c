#include "include/logger.h"
#include <stdio.h>
#include <time.h>

void log_to_file(const char* message, const Config* cfg) {
    if (!message || !cfg) return;
    
    FILE* f = fopen(cfg->log_file, "a");
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
