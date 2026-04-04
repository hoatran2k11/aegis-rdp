#ifndef CONFIG_H
#define CONFIG_H

#define THRESHOLD 5
#define TIME_WINDOW 60
#define LONG_THRESHOLD 10
#define LONG_WINDOW 300
#define BLOCK_DURATION 600
#define MAX_IP 100
#define MAX_FAILS 100
#define STATS_INTERVAL 30

#define LOG_FILE "aegis-rdp.log"
#define DEFAULT_WHITELIST "127.0.0.1,192.168.1.1"

#define DEBUG_LOG(cfg, fmt, ...) \
    do { if ((cfg) && (cfg)->debug_mode) printf("[DEBUG] " fmt, ##__VA_ARGS__); } while (0)

typedef struct {
    int threshold;
    int time_window;
    int long_threshold;
    int long_window;
    int block_duration;
    int dry_run;
    int debug_mode;
    int stats_interval;
    const char* log_file;
    char* whitelist[MAX_IP + 1];
    int whitelist_count;
} Config;

#endif /* CONFIG_H */
