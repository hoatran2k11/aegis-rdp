#include "include/config_loader.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

static char g_log_file_buffer[256];
static char g_whitelist_storage[MAX_IP][46];
static char* g_whitelist_ptrs[MAX_IP + 1];

static char* trim(char* str) {
    if (!str) return str;
    while (*str && isspace((unsigned char)*str)) str++;
    char* end = str + strlen(str) - 1;
    while (end >= str && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }
    return str;
}

static int string_iequals(const char* a, const char* b) {
    if (!a || !b) return 0;
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
        a++; b++;
    }
    return *a == '\0' && *b == '\0';
}

static int parse_bool(const char* value, int* out) {
    if (!value || !out) return 0;
    if (string_iequals(value, "true") || string_iequals(value, "1") || string_iequals(value, "yes") || string_iequals(value, "on")) {
        *out = 1;
        return 1;
    }
    if (string_iequals(value, "false") || string_iequals(value, "0") || string_iequals(value, "no") || string_iequals(value, "off")) {
        *out = 0;
        return 1;
    }
    return 0;
}

static void reset_whitelist(Config* cfg) {
    if (!cfg) return;
    cfg->whitelist_count = 0;
    for (int i = 0; i < MAX_IP + 1; i++) {
        cfg->whitelist[i] = NULL;
    }
}

static void add_whitelist_entry(Config* cfg, const char* ip) {
    if (!cfg || !ip || cfg->whitelist_count >= MAX_IP) return;
    char trimmed[46];
    strncpy_s(trimmed, sizeof(trimmed), ip, _TRUNCATE);
    char* clean_ip = trim(trimmed);
    if (*clean_ip == '\0') return;

    for (int i = 0; i < cfg->whitelist_count; i++) {
        if (cfg->whitelist[i] && strcmp(cfg->whitelist[i], clean_ip) == 0) {
            return;
        }
    }

    size_t index = cfg->whitelist_count;
    strncpy_s(g_whitelist_storage[index], sizeof(g_whitelist_storage[index]), clean_ip, _TRUNCATE);
    g_whitelist_ptrs[index] = g_whitelist_storage[index];
    cfg->whitelist[index] = g_whitelist_ptrs[index];
    cfg->whitelist_count++;
    cfg->whitelist[cfg->whitelist_count] = NULL;
}

static void parse_whitelist_value(Config* cfg, const char* value) {
    if (!cfg || !value) return;
    char buffer[512];
    strncpy_s(buffer, sizeof(buffer), value, _TRUNCATE);
    char* token = strtok(buffer, ",");
    while (token) {
        char* trimmed = trim(token);
        add_whitelist_entry(cfg, trimmed);
        token = strtok(NULL, ",");
    }
}

static void apply_default_whitelist(Config* cfg) {
    reset_whitelist(cfg);
    parse_whitelist_value(cfg, DEFAULT_WHITELIST);
}

int load_config_from_ini(Config* cfg, const char* filename) {
    if (!cfg || !filename) return 0;

    apply_default_whitelist(cfg);
    cfg->log_file = LOG_FILE;

    FILE* file = fopen(filename, "r");
    if (!file) {
        return 0;
    }

    char line[512];
    char section[64] = "";
    int whitelist_section_seen = 0;

    while (fgets(line, sizeof(line), file)) {
        char* text = trim(line);
        if (*text == '\0' || *text == ';' || *text == '#') continue;

        if (*text == '[') {
            char* endBracket = strchr(text, ']');
            if (!endBracket) continue;
            *endBracket = '\0';
            strncpy_s(section, sizeof(section), text + 1, _TRUNCATE);
            for (char* p = section; *p; ++p) *p = (char)tolower((unsigned char)*p);
            continue;
        }

        char* equals = strchr(text, '=');
        if (!equals) continue;

        *equals = '\0';
        char* key = trim(text);
        char* value = trim(equals + 1);
        if (*key == '\0' || *value == '\0') continue;

        if (string_iequals(section, "detection")) {
            if (string_iequals(key, "threshold")) {
                int parsed = atoi(value);
                if (parsed > 0) cfg->threshold = parsed;
            } else if (string_iequals(key, "time_window")) {
                int parsed = atoi(value);
                if (parsed > 0) cfg->time_window = parsed;
            } else if (string_iequals(key, "long_threshold")) {
                int parsed = atoi(value);
                if (parsed > 0) cfg->long_threshold = parsed;
            } else if (string_iequals(key, "long_window")) {
                int parsed = atoi(value);
                if (parsed > 0) cfg->long_window = parsed;
            }
        } else if (string_iequals(section, "action")) {
            if (string_iequals(key, "block_duration")) {
                int parsed = atoi(value);
                if (parsed > 0) cfg->block_duration = parsed;
            } else if (string_iequals(key, "dry_run")) {
                int boolValue;
                if (parse_bool(value, &boolValue)) cfg->dry_run = boolValue;
            }
        } else if (string_iequals(section, "logging")) {
            if (string_iequals(key, "log_file")) {
                strncpy_s(g_log_file_buffer, sizeof(g_log_file_buffer), value, _TRUNCATE);
                cfg->log_file = g_log_file_buffer;
            } else if (string_iequals(key, "debug_mode")) {
                int boolValue;
                if (parse_bool(value, &boolValue)) cfg->debug_mode = boolValue;
            }
        } else if (string_iequals(section, "whitelist")) {
            if (!whitelist_section_seen) {
                reset_whitelist(cfg);
                whitelist_section_seen = 1;
            }
            parse_whitelist_value(cfg, value);
        }
    }

    fclose(file);
    return 1;
}
