#ifndef CONFIG_LOADER_H
#define CONFIG_LOADER_H

#include "config.h"

int load_config_from_ini(Config* cfg, const char* filename);
void ensure_config_exists(const char* filename);

#endif /* CONFIG_LOADER_H */
