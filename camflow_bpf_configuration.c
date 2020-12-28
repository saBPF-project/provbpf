#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ini.h>
#include <time.h>

#include "camflow_bpf_configuration.h"

#define CONFIG_PATH "/etc/provbpf.ini"

configuration __config;

#define MATCH(s, n) (strcmp(section, s) == 0 && strcmp(name, n) == 0)

/* call back for configuation */
static int handler(void* user, const char* section, const char* name,
                   const char* value)
{
    configuration* pconfig = (configuration*)user;

    time_t now;
    struct tm *local;

    if(MATCH("log", "path")) {
        time(&now);
        local = localtime(&now);
        snprintf(pconfig->log_path, PATH_MAX,
            "%sprovbpf-%d-%02d-%02d_%02d-%02d-%02d.log",
            value,
            local->tm_year + 1900,
            local->tm_mon + 1,
            local->tm_mday,
            local->tm_hour,
            local->tm_min,
            local->tm_sec
        );
    } else if(MATCH("general", "output")) {
        if(strcmp(value, "log")==0) {
            pconfig->output = CF_BPF_LOG;
        } else if(strcmp(value, "null")==0) {
            pconfig->output = CF_BPF_NULL;
        } else if(strcmp(value, "terminal")==0) {
            pconfig->output = CF_BPF_TERMINAL;
        } else {
            printf("\n\nUnknown output: %s\n\n", value);
            return -1;
        }
    } else {
        return 0; /* unknown section/name error */
    }
    return 1;
}

void read_config(void){
  memset(&__config, 0, sizeof(configuration));
  if (ini_parse(CONFIG_PATH, handler, &__config) < 0) {
      printf("Can't load configuration: %s\n", CONFIG_PATH);
      exit(-1);
  }
}
