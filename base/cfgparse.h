#ifndef __CFG_PARSE_H__
#define __CFG_PARSE_H__

#ifdef __cplusplus
extern "C" {
#endif

struct sec_dict_s
{
    char *sec;
    dict *hash;
};

typedef struct sec_dict_s sec_dict_t;

struct cfg_s
{
    char filename[TS_MAX_PATH_LEN + 1];
    dlist_t *list;    
};

typedef struct cfg_s cfg_t;


cfg_t * cfg_create();
void cfg_destroy(cfg_t *cfg);

int parse_conf(const char *filename, cfg_t *cfg);

sec_dict_t *get_section(cfg_t *cfg, const char *sec_name);

char* get_value(sec_dict_t* sec, const char* key);

#ifdef __cplusplus
}
#endif

#endif

