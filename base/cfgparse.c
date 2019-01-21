#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

#include "dict.h"
#include "dlist.h"
#include "logger.h"
#include "compiler.h"
#include "cfgparse.h"

enum
{
    CFG_KEY_LEN = 128,
    CFG_VAL_LEN = 4096,
};

/*private API*/
static void clear_dlist(dlist_t *list);
static int parse_line(const char *line, cfg_t *cfg);
static dict *parse_section(const char *line, dlist_t *list);
static int parse_comm(const char *line, dict *d);
static void get_key_and_value(const char *line, char ch, char *key, char *value);
static void trim(char *str);


cfg_t *cfg_create()
{
    cfg_t *cfg =(cfg_t*)malloc(sizeof(cfg_t));
    if(unlikely(NULL == cfg))
    {
        LOG_ERROR("in cfg_create, malloc failed.\n");
        return NULL;
    }

    cfg->list = dlist_create();
    if(unlikely(NULL == cfg->list))
    {
        LOG_ERROR("create dlist failed.\n");
        free(cfg);
        return NULL;
    }

    return cfg;
}

void cfg_destroy(cfg_t *cfg)
{
    if(cfg)
    {
        if(cfg->list)
            clear_dlist(cfg->list);

        free(cfg);
    }
}


sec_dict_t *get_section(cfg_t *cfg, const char *sec_name)
{
    dlist_t *list = cfg->list;
    dlist_entry_t *item = NULL;
    list_for_each(item, list->head, list->tail)
    {
        sec_dict_t *sd = (sec_dict_t *) item->data;
        if (sd && (strlen(sec_name) == strlen(sd->sec)) && (0 == strcmp(sd->sec, sec_name)))
        {
            return sd;
        }
    }

    return NULL;
}

char* get_value(sec_dict_t *sec, const char* key)
{
    return (char*)dict_fetch_value(sec->hash, key, strlen(key));
}

int parse_conf(const char *filename, cfg_t *cfg)
{
    strncpy(cfg->filename, filename, TS_MAX_PATH_LEN);

    FILE *fp = fopen(filename, "r");
    if (NULL == fp)
    {
        warning("open file faied, file = %s err = %s\n", filename,
                strerror(errno));
        return -1;
    }

    char *line = NULL;
    size_t len = 0;
    ssize_t ret = 0;

    while ((ret = getline(&line, &len, fp)) != -1)
    {

        if ('#' == line[0] || '\n' == line[0] || '\0' == line[0])
            continue;
        if (parse_line(line, cfg) < 0)
        {
            warning("parse line failed, line = %s\n", line);
            return -1;
        }
    }
    free(line);

    fclose(fp);

    return 0;
}

void clear_dlist(dlist_t *list)
{
    dlist_entry_t *item;
    for(item = list->head->next; item != list->tail; item = item->next)
    {
        sec_dict_t *sd = (sec_dict_t*) item->data;
        if (sd)
        {
            free(sd->sec);
            dict_release(sd->hash);
            free(sd);
            sd = NULL;
        }
    }

    dlist_delete_all(list, DLIST_DONOT_FREE_DATA);
    dlist_destroy(list);
}

int parse_line(const char *line, cfg_t *cfg)
{
    static struct dict *s;

    if ('[' == line[0])
    {
        s = parse_section(line, cfg->list);
        if (NULL == s)
        {
            return -1;
        }

        return 0;
    }

    if (parse_comm(line, s) < 0)
    {
        LOG_ERROR("parse_line: failed, line = %s\n", line);
        return -1;
    }

    return 0;
}

struct dict *parse_section(const char *line, dlist_t *list)
{
    if ('[' != line[0])
        return NULL;

    char *p, *tail = NULL;

    p = (char *) line;

    while (*p)
    {
        if (*p == ']')
        {
            tail = p;
            break;
        }

        p++;
    }

    if (NULL == tail)
    {
        LOG_WARN("sytle error, %s\n", line);
        return NULL;
    }

    p = (char *) line;
    p++;
    size_t len = tail - p;
    if (0 >= len)
    {
        LOG_WARN("empty section name\n");
        return NULL;
    }

    sec_dict_t *sd = (sec_dict_t*) malloc(sizeof(sec_dict_t));
    if (NULL == sd)
    {
        LOG_ERROR("parse_section: malloc sd failed\n");
        return NULL;
    }

    sd->sec = (char *) malloc(len + 1);
    if (NULL == sd->sec)
    {
        LOG_ERROR("in parse_section, malloc failed.\n");
        free(sd);
        return NULL;
    }

    sd->hash = dict_create(NULL);
    if (NULL == sd->hash)
    {
        LOG_ERROR("in parse_section, dict_create failed.\n");
        free(sd->sec);
        free(sd);
        return NULL;
    }

    strncpy(sd->sec, p, len);
    sd->sec[len] = '\0';
    dlist_insert(list, sd);

    return sd->hash;
}

int parse_comm(const char *line, dict *d)
{
    char *key = (char *) malloc(CFG_KEY_LEN);
    char *value = (char *) malloc(CFG_VAL_LEN);
    memset(key, 0, CFG_KEY_LEN);
    memset(value, 0, CFG_VAL_LEN);

    get_key_and_value(line, '=', key, value);

    trim(key);
    trim(value);

    if ('\0' == key[0] || '\0' == value[0])
    {
        LOG_WARN("line parse failed, line = %s\n", line);
        free(key);
        free(value);
        return -1;
    }

    int retval = dict_add(d, key, strlen(key), value, strlen(value));
    if (DICT_OK != retval)
    {
        LOG_WARN("dict_add failed, key = %s\n", key);
    }

    return 0;
}

void get_key_and_value(const char *line, char ch, char *key, char *value)
{
    char *p = (char *) line;
    char *pos = (char *) line;
    char *end = (char *) line + strlen(line);

    int len = 0;
    while (pos < end)
    {
        if (*pos == ch)
        {
            break;
        }

        pos++;
    }

    len = pos - p;
    if (len > 0)
    {
        len = len > CFG_KEY_LEN ? CFG_KEY_LEN : len;
        strncpy(key, p, len);
    }

    len = end - (pos + 1);
    if (len > 0)
    {
        len = len > CFG_VAL_LEN ? CFG_VAL_LEN : len;
        strncpy(value, pos + 1, len);
    }
}

void trim(char *str)
{
    char *p = str;
    int n_space = 0;

    while ('\0' != *p && isspace(*p))
    {
        p++;
        n_space++;
    }

    if (p != str)
    {
        int move_len = strlen(str) - n_space;
        memmove(str, p, move_len);
        str[move_len] = '\0';
    }

    size_t len = strlen(str);

    p = str + len - 1;
    char *p1 = p;

    while (p >= str)
    {
        if (!isspace(*p))
        {
            if (p != p1)
                *(p + 1) = '\0';

            return;
        }

        --p;
    }

    *str = '\0';
}



