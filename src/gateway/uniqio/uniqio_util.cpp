#include "uniqio_util.h"

gateway_info_t* get_gateway_data(dict* wq,const char *key)
{
    if ( wq == NULL || key == NULL )
    {
        return NULL;
    }

    int len = strlen(key);
    if (len >= MAX_PATH_LEN )
    {
        return NULL;
    }

    char channelid[MAX_PATH_LEN] = {0};
    strcpy(channelid, key);

    return (gateway_info_t*)dict_fetch_value(wq,channelid,sizeof(channelid));
}

int delete_gateway_data(dict* wq,const char *key)
{
    gateway_info_t* s = get_gateway_data(wq,key);
    if ( s == NULL )
    {
        LOG_DEBUG("the key %s is not in g_gateway_dict.\n", key);
        return 0;
    }

    int ret = dict_delete(wq,s->channel_id,sizeof(s->channel_id));
    if (ret != DICT_OK)
    {
        LOG_ERROR("dict_delete failed.\n");
        return - 1;
    }

    LOG_DEBUG("delete key = %s from g_gateway_dict.\n", key);

    return 0;
}

int insert_gateway_data(dict* wq,gateway_info_t &data)
{
    char* d_key = (char*)alloc_key(wq, sizeof(data.channel_id));
    gateway_info_t* d_val = (gateway_info_t*)alloc_val(wq, sizeof(gateway_info_t));

    memcpy(d_key, data.channel_id, sizeof(data.channel_id));
    memcpy(d_val, &data, sizeof(gateway_info_t));

    int ret = dict_add(wq, d_key,sizeof(data.channel_id), d_val, sizeof(gateway_info_t));

    if (ret != DICT_OK)
    {
        LOG_ERROR("dict_add failed.");
        free(d_key);
        free(d_val);

        return -1;
    }
    return 0;
}
