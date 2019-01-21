#include "send_util.h"
#include "send_db.h"
#include <json/json.h>

channel_reserved_t* get_channel_reserved_data(dict* wq,int key)
{
    if ( wq == NULL )
    {
        return NULL;
    }

    return (channel_reserved_t*)dict_fetch_value(wq, &key, sizeof(int));
}

int delete_channel_reserved_data(dict* wq,int key)
{
    channel_reserved_t* s = get_channel_reserved_data(wq, key);
    if (s == NULL)
    {
        LOG_DEBUG("the key %d is not in g_channel_dict.\n", key);
        return 0;
    }

    int ret = dict_delete(wq, &key, sizeof(int));
    if (ret != DICT_OK)
    {
        LOG_ERROR("dict_delete failed.\n");
        return - 1;
    }

    LOG_DEBUG("delete key = %d from g_channel_dict.\n", key);

    return 0;
}

int insert_channel_reserved_data(dict* wq,channel_reserved_t &data)
{
    int* d_key = (int*)alloc_key(wq, sizeof(int));
    channel_reserved_t* d_val = (channel_reserved_t*)alloc_val(wq, sizeof(channel_reserved_t));

    *d_key = data.fd;
    memcpy(d_val, &data, sizeof(channel_reserved_t));

    int ret = dict_add(wq, d_key, sizeof(int), d_val, sizeof(channel_reserved_t));

    if (ret != DICT_OK)
    {
        LOG_ERROR("dict_add failed.");
        free(d_key);
        free(d_val);

        return -1;
    }
    return 0;
}

int handle_channel_status(string channel_id,int status)
{
    Json::FastWriter jsonWriter;
    Json::Value jsonValue;
    jsonValue["channel_id"] = Json::Value(channel_id);
    jsonValue["channel_status"] = Json::Value(status);
    string channel_status = jsonWriter.write(jsonValue);
    save_channel_status(channel_status);
    return 0;
}
