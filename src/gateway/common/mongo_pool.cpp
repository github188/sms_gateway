#include "mongo_pool.h"
#include <json/json.h>

MongoPool::MongoPool()
{
    m_pMongoPool = NULL;
    m_pMongoUri = NULL;
}

MongoPool::~MongoPool()
{
    if (m_pMongoPool)
    {
        mongoc_client_pool_destroy(m_pMongoPool);
        m_pMongoPool = NULL;
    }
    if (m_pMongoUri)
    {
        mongoc_uri_destroy(m_pMongoUri);
        m_pMongoUri = NULL;
    }
}

int MongoPool::init_db(const char* conf)
{
    if (conf == NULL) return -1;

    //读取配置文件
    cfg_t *cfg = cfg_create();
    if (cfg == NULL)
    {
        LOG_ERROR("cfg_create failed.\n");
        return -1;
    }

    int ret = parse_conf(conf, cfg);
    if (ret < 0)
    {
        LOG_ERROR("parse_conf failed.\n");
        return -1;
    }

    char db_ip[MAX_IP_LEN] = {0};
    int  db_port = 0;
    char db_name[MAX_DB_DOMAIN_LEN] = {0};
    char db_user[MAX_DB_USER_LEN] = {0};
    char db_psw[MAX_DB_PSW_LEN] = {0};
    char db_auth[MAX_DB_PSW_LEN] = {0};
    sec_dict_t *sec = get_section(cfg, "MONGO_DB");
    if (sec != NULL)
    {
        //db
        READ_CONF_STR_MUST(sec, "DB_IP",        db_ip);
        READ_CONF_INT_MUST(sec, "DB_PORT",      db_port);
        READ_CONF_STR_MUST(sec, "DB_NAME",      db_name);
        READ_CONF_STR_MUST(sec, "DB_USER",      db_user);
        READ_CONF_STR_MUST(sec, "DB_PSW",       db_psw);
        READ_CONF_STR_MUST(sec, "DB_AUTH",      db_auth);
    }
    cfg_destroy(cfg);

    char mongo_uri[MAX_DB_CONN_LEN] = {0};
    snprintf(mongo_uri,sizeof(mongo_uri),"mongodb://%s:%s@%s:%d/?authMechanism=%s&authSource=%s",
                                        db_user,
                                        db_psw,
                                        db_ip,
                                        db_port,
                                        db_auth,
                                        db_name);
    // 初始化
    mongoc_init();
    m_pMongoUri = mongoc_uri_new(mongo_uri);
    if (!m_pMongoUri)         return -1;
    // 连接池初始化
    m_pMongoPool = mongoc_client_pool_new(m_pMongoUri);
    if (!m_pMongoPool)      return -1;
    // 设置线程池的最大连接数
    mongoc_client_pool_max_size(m_pMongoPool, 10);
    // 设置appname
    if (!mongoc_client_pool_set_appname(m_pMongoPool, "HttpMongoDB"))
        return -1;

    return 0;
}

bool MongoPool::GetAccessCode(std::string sMessageid, std::string sMobilePhone, std::string &sAccessCode)
{
    if (!m_pMongoPool || sMessageid.empty() || sMobilePhone.empty())
    {
        LOG_ERROR("GetAccessCode function.msgid:%s.mobile:%s.\n",sMessageid.c_str(), sMobilePhone.c_str());
        return false;
    }

    mongoc_client_t *pMongoClient = mongoc_client_pool_pop(m_pMongoPool);
    if (!pMongoClient)      return false;

    time_t tCurUnixTime = time(NULL);
    char sCollectName[15] = { 0x0 };
    // 拼装查询条件BSON
    bson_t *pQueryBson = bson_new();
    BSON_APPEND_UTF8(pQueryBson, "msgid", sMessageid.c_str());
    BSON_APPEND_UTF8(pQueryBson, "mobile", sMobilePhone.c_str());
    // 遍历查询
    bool bFound = false;
    std::string sSmsJson = "";
    for (int queryCount = 0; queryCount <= 3; queryCount++)
    {
        time_t tSmsUnixTime = tCurUnixTime - (queryCount * 24 * 3600);
        struct tm *pSmsUnixTime = localtime(&tSmsUnixTime);
        snprintf(sCollectName, sizeof(sCollectName), "state_%04u%02u%02u", 
                                (unsigned int)(1900 + pSmsUnixTime->tm_year), 
                                (unsigned int)(1 + pSmsUnixTime->tm_mon), 
                                (unsigned int)(pSmsUnixTime->tm_mday));
        mongoc_collection_t *pMongoCollection = mongoc_client_get_collection(pMongoClient, "sms", sCollectName);
        if (!pMongoCollection)      continue;
        mongoc_cursor_t *pMongoCursor = mongoc_collection_find_with_opts(pMongoCollection, pQueryBson, NULL, NULL);
        if (!pMongoCursor)
        {
            mongoc_collection_destroy(pMongoCollection);
            LOG_ERROR("mongo_collection_find_with_opts is failure.CollectName:%s.\n", sCollectName);
            continue;
        }
        const bson_t *pDataBson = NULL;
        if (mongoc_cursor_next(pMongoCursor, &pDataBson))
        {
            char *str = bson_as_canonical_extended_json(pDataBson, NULL);
            sSmsJson = std::string(str);
            bson_free(str);
            mongoc_cursor_destroy(pMongoCursor);
            mongoc_collection_destroy(pMongoCollection);
            LOG_ERROR("Found access code.json:%s.\n", sSmsJson.c_str());
            bFound = true;
            break;
        }
        mongoc_cursor_destroy(pMongoCursor);
        mongoc_collection_destroy(pMongoCollection);
    }
    bson_destroy(pQueryBson);
    mongoc_client_pool_push(m_pMongoPool, pMongoClient);

    if (!bFound)
    {
        LOG_ERROR("Not found access code.msgid:%s.mobile:%s.\n", sMessageid.c_str(), sMobilePhone.c_str());
        return false;
    }
    else
    {
        Json::Reader jsonReader;
        Json::Value jsonValue;
        try
        {
            if (!jsonReader.parse(sSmsJson, jsonValue))
            {
                LOG_ERROR("Parse json failure.json:%s.\n", sSmsJson.c_str());
                return false;
            }
            if (!jsonValue["accesscode"].isString())
            {
                LOG_ERROR("accesscode is not string.json:%s.\n", sSmsJson.c_str());
                return false;
            }
            sAccessCode = jsonValue["accesscode"].asString();
            return true;
        }
        catch (Json::Exception &ex)
        {
            LOG_ERROR("Catch a exception.exception:%s.\n", ex.what());
            return false; 
        }
    }
}