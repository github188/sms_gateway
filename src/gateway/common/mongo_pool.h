#ifndef __MONGO_POOL_H__
#define __MONGO_POOL_H__

#include <bson/bson.h>
#include <mongoc/mongoc.h>
#include "public.h"

class MongoPool
{
public:
    MongoPool();
    ~MongoPool();
    int init_db(const char* conf);
    bool GetAccessCode(std::string sMessageid, std::string sMobilePhone, std::string &sAccessCode);
private:
    mongoc_client_pool_t *m_pMongoPool;
    mongoc_uri_t *m_pMongoUri;
};

#endif