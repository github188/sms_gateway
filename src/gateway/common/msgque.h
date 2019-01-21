#ifndef __MSGQUE_H__
#define __MSGQUE_H__

#include <sys/types.h>
#include <sys/msg.h>
#include "public.h"

typedef struct _msgform
{
    long mtype;
    long data_len;
    char mtext[1024*1024*5]; //5m
}msgform_t;

class msgque
{
public:
    msgque();
    virtual ~msgque();
public:
    int create(const char* pName);
    int attach(const char* pName);
    int destroy();
    bool isConnect();
    uint64_t getMsgQueLen();
public:
    int read(msgform_t *msgp, size_t msgsz, long msgtyp, int msgflg);
    int write(msgform_t *msgp, size_t msgsz, int msgflg);
private:
    int m_id;
};

#endif
