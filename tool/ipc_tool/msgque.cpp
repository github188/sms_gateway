#include <string.h>
#include <errno.h>
#include <stdio.h>
#include "msgque.h"

msgque::msgque()
{
    m_id = -1;
}

msgque::~msgque()
{
}

int msgque::create(const char* pName)
{
    if (m_id >= 0)
    {
        return -1;
    }
    key_t key = ftok(pName, 1);
    if (key == -1)
    {
        return -2;
    }
    int id = msgget(key, IPC_CREAT | IPC_EXCL | 0666);
    if (id == -1)
    {
        return -3;
    }
    m_id = id;
    return id;
}

int msgque::attach(const char* pName)
{
    key_t key = ftok(pName, 1);
    if (key == -1)
    {
        return -1;
    }
    int id = msgget(key, 0666);
    if (id == -1)
    {
        return -2;
    }
    m_id = id;
    return id;
}

int msgque::destroy()
{
    if (m_id < 0)
    {
        return -1;
    }
    if (msgctl(m_id, IPC_RMID, 0) != 0)
    {
        return -2;
    }
    return 0;
}

bool msgque::isConnect()
{
    return (m_id >= 0 ? true : false);
}

int msgque::read(msgform_t *msgp, size_t msgsz, long msgtyp, int msgflg)
{
    int nLen = msgrcv(m_id, msgp, msgsz, msgtyp, msgflg);
    if (nLen <= 0)
    {
        if (errno == EINTR)
        {
            return -1;
        }
        else
        {
            return -2;
        }
    }
    else
    {
        return nLen;
    }
}

int msgque::write(msgform_t *msgp, size_t msgsz, int msgflg)
{
    int nRet = msgsnd(m_id, msgp, msgsz, msgflg);
    if (nRet < 0)
    {
        if (errno == EINTR)
        {
            return -1;
        }
        else
        {
            return -2;
        }
    }
    else
    {
        return 0;
    }
}

uint64_t msgque::getMsgQueLen()
{
    if (m_id < 0)
    {
        return -1;
    }

    struct msqid_ds buf;
    if (msgctl(m_id, IPC_STAT, &buf) != 0)
    {
        return -2;
    }
    return buf.msg_qnum;
}
