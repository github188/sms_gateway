#ifndef __SPACEI_H__
#define __SPACEI_H__

#include "interface.h"


class SpaceiBiz: public HttpBiz
{
public:
    SpaceiBiz();
    virtual ~SpaceiBiz();

    virtual int is_need_to_listen(int& need_to_listen,int& listen_port);
    virtual int channel_req(const char* in_msg,int in_len,char* out_msg,int& out_len); 
    virtual int channel_rsp(dict* wq,
                          const char* in_msg, 
                          int in_len,
                          char *sid,
                          char* out_msg, 
                          int& out_len);
    virtual int send_msg_req(dict* wq,
                             message_packet_t *packet,
                             char *sid,
                             char* out_msg, 
                             int& out_len);
    virtual int timer_process( dict* wq,
                              char *sid,
                              char* out_msg, 
                              int& out_len );
};

#endif
