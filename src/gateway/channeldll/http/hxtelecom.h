#ifndef __HXTELECOM_H__
#define __HXTELECOM_H__

#include "interface.h"

class HxTelecomBiz: public HttpBiz
{
public:
    HxTelecomBiz();
    virtual ~HxTelecomBiz();
    
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
private:
    int handle_submit_rsp(uint32_t seq_id,const char* body,int len);
    int handle_report_rsp(uint32_t seq_id,const char* body,int len);
    int handle_uplink_rsp(uint32_t seq_id,const char* body,int len);
private:
    static int random;
};

#endif
