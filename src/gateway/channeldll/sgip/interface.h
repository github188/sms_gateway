#ifndef __INTERFACE_H__
#define __INTERFACE_H__

#include "biz.h"
#include "public.h"
#include "sgip.h"

using namespace std;

class SgipBiz: public IChannelBiz
{
public:
    SgipBiz();
    virtual ~SgipBiz();

    virtual int init_biz(const char* conf, void* args,channel_conf_t *channel);
    virtual int uninit_biz();
    virtual int is_login_success(int& is_success );
    virtual int is_need_to_listen(int& need_to_listen,int& listen_port);
    virtual int is_packet_complete(const char* msg, int len);
    virtual int channel_login_req(char* out_msg, int& out_len);
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
private:
    int handle_bind_req(sgip_header_t *hdr,const char* body,int len,char* out_msg,int& out_len);
    int handle_deliver_req(sgip_header_t *hdr,const char* body,int len,char* out_msg,int& out_len);
    int handle_report_req(sgip_header_t *hdr,const char* body,int len,char* out_msg,int& out_len);
    int handle_unbind_req(sgip_header_t *hdr,const char* body,int len,char* out_msg,int& out_len);
    
    int handle_bind_rsp(sgip_header_t *hdr,const char* body,int len);
    int handle_submit_rsp(sgip_header_t *hdr,const char* body,int len);
    int handle_trace_rsp(sgip_header_t *hdr,const char* body,int len);
    int handle_unbind_rsp(sgip_header_t *hdr,const char* body,int len);

    uint32_t get_ui_seq();
    unsigned char get_uc_seq();
    int append_response_map(uint32_t seq_id,message_packet_t *req);
    void save_message_response(int type,message_response_t *rsp);
    void save_message_response(uint32_t seq_id,uint32_t result,string msg_id);
    void save_message_report(string sMessageid,
                            string sSrcPhone,
                            string sDestPhone,
                            string sRealStatus,
                            string sConvertStatus);
    void save_message_uplink(string sSrcPhone,string sDestPhone,string sMessageContent);
    bool format_to_json(message_response_t *rsp,string &sRecvJson);
    void do_message_response_timeout();
    
private:
    int                                 m_login_success;   //是否登录成功
    Sgip                                m_sgip;           //协议解析
    map<uint32_t,message_response_t>    m_MessageResponse;
    static uint32_t                     ui_seq_id;
    static unsigned char                uc_seq_id;
    int                                 m_pid;
    int									m_rsp_cnt;
	time_t								m_last_rsp_opr_redis_time;
	int									m_report_cnt;
	time_t								m_last_report_opr_redis_time;
};

#endif
