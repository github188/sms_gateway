package main

import(
	"github.com/golang/protobuf/proto"
	//gateway.pb.go 的路径
	"./gateway"
	"fmt"
	"net"
	"encoding/binary"
)

const (
	PROTOCOL_HEADER_LENGTH  	=	32
	CMD_HEARTBEAT_REQ  			=	0x00010001 // 心跳请求
    CMD_HEARTBEAT_RSP			=	0x00010002 // 心跳应答
    CMD_SVR_REG_REQ				=	0x00010003 // 服务注册请求
    CMD_SVR_REG_RSP				=	0x00010004 // 服务注册应答
    CMD_CHANNEL_MGR_REQ			= 	0x00020001 // 通道管理请求
    CMD_CHANNEL_MGR_RSP			= 	0x00020002 // 通道管理应答
    CMD_CHANNEL_UPDATE_REQ		= 	0x00020003 // 通道参数变更请求
    CMD_CHANNEL_UPDATE_RSP		= 	0x00020004 // 通道参数变更应答
    CMD_GATEWAY_MSG_SEND_REQ	= 	0x00020005 // 信息发送请求
    CMD_GATEWAY_MSG_SEND_RSP	= 	0x00020006 // 信息发送应答
)

type message_header_t struct{
	version uint32
	length uint32
	command uint32
	vender_id uint32
	market uint32
	is_cksum uint32
	check_sum uint32
	extend uint32
}

func make_header(header *message_header_t,buf []byte)(int){

    var offset int = 0

	var uint32buf [4]byte
	binary.BigEndian.PutUint32(uint32buf[:],header.version)
	copy(buf[offset:],uint32buf[:])

	offset += 4
	binary.BigEndian.PutUint32(uint32buf[:],header.length)
	copy(buf[offset:],uint32buf[:])

	offset += 4
	binary.BigEndian.PutUint32(uint32buf[:],header.command)
	copy(buf[offset:],uint32buf[:])

	offset += 4
	binary.BigEndian.PutUint32(uint32buf[:],header.vender_id)
	copy(buf[offset:],uint32buf[:])

	offset += 4
	binary.BigEndian.PutUint32(uint32buf[:],header.market)
	copy(buf[offset:],uint32buf[:])

	offset += 4
	binary.BigEndian.PutUint32(uint32buf[:],header.is_cksum)
	copy(buf[offset:],uint32buf[:])

	offset += 4
	binary.BigEndian.PutUint32(uint32buf[:],header.check_sum)
	copy(buf[offset:],uint32buf[:])

	offset += 4
	binary.BigEndian.PutUint32(uint32buf[:],header.extend)
	copy(buf[offset:],uint32buf[:])
	
	return offset
}

func parse_header(buf []byte,header *message_header_t){

	header.version = binary.BigEndian.Uint32(buf[0:4])
	header.length = binary.BigEndian.Uint32(buf[4:8])
	header.command = binary.BigEndian.Uint32(buf[8:12])
	header.vender_id = binary.BigEndian.Uint32(buf[12:16])
	header.market = binary.BigEndian.Uint32(buf[16:20])
	header.is_cksum = binary.BigEndian.Uint32(buf[20:24])
	header.check_sum = binary.BigEndian.Uint32(buf[24:28])
	header.extend = binary.BigEndian.Uint32(buf[28:32])
}

func handle_heartbeat_req(inbuf []byte,outbuf []byte,outlen *int)(int){

	heartbeatreq := &gatewaymsg.HeartBeatReq{}
	inData := inbuf[:]
	err := proto.Unmarshal(inData, heartbeatreq)
    if err != nil {
        fmt.Println("Unmarshaling HeartBeatReq error: ", err)
        return -1
	}

	fmt.Printf("heartbeat.[%s]\n",heartbeatreq.GetSID())

	heartbeatrsp := &gatewaymsg.HeartBeatRsp {
		SID: proto.String(heartbeatreq.GetSID()),
	}

	outData, err := proto.Marshal(heartbeatrsp)
    if err != nil {
        fmt.Println("Marshaling HeartBeatRsp error: ", err)
        return -1
	}
	nlen := len(outData)

	var header message_header_t
	header.version = uint32(1)
	header.vender_id = uint32(0)
	header.market = uint32(0)
	header.is_cksum = uint32(0)
	header.check_sum = uint32(0)
	header.extend = uint32(0)
	header.command = uint32(CMD_HEARTBEAT_RSP)
	header.length = uint32(nlen + 32)
	make_header(&header,outbuf)

	copy(outbuf[32:],outData)

	*outlen = 32 + nlen
	return 0
}

func handle_svr_reg_req(inbuf []byte,outbuf []byte,outlen *int)(int){

	svrregreq := &gatewaymsg.SvrRegReq{}
	inData := inbuf[:]
	err := proto.Unmarshal(inData, svrregreq)
    if err != nil {
        fmt.Println("Unmarshaling svr reg req error: ", err)
        return -1
	}

	fmt.Printf("svr reg req.[%s][%s][%s]\n",
					svrregreq.GetSID(),
					svrregreq.GetProtocolType(),
					svrregreq.GetChannelId())

	svrregrsp := &gatewaymsg.SvrRegRsp {
		SID: proto.String(svrregreq.GetSID()),
		RetCode: proto.Int(0),
	}

	outData, err := proto.Marshal(svrregrsp)
    if err != nil {
        fmt.Println("Marshaling svr reg rsp error: ", err)
        return -1
	}
	nlen := len(outData)

	var header message_header_t
	header.version = uint32(1)
	header.vender_id = uint32(0)
	header.market = uint32(0)
	header.is_cksum = uint32(0)
	header.check_sum = uint32(0)
	header.extend = uint32(0)
	header.command = uint32(CMD_HEARTBEAT_RSP)
	header.length = uint32(nlen + 32)
	make_header(&header,outbuf)

	copy(outbuf[32:],outData)

	*outlen = 32 + nlen
	return 0
}

func handle_channel_update_rsp(inbuf []byte,outbuf []byte,outlen *int)(int){

	
	return 0
}

func Server(conn net.Conn){
	defer conn.Close()
	for{
		ret := 0
		inbuf := make([]byte,1024*64)
		inlen,err := conn.Read(inbuf)
		if err != nil{
			fmt.Printf("recv msg fail.[%s]\n",err.Error())
			break;
		}

		var header message_header_t
		parse_header(inbuf[0:PROTOCOL_HEADER_LENGTH],&header)

		outbuf := make([]byte,1024*64)
		outlen := 0

		switch header.command {
		case CMD_HEARTBEAT_REQ:
			ret = handle_heartbeat_req(inbuf[PROTOCOL_HEADER_LENGTH:inlen],
									outbuf[:],&outlen)
		case CMD_SVR_REG_REQ:
			ret = handle_svr_reg_req(inbuf[PROTOCOL_HEADER_LENGTH:inlen],
									outbuf[:],&outlen)
		case CMD_CHANNEL_UPDATE_RSP:
			ret = handle_channel_update_rsp(inbuf[PROTOCOL_HEADER_LENGTH:inlen],
									outbuf[:],&outlen)
		}
		if(ret == 0){
			conn.Write(outbuf[0:outlen])
		}
	}
}

func main(){
	listen,err := net.Listen("tcp","127.0.0.1:8001")
	if err != nil {
		fmt.Printf("listen tcp fail.[%s]\n",err.Error())
		return
	}
	fmt.Println("listen tcp ok.waiting for client connect!")
	for{
		conn,err := listen.Accept()
		if err != nil{
			fmt.Printf("accept client fail.[%s]\n",err.Error())
			continue
		}
		fmt.Printf("client[%s] is connect.\n",conn.RemoteAddr().String())
		go Server(conn)
	}
}

