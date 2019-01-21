#ifndef __SIM_H__
#define __SIM_H__

#include "sim_struct.h"

//建立守护进程
void daemonlize();

//打印使用方法
void usage();

//版本信息
void version();

//注册信号
int reg_signal();

//加载配置文件
int load_config();

//初始化日志
int init_log();
void uninit_log();

// 初始化网络连接
int init_net();
void uninit_net();

//主要处理过程
int main_process();


#endif 
