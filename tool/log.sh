#!/bin/bash
#删除3天前被访问过的*.log文件
find /home/xjj/message/logs -atime +3 -name "*.log" -print -delete