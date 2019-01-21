#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>     
#include <netinet/in.h>     
#include <net/if_arp.h> 
#include <sys/ioctl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "ts_sid.h"
#include "logger.h"
#include "util.h"
#include "compiler.h"
#include "ts_time.h"

static int64_t get_mac_address();

int64_t get_mac_address()
{
    int num_of_interface;   
    struct ifreq req[16];   
    struct ifconf ifc;          
    ifc.ifc_len = sizeof(req);         
    ifc.ifc_buf = (caddr_t)req;         
    int64_t mac_address = -1;

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0)
    {
        LOG_ERROR("socket failed.%s\n", strerror(errno));
        return -1;
    }

    if(!ioctl(sockfd, SIOCGIFCONF, (char*)&ifc))      
    {           
        num_of_interface = ifc.ifc_len/sizeof(struct ifreq);             
        /*
        LOG_DEBUG("interface num = %d\n", num_of_interface);
        */

        for(int index = 0; index < num_of_interface; index++)
        {
            /*
            LOG_DEBUG("interface name:%s\n", req[index].ifr_name);
            */

            if(strncmp(req[index].ifr_name, "lo", 2) == 0)
            {
                //ignore the lo interface
                /*
                LOG_DEBUG("ignore the lo interface.\n");
                */
                continue;
            }

            if((ioctl(sockfd, SIOCGIFFLAGS, &req[index])) == -1)               
            {                   
                LOG_WARN("ioctl SIOCGIFFLAGS failed. %s\n", strerror(errno));
                continue;
            } 

            if(!(req[index].ifr_flags & IFF_UP))         
            {
                //ignore the interface if it's status is down.
                /*
                LOG_DEBUG("ignore the interface if it's status is down\n");
                */
                continue;
            }

            //Get HWaddr of the interface                  
            if(!(ioctl(sockfd, SIOCGIFHWADDR, &req[index])))                 
            {      
                struct sockaddr hwaddr = req[index].ifr_hwaddr;
                mac_address = *(int64_t*)hwaddr.sa_data;
                /*
                LOG_DEBUG("original mac:%lx\n", mac_address);
                */
                mac_address = ntohl64(mac_address);
                if(0 == (mac_address & 0xffff))
                {
                    mac_address = mac_address >> 16;
                    mac_address &= 0x0000ffffffffffff;
                }
                /*
                LOG_DEBUG("after exchange:%lx\n", mac_address);
                */
                break;
            }
            else
            {
                LOG_WARN("ioctl SIOCGIFHWADDR failed. %d %s\n", errno, strerror(errno));
            }
        }
    }

    return mac_address;
}





int get_sid_two(int loginid, int64_t *sid_first, int64_t *sid_second)
{
    if(unlikely(NULL == sid_first || NULL == sid_second))
    {
        return -1;
    }

    static int64_t mac = -1;
    static int pid = -1;
    if(mac == -1)
        mac = get_mac_address();

    if(pid == -1)
    {
        pid = getpid();
        srand((unsigned int)pid);
    }

    if(0 == loginid)
        loginid = rand();

    *sid_first = mac << 32;
    *sid_first &= 0xffffffff00000000;
    *sid_first |= loginid;

    *sid_second = get_utc_microseconds();
    *sid_second = *sid_second << 12;
    int arand = rand() % 4096;
    *sid_second |= arand;

    return 0;
}

int get_sid_one(int loginid, ts_sid_t *sid)
{
    if(unlikely(NULL == sid))
    {
        return -1;
    }

    return get_sid_two(loginid, &sid->sid_first, &sid->sid_second);
}

int get_sid_str(int loginid, char* dest, int dest_len)
{
    if(unlikely(NULL == dest || dest_len < 32))
        return -1;

    int64_t sid_first = -1;
    int64_t sid_second = -1;

    if(get_sid_two(loginid, &sid_first, &sid_second) != 0)
        return -1;

    snprintf(dest, dest_len, "%016lx", sid_first);
    snprintf(dest + 16, dest_len - 16, "%016lx", sid_second);

    return 0;
}




