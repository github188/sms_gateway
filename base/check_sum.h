#ifndef __CHECK_SUM_H__
#define __CHECK_SUM_H__

#ifdef __cplusplus
extern "C" {
#endif


/**
 * context structure
 */
struct check_context_s
{
    unsigned int total[2];          
    unsigned int state[8];          
    unsigned char buffer[64];   

    unsigned char ipad[64];     
    unsigned char opad[64];   
};
typedef struct check_context_s check_context_t;


int check_sum_init();
void check_sum_destroy();

void check_update(const unsigned char *input, unsigned int ilen );

int check_finish(char* output, int outlen);

/**
 * context reset
 */
void check_reset();



#ifdef __cplusplus
}
#endif

#endif 

