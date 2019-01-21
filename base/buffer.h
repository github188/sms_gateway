#ifndef __BUFFER_H__
#define __BUFFER_H__

#ifdef __cplusplus
extern "C" {
#endif

enum
{
    BUF_MIN_SIZE = 4096,
    BUF_DEFAULT_SIZE = 4096 * 4,       /*default size 16K*/
    BUF_MAX_SIZE = 1024 * 1024 * 100,  /*max size 100M*/
};


typedef struct buffer_s buffer_t;

struct buffer_s {
    char *data;
    int ptr;
    int data_len;
    int buf_size;

    char *(*get_write_ptr) (buffer_t *buf);
    const char *(*get_read_ptr) (buffer_t *buf);
    int (*get_data_size) (buffer_t *buf);
    int (*get_free_size) (buffer_t *buf);
    void (*set_write_size) (buffer_t *buf, int len);
    void (*set_read_size) (buffer_t *buf, int len);
    int (*is_full) (buffer_t *buf);
};


buffer_t *create_buffer(int size);
void destroy_buffer(buffer_t *buf);

#ifdef __cplusplus
}
#endif

#endif
