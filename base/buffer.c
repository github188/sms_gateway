#include <string.h>
#include <stdlib.h>

#include "buffer.h"
#include "logger.h"
#include "compiler.h"

static char *__get_write_ptr(buffer_t *buf);
static const char *__get_read_ptr(buffer_t *buf);
static int __get_data_size(buffer_t *buf);
static int __get_free_size(buffer_t *buf);
static void __set_write_size(buffer_t *buf, int len);
static void __set_read_size(buffer_t *buf, int len);
static int __is_full(buffer_t *buf);


buffer_t *create_buffer(int size)
{
    buffer_t *pbuf = (buffer_t *) malloc(sizeof(buffer_t));
    if (unlikely(NULL == pbuf))
    {
        LOG_ERROR("create_buffer:malloc pbuf failed\n");
        return NULL;
    }
    memset(pbuf, 0, sizeof(buffer_t));

    if (size < BUF_MIN_SIZE || size > BUF_MAX_SIZE)
    {
        pbuf->buf_size = BUF_DEFAULT_SIZE;
    }
    else
    {
        pbuf->buf_size = size;
    }

    pbuf->data = (char *) malloc(pbuf->buf_size);
    if (unlikely(NULL == pbuf->data))
    {
        LOG_ERROR("create_buffer: malloc data failed\n");
        free(pbuf);
        return NULL;
    }

    memset(pbuf->data, 0, sizeof(pbuf->buf_size));

    pbuf->get_write_ptr = __get_write_ptr;
    pbuf->get_read_ptr = __get_read_ptr;

    pbuf->set_write_size = __set_write_size;
    pbuf->set_read_size = __set_read_size;

    pbuf->get_data_size = __get_data_size;
    pbuf->get_free_size = __get_free_size;

    pbuf->is_full = __is_full;

    pbuf->data_len = 0;
    pbuf->ptr = 0;

    return pbuf;
}

void destroy_buffer(buffer_t *buf)
{
    if (NULL != buf)
    {
        if (NULL != buf->data)
        {
            free(buf->data);
            buf->data = NULL;
        }
        free(buf);
    }
}

char *__get_write_ptr(buffer_t *buf)
{
    if (unlikely(NULL == buf))
    {
        LOG_ERROR("__get_write_ptr:point is NULL\n");
        return NULL;
    }

    if ((0 != buf->ptr) && (0 != buf->data_len))
    {
        memmove(buf->data, &(buf->data[buf->ptr]), buf->data_len);
    }

    buf->ptr = 0;
    return &(buf->data[buf->data_len]);
}

const char *__get_read_ptr(buffer_t *buf)
{
    if (unlikely(NULL == buf))
    {
        LOG_ERROR("__get_read_ptr:point is NULL\n");
        return NULL;
    }

    if (0 != (buf->ptr & 3))
    {
        memmove(buf->data, &(buf->data[buf->ptr]), buf->data_len);
        buf->ptr = 0;
    }

    return &(buf->data[buf->ptr]);
}

void __set_write_size(buffer_t *buf, int len)
{
    if (likely(NULL != buf))
    {
        buf->data_len += len;
    }
}

void __set_read_size(buffer_t *buf, int len)
{
    if (likely(NULL != buf))
    {
        buf->ptr += len;
        buf->data_len -= len;
    }
}

int __get_data_size(buffer_t *buf)
{
    if (likely(NULL != buf))
    {
        return buf->data_len;
    }

    return -1;
}

int __get_free_size(buffer_t *buf)
{
    if (likely(NULL != buf))
    {
        return (buf->buf_size - buf->data_len);
    }

    return -1;
}

int __is_full(buffer_t *buf)
{
    if (likely(NULL != buf))
    {
        if (buf->buf_size <= buf->data_len)
            return 1;
    }

    return 0;
}

