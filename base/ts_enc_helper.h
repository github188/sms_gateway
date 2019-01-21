
#ifndef __TS_ENC_HELPER__
#define __TS_ENC_HELPER__

#ifdef __cplusplus
extern "C" {
#endif

int ts_db_enc(const char* in, int inlen, char* out, int* outlen);
int ts_db_dec(const char* in, int inlen, char* out, int* outlen);

#ifdef __cplusplus
}
#endif

#endif
