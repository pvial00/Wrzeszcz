#ifndef wrzeszcz_h__
#define wrzeszcz_h__

unsigned char * crypt(unsigned char *data, unsigned char *key, unsigned char *nonce, long datalen, int keylen);

unsigned char * wrzeszcz_kdf(unsigned char *password, unsigned char *key, unsigned char *salt, int iterations, int keylen);

unsigned char * wrzeszcz_random (unsigned char *buf, int num_bytes);

#endif 
