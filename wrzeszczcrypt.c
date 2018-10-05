#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wrzeszcz.c"

int k[256] = {0};
int s[256];
int j = 0;
int temp;

void keysetup(unsigned char *key, unsigned char *nonce, int keylen) {
    int c;
    int diff = 256 - keylen;
    for (c = 0; c < 256; c++) {
        s[c] = c; 
    }
    for (c=0; c < keylen; c++) {
        k[c] = (k[c] + key[c]) & 0xff;
        j = (j + k[c]) & 0xff; }
    for (c = 0; c < diff; c++) {
        k[c+keylen] = (k[c] + k[(c + 1) % diff]  + j + s[j]) & 0xff;
        j = (j + k[c % diff] + c) & 0xff; 
        temp = s[c & 0xff];
	s[c & 0xff] = s[j];
	s[j] = temp; }
    for (c = 0; c < 768; c++) {
        k[c & 0xff] = (k[c & 0xff] + j) & 0xff;
        j = (j + k[c & 0xff] + c) & 0xff; }
        temp = s[c & 0xff];
	s[c & 0xff] = s[j];
	s[j] = temp;
    for (c = 0; c < sizeof(nonce); c++) {
        k[c] = (k[c] + nonce[c]) & 0xff;
        j = (j + k[c]) & 0xff; }
    for (c = 0; c < 768; c++) {
        k[c & 0xff] = (k[c & 0xff] + j) & 0xff;
        j = (j + k[c & 0xff] + c) & 0xff; 
        temp = s[c & 0xff];
	s[c & 0xff] = s[j];
	s[j] = temp; }

}

void usage() {
    printf("wrzeszcz <encrypt/decrypt> <input file> <output file> <password>\n");
    exit(0);
}

int main(int argc, char *argv[]) {
    FILE *infile, *outfile, *randfile;
    char *in, *out, *mode;
    unsigned char *data = NULL;
    unsigned char *buf = NULL;
    int x = 0;
    int i = 0;
    int output;
    int ch;
    int buflen = 131072;
    int keylen = 5;
    int bsize;
    unsigned char *key[keylen];
    unsigned char *password;
    int nonce_length = 8;
    int iterations = 10000;
    unsigned char *salt = "WrzeszczCipher";
    unsigned char *nonce[nonce_length];
    unsigned char block[buflen];
    if (argc != 5) {
        usage();
    }
    mode = argv[1];
    in = argv[2];
    out = argv[3];
    password = argv[4];
    infile = fopen(in, "rb");
    fseek(infile, 0, SEEK_END);
    long fsize = ftell(infile);
    fseek(infile, 0, SEEK_SET);
    outfile = fopen(out, "wb");
    int c = 0;
    int b;
    if (strcmp(mode, "encrypt") == 0) {
        long blocks = fsize / buflen;
        long extra = fsize % buflen;
        if (extra != 0) {
            blocks += 1;
        }
	wrzeszcz_random(nonce, nonce_length);
        fwrite(nonce, 1, nonce_length, outfile);
	wrzeszcz_kdf(password, key, salt, iterations, keylen);
        keysetup(key, nonce, keylen);
        for (int d = 0; d < blocks; d++) {
            fread(block, buflen, 1, infile);
            bsize = sizeof(block);
            for (b = 0; b < bsize; b++) {
                k[c] = (k[c] + k[(c + 1) & 0xff] + j) & 0xff;
                j = (j + k[c] + c) & 0xff;
		output = s[j] ^ k[c];
                block[b] = block[b] ^ output;
                c = (c + 1) & 0xff;
		temp = s[c];
		s[c] = s[j];
		s[j] = temp;
            }
            if (d == (blocks - 1) && extra != 0) {
                bsize = extra;
            }
            fwrite(block, 1, bsize, outfile);
        }
    }
    else if (strcmp(mode, "decrypt") == 0) {
        long blocks = (fsize - nonce_length) / buflen;
        long extra = (fsize - nonce_length) % buflen;
        if (extra != 0) {
            blocks += 1;
        }
        fread(nonce, 1, nonce_length, infile);
	wrzeszcz_kdf(password, key, salt, iterations, keylen);
        keysetup(key, nonce, keylen);
        for (int d = 0; d < blocks; d++) {
            fread(block, buflen, 1, infile);
            bsize = sizeof(block);
            for (b = 0; b < bsize; b++) {
                k[c] = (k[c] + k[(c + 1) & 0xff] + j) & 0xff;
                j = (j + k[c] + c) & 0xff;
		output = s[j] ^ k[c];
                block[b] = block[b] ^ output;
                c = (c + 1) & 0xff;
		temp = s[c];
		s[c] = s[j];
		s[j] = temp;
            }
            if ((d == (blocks - 1)) && extra != 0) {
                bsize = extra;
            }
            fwrite(block, 1, bsize, outfile);
        }
    }
    fclose(infile);
    fclose(outfile);
    return 0;
}
