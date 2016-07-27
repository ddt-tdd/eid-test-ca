#include "signdata.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#define PHOTO_HASH_TAG 0x11

void* set_photohash(struct derdata* idfile, char* photofn, int hashnid) {
	char tag, length = 0;
	uint8_t* ptr = (char*)idfile->data;
	struct derdata* rv = idfile;
	const EVP_MD *hash = (hashnid == NID_sha1 ? EVP_sha1() : EVP_sha256());
	int hashlen = EVP_MD_size(hash);

	do {
		ptr += length;
		tag = *ptr++; length = *ptr++;
	} while(tag != PHOTO_HASH_TAG);
	if(length != hashlen) {
		int offset = (ptr - (idfile->data));
		rv = derdata_new(idfile->len + (hashlen - length));
		memcpy(rv->data, idfile->data, idfile->len);
		memmove(rv->data + offset + hashlen, rv->data + offset + length, idfile->len - offset - length);
		ptr = (char*)(rv->data + offset);
		ptr[-1] = (uint8_t)hashlen;

		FILE* f = fopen(photofn, "rb");
		fseek(f, 0, SEEK_END);
		size_t plen = ftell(f);
		fseek(f, 0, SEEK_SET);
		struct derdata *photo = derdata_new(plen);
		fread(photo->data, plen, 1, f);
		fclose(f);
		EVP_MD_CTX ctx;
		EVP_DigestInit(&ctx, hash);
		EVP_DigestUpdate(&ctx, photo->data, plen);
		EVP_DigestFinal(&ctx, ptr, NULL);
		derdata_destroy(photo);
		derdata_destroy(idfile);
	}
	return rv;
}

int main(int argc, char** argv) {
	assert(argc >= 7);

	char* id_fn = argv[1];
	char* sigout_fn = argv[2];
	char* photo_fn = argv[3];
	char* address_fn = argv[4];
	char* addout_fn = argv[5];
	char* privkey_fn = argv[6];
	int hashnid;
	if(argc > 7) {
		switch(argv[7][0]) {
			case '1':
				hashnid = NID_sha1;
				break;
			case '2':
				hashnid = NID_sha256;
				break;
			default:
				fprintf(stderr, "E: Unknown hash requested");
				exit(EXIT_FAILURE);
		}
	} else {
		hashnid = NID_sha1;
	}

	FILE* f = fopen(privkey_fn, "rb");
	EVP_PKEY *evp_key = PEM_read_PrivateKey(f, NULL, NULL, NULL);
	if(!evp_key) {
		ERR_load_crypto_strings();
		unsigned long e = ERR_get_error();
		printf("error %ld: %s\n", e, ERR_error_string(e, NULL));
		exit(EXIT_FAILURE);
	}
	fclose(f);

	RSA *key_id = EVP_PKEY_get1_RSA(evp_key);
	RSA *key_address = EVP_PKEY_get1_RSA(evp_key);

	f = fopen(id_fn, "rb");
	fseek(f, 0, SEEK_END);
	size_t size = ftell(f);
	fseek(f, 0, SEEK_SET);
	struct derdata* id = derdata_new(size);
	fread(id->data, size, 1, f);
	fclose(f);

	f = fopen(address_fn, "rb");
	fseek(f, 0, SEEK_END);
	size = ftell(f);
	fseek(f, 0, SEEK_SET);
	struct derdata* address = derdata_new(size);
	fread(address->data, size, 1, f);
	fclose(f);

	id = set_photohash(id, photo_fn, hashnid);

	struct derdata* id_sign = sign_id(id, hashnid, key_id);
	struct derdata* address_sign = sign_address(id_sign, address, hashnid, key_address);

	RSA_free(key_id);
	RSA_free(key_address);

	f = fopen(sigout_fn, "wb");
	fwrite(id_sign->data, id_sign->len, 1, f);
	fclose(f);

	f = fopen(addout_fn, "wb");
	fwrite(address_sign->data, address_sign->len, 1, f);
	fclose(f);
}
