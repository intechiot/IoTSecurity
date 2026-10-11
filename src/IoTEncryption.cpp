#include "IoTEncryption.h"
#include "mbedtls/gcm.h"

void IoTEncryption::begin(const byte* key) {
  memcpy(_key, key, 32);
}

int IoTEncryption::encrypt(const char* plaintext, byte* ciphertext, 
                            byte* iv, byte* tag) {
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);
  mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, _key, 256);

  int len = strlen(plaintext);
  int ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, len,
                                       iv, 12, NULL, 0,
                                       (const byte*)plaintext, ciphertext,
                                       16, tag);
  mbedtls_gcm_free(&ctx);
  return (ret == 0) ? len : -1;
}

int IoTEncryption::decrypt(const byte* ciphertext, int ctLen, 
                            const byte* iv, const byte* tag, char* output) {
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);
  mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, _key, 256);

  int ret = mbedtls_gcm_auth_decrypt(&ctx, ctLen, iv, 12,
                                      NULL, 0, tag, 16,
                                      ciphertext, (byte*)output);
  mbedtls_gcm_free(&ctx);
  if (ret == 0) output[ctLen] = '\0';
  return (ret == 0) ? ctLen : -1;
}
