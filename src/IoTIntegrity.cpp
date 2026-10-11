#include "IoTIntegrity.h"
#include "mbedtls/md.h"

void IoTIntegrity::begin(const byte* hmacKey) {
  memcpy(_hmacKey, hmacKey, 32);
}

void IoTIntegrity::compute(const byte* data, int len, byte* output) {
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
  mbedtls_md_hmac_starts(&ctx, _hmacKey, 32);
  mbedtls_md_hmac_update(&ctx, data, len);
  mbedtls_md_hmac_finish(&ctx, output);
  mbedtls_md_free(&ctx);
}

bool IoTIntegrity::verify(const byte* data, int len, const byte* received) {
  byte computed[32];
  compute(data, len, computed);
  return memcmp(computed, received, 32) == 0;
}
