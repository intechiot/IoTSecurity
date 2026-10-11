#include "IoTSecurity.h"

void IoTSecurity::begin(const char* deviceId, const byte* aesKey, const byte* hmacKey) {
  _enc.begin(aesKey);
  _int.begin(hmacKey);
  _auth.begin(deviceId, hmacKey);
  Serial.println("[IoTSecurity] Initialized");
}

int IoTSecurity::securePacket(const char* payload, byte* output) {
  // 1. Generate random IV
  byte iv[12];
  esp_fill_random(iv, 12);

  // 2. Encrypt payload with AES-256-GCM
  byte tag[16];
  int ctLen = _enc.encrypt(payload, output + 12, iv, tag);

  // 3. Copy IV to the start of the packet
  memcpy(output, iv, 12);

  // 4. Calculate HMAC over the entire packet (IV + Ciphertext)
  byte hmac[32];
  _int.compute(output, 12 + ctLen, hmac);

  // 5. Append GCM tag and HMAC to the packet
  memcpy(output + 12 + ctLen, tag, 16);
  memcpy(output + 12 + ctLen + 16, hmac, 32);

  return 12 + ctLen + 16 + 32; // Total packet length
}
