#ifndef IOT_SECURITY_H
#define IOT_SECURITY_H

#include <Arduino.h>
#include "IoTEncryption.h"
#include "IoTIntegrity.h"
#include "IoTAuthentication.h"

class IoTSecurity {
  public:
    // Initialize with device ID and cryptographic keys
    void begin(const char* deviceId, const byte* aesKey, const byte* hmacKey);

    // Encrypt, authenticate, and package a sensor payload
    int securePacket(const char* payload, byte* output);

    // Verify, authenticate, and decrypt a received packet
    bool verifyPacket(const byte* input, int len, char* payload, char* errorReason);

  private:
    IoTEncryption _enc;
    IoTIntegrity _int;
    IoTAuthentication _auth;
};

#endif
