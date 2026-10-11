#ifndef IOT_ENCRYPTION_H
#define IOT_ENCRYPTION_H

#include <Arduino.h>

class IoTEncryption {
  public:
    void begin(const byte* key);
    int encrypt(const char* plaintext, byte* ciphertext, byte* iv, byte* tag);
    int decrypt(const byte* ciphertext, int ctLen, const byte* iv, 
                const byte* tag, char* output);
  private:
    byte _key[32];
};

#endif
