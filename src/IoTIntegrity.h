#ifndef IOT_INTEGRITY_H
#define IOT_INTEGRITY_H

#include <Arduino.h>

class IoTIntegrity {
  public:
    void begin(const byte* hmacKey);
    void compute(const byte* data, int len, byte* output);
    bool verify(const byte* data, int len, const byte* received);
  private:
    byte _hmacKey[32];
};

#endif
