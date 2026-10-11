#ifndef IOT_AUTHENTICATION_H
#define IOT_AUTHENTICATION_H

#include <Arduino.h>

class IoTAuthentication {
  public:
    void begin(const char* deviceId, const byte* secret);
    const char* getDeviceId();
  private:
    const char* _deviceId;
    byte _secret[32];
};

#endif
