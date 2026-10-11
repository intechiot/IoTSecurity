#include "IoTAuthentication.h"

void IoTAuthentication::begin(const char* deviceId, const byte* secret) {
  _deviceId = deviceId;
  memcpy(_secret, secret, 32);
}

const char* IoTAuthentication::getDeviceId() {
  return _deviceId;
}
