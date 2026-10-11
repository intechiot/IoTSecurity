/*
 * SecureMQ135.ino
 * 
 * Example: Securing MQ135 Air Quality Sensor Data with IoTSecurity Library
 * 
 * This sketch reads the MQ135 air quality sensor, encrypts and authenticates
 * the data using the IoTSecurity library, then publishes it over MQTT.
 * 
 * Hardware:
 *   - ESP32
 *   - MQ135 sensor connected to GPIO 34 (ADC1)
 * 
 * Library: IoTSecurity
 */

#include <WiFi.h>
#include <PubSubClient.h>
#include "IoTSecurity.h"

// ---------- WiFi Credentials ----------
const char* ssid     = "Embang";
const char* password = "19Suraidah75";

// ---------- MQTT Broker ----------
const char* mqtt_server = "broker.hivemq.com";
const int   mqtt_port   = 1883;

// ---------- MQTT Topics ----------
const char* topic_secure_air     = "farm/plot1/mq135/secure";
const char* topic_secure_voltage = "farm/plot1/mq135/voltage/secure";

// ---------- MQ135 Sensor ----------
#define MQ135_PIN 34

// ---------- IoT Security Library ----------
// IMPORTANT: In a real deployment, these keys must be unique per device
// and stored in secure flash (NVS encryption), never hard-coded.
byte aesKey[32]  = {
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
  0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
  0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
  0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
};

byte hmacKey[32] = {
  0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8,
  0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0,
  0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8,
  0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0
};

const char* deviceId = "ESP32-MQ135-001";

IoTSecurity secure;

// ---------- Network Clients ----------
WiFiClient   espClient;
PubSubClient client(espClient);

// ---------- Timing ----------
unsigned long lastMsg = 0;
const long    interval = 5000;

unsigned long bootTime = 0;
const long    warmupMs = 30000;

// ---------- WiFi Setup ----------
void setup_wifi() {
  Serial.print("Connecting to WiFi");
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println();
  Serial.print("WiFi connected. IP: ");
  Serial.println(WiFi.localIP());
}

// ---------- MQTT Reconnect ----------
void reconnect() {
  while (!client.connected()) {
    Serial.print("Attempting MQTT connection...");
    String clientId = "ESP32Client-" + String(random(0xffff), HEX);
    bool ok = client.connect(clientId.c_str());

    if (ok) {
      Serial.println("connected");
    } else {
      Serial.print("failed, rc=");
      Serial.print(client.state());
      Serial.println(" retrying in 2 s");
      delay(2000);
    }
  }
}

// ---------- Setup ----------
void setup() {
  Serial.begin(115200);
  analogReadResolution(12);
  analogSetPinAttenuation(MQ135_PIN, ADC_11db);

  setup_wifi();

  // Initialize the IoT Security Library
  secure.begin(deviceId, aesKey, hmacKey);

  client.setServer(mqtt_server, mqtt_port);

  Serial.println("=== Secure MQ135 Air Quality Monitor ===");
  Serial.println("Warming up sensor (30 s)...");
  bootTime = millis();
}

// ---------- Main Loop ----------
void loop() {
  if (!client.connected()) reconnect();
  client.loop();

  unsigned long now = millis();

  if (now - lastMsg > interval) {
    lastMsg = now;

    // Skip publishing during warm-up
    if (now - bootTime < warmupMs) {
      Serial.println("Warming up...");
      return;
    }

    // ---------- Sample the MQ135 ----------
    long sum = 0;
    const int samples = 20;
    for (int i = 0; i < samples; i++) {
      sum += analogRead(MQ135_PIN);
      delay(10);
    }
    int raw = sum / samples;
    float voltage = raw * (3.3f / 4095.0f);

    // ---------- Build the JSON payload ----------
    char payload[128];
    snprintf(payload, sizeof(payload),
             "{\"device\":\"%s\",\"raw\":%d,\"voltage\":%.3f}",
             deviceId, raw, voltage);

    Serial.printf("Plaintext: %s\n", payload);

    // ---------- Secure the packet ----------
    byte securePacket[256];
    int packetLen = secure.securePacket(payload, securePacket);

    if (packetLen <= 0) {
      Serial.println("ERROR: Encryption failed");
      return;
    }

    Serial.printf("Encrypted packet length: %d bytes\n", packetLen);

    // ---------- Publish over MQTT ----------
    // Note: PubSubClient.publish() accepts a byte buffer and length
    bool pubOk = client.publish(topic_secure_air,
                                (const uint8_t*)securePacket,
                                packetLen);

    if (pubOk) {
      Serial.println("Published encrypted MQ135 data OK");
    } else {
      Serial.println("Publish FAILED");
    }

    Serial.println("----------------------------------------");
  }
}
