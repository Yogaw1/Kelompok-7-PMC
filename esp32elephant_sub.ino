#include <WiFi.h>
#include <PubSubClient.h>
#include <Wire.h>
#include <Adafruit_SSD1306.h>

const char* ssid = " ";
const char* password = " ";
const char* mqtt_server = "broker.mqtt-dashboard.com";
const char* topic = "PMC7esp";

WiFiClient espClient;
PubSubClient client(espClient);
unsigned long lastMsg = 0;
#define MSG_BUFFER_SIZE (50)
char msg[MSG_BUFFER_SIZE];
int value = 0;

Adafruit_SSD1306 display(128, 64, &Wire, -1);

void setup_wifi() {
  delay(10);

  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  randomSeed(micros());

  Serial.println("");
  Serial.println("WiFi connected");
  Serial.println("IP address:");
  Serial.println(WiFi.localIP());
}

void callback(char* topic, byte* payload, unsigned int length) {
  Serial.print("Message arrived [");
  Serial.print(topic);
  Serial.print("] : ");

  display.clearDisplay();
  display.setCursor(0, 0);
  display.println("Message:");
  display.setCursor(0, 13);
  delay(2000); 
  for (int i = 0; i < length; i++) {
    display.print((char)payload[i]);
    Serial.print((char)payload[i]);
  }
  Serial.println();
  display.display();
}

void reconnect() {
  while (!client.connected()) {
    display.clearDisplay();
    display.setCursor(0, 0);
    display.println("MQTT: Connecting");

    Serial.print("Attempting MQTT connection...");
    String clientId = "ESP32Client-";
    clientId += String(random(0xffff), HEX);
    if (client.connect(clientId.c_str())) {
      client.subscribe(topic);
      display.clearDisplay();
      display.setCursor(0, 0);
      display.println("MQTT : Connected");
    } else {
      Serial.print("failed, rc = ");
      Serial.print(client.state());
      Serial.println(" try again in 5 seconds");
      display.clearDisplay();
      display.setCursor(0, 0);
      display.println("MQTT : Failed");
      display.display();
      delay(5000);
    }
  }
}

void setup() {
  Serial.begin(115200);
  setup_wifi();
  client.setServer(mqtt_server, 1883);
  client.setCallback(callback);
  display.begin(SSD1306_SWITCHCAPVCC, 0x3C);
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.println("Connecting...");
  display.display();
  delay(1000);
}

bool passwordEntered = false;
bool passwordPrompted = false;

void loop() {
  if (!passwordEntered) {
    if (!passwordPrompted) {
      display.clearDisplay();
      display.setCursor(0, 0);
      display.println("Enter password :");
      display.display();
      passwordPrompted = true;
    }

    if (Serial.available()) {
      String input = Serial.readStringUntil('\n');
      input.trim();
      display.setCursor(0, 1);
      if (input.equals("132210YZ")) {
        passwordEntered = true;
        display.clearDisplay();
        display.setCursor(0, 0);
        display.println("Password correct");
        display.setCursor(0, 13);
        display.println("MQTT connected");
        display.display();
        Serial.println("Password correct. MQTT connection established.");
      } 
      else {
        display.clearDisplay();
        display.setCursor(0, 0);
        display.println("Incorrect password");
        display.setCursor(0, 13);
        display.println("Please try again");
        display.display();
        Serial.println("Incorrect password. Please try again.");
        delay(2000);
        display.clearDisplay();
        display.setCursor(0, 0);
        display.println("Enter password:");
        display.display();
        passwordPrompted = false;
      }
    }
    return;
  }

  if (!client.connected()) {
    reconnect();
  }
  client.loop();
}