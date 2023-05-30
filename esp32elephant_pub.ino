#include "api.h"
#include "crypto_aead.h"
#include "elephant_200.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <WiFi.h>
#include <PubSubClient.h>
#include <DHT.h>

const char* ssid = " ";
const char* password = " ";
const char* mqtt_server = "broker.mqtt-dashboard.com";
const char* topic = "PMC7esp";

#define DHTPIN 13       
#define DHTTYPE DHT22   

WiFiClient espClient;
PubSubClient client(espClient);
unsigned long lastMsg = 0;
#define MSG_BUFFER_SIZE (50)
char msg[MSG_BUFFER_SIZE];
int value = 0;

DHT dht(DHTPIN, DHTTYPE);

void setup_wifi() {
  delay(10);
  Serial.println();
  Serial.print("Connecting to ");
  Serial.println(ssid);

  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  randomSeed(micros());

  Serial.println("");
  Serial.println("WiFi connected");
  Serial.println("IP address: ");
  Serial.println(WiFi.localIP());
}

void reconnect() {
  while (!client.connected()) {
    Serial.print("Attempting MQTT connection...");
    String clientId = "ESP32Client-";
    clientId += String(random(0xffff), HEX);

    if (client.connect(clientId.c_str())) {
      Serial.println("connected");
    } else {
      Serial.print("failed, rc = ");
      Serial.print(client.state());
      Serial.println(" try again in 5 seconds");

      delay(5000);
    }
  }
}

#define maxNrRounds 18
#define nrLanes 25
#define index(x, y) (((x) % 5) + 5 * ((y) % 5))
const unsigned char nonce[CRYPTO_NPUBBYTES] = "EL2008"; 
const unsigned char key[CRYPTO_KEYBYTES] = "PMCelephant7"; 
const unsigned char ad[CRYPTO_ABYTES] = "132210XY"; 

const BYTE KeccakRoundConstants[maxNrRounds] = {
  0x01, 0x82, 0x8a, 0x00, 0x8b, 0x01, 0x81, 0x09, 0x8a,
  0x88, 0x09, 0x0a, 0x8b, 0x8b, 0x89, 0x03, 0x02, 0x80
};

const unsigned int KeccakRhoOffsets[nrLanes] = {
  0, 1, 6, 4, 3, 4, 4, 6, 7, 4, 3, 2, 3, 1, 7, 1, 5, 7, 5, 0, 2, 2, 5, 0, 6
};

#define ROL8(a, offset) ((offset != 0) ? ((((BYTE)a) << offset) ^ (((BYTE)a) >> (sizeof(BYTE)*8-offset))) : a)

void theta(BYTE *A) {
  unsigned int x, y;
  BYTE C[5], D[5];

  for(x = 0; x < 5; x++) {
    C[x] = 0;
    for(y = 0; y < 5; y++)
      C[x] ^= A[index(x, y)];
  }
  for(x = 0; x < 5; x++)
    D[x] = ROL8(C[(x + 1) % 5], 1) ^ C[(x + 4) % 5];
  for(x = 0; x < 5; x++)
    for(y = 0; y < 5; y++)
      A[index(x, y)] ^= D[x];
}

void rho(BYTE *A) {
  for(unsigned int x = 0; x < 5; x++)
    for(unsigned int y = 0; y < 5; y++)
      A[index(x, y)] = ROL8(A[index(x, y)], KeccakRhoOffsets[index(x, y)]);
}

void pi(BYTE *A) {
  BYTE tempA[25];

  for(unsigned int x = 0; x < 5; x++)
    for(unsigned int y = 0; y < 5; y++)
      tempA[index(x, y)] = A[index(x, y)];
  for(unsigned int x = 0; x < 5; x++)
    for(unsigned int y = 0; y < 5; y++)
      A[index(0 * x + 1 * y, 2 * x + 3 *y)] = tempA[index(x, y)];
}

void chi(BYTE *A) {
  unsigned int x, y;
  BYTE C[5];

  for(y = 0; y < 5; y++) {
    for(x = 0; x < 5; x++)
      C[x] = A[index(x, y)] ^ ((~A[index(x + 1, y)]) & A[index(x + 2, y)]);
    for(x = 0; x < 5; x++)
      A[index(x, y)] = C[x];
  }
}

void iota(BYTE *A, unsigned int indexRound) {
  A[index(0, 0)] ^= KeccakRoundConstants[indexRound];
}

void KeccakP200Round(BYTE *state, unsigned int indexRound) {
  theta(state);
  rho(state);
  pi(state);
  chi(state);
  iota(state, indexRound);
}

void permutation(BYTE* state) {
  for(unsigned int i = 0; i < maxNrRounds; i++)
    KeccakP200Round(state, i);
}

BYTE rotl(BYTE b) {
  return (b << 1) | (b >> 7);
}

int constcmp(const BYTE* a, const BYTE* b, SIZE length) {
  BYTE r = 0;
  for (SIZE i = 0; i < length; ++i)
    r |= a[i] ^ b[i];
  return r;
}

void lfsr_step(BYTE* output, BYTE* input) {
  BYTE temp = rotl(input[0]) ^ rotl(input[2]) ^ (input[13] << 1);
  for(SIZE i = 0; i < BLOCK_SIZE - 1; ++i)
    output[i] = input[i + 1];
  output[BLOCK_SIZE - 1] = temp;
}

void xor_block(BYTE* state, const BYTE* block, SIZE size) {
  for(SIZE i = 0; i < size; ++i)
    state[i] ^= block[i];
}

void get_ad_block(BYTE* output, const BYTE* ad, SIZE adlen, const BYTE* npub, SIZE i) {
  SIZE len = 0;
  if(i == 0) {
    memcpy(output, npub, CRYPTO_NPUBBYTES);
    len += CRYPTO_NPUBBYTES;
  }

  const SIZE block_offset = i * BLOCK_SIZE - (i != 0) * CRYPTO_NPUBBYTES;
  if(i != 0 && block_offset == adlen) {
    memset(output, 0x00, BLOCK_SIZE);
    output[0] = 0x01;
    return;
  }
  const SIZE r_outlen = BLOCK_SIZE - len;
  const SIZE r_adlen  = adlen - block_offset;
  if(r_outlen <= r_adlen) { 
    memcpy(output + len, ad + block_offset, r_outlen);
  } 
  else {
    if(r_adlen > 0) 
      memcpy(output + len, ad + block_offset, r_adlen);
    memset(output + len + r_adlen, 0x00, r_outlen - r_adlen);
    output[len + r_adlen] = 0x01;
  }
}

void get_c_block(BYTE* output, const BYTE* c, SIZE clen, SIZE i) {
  const SIZE block_offset = i * BLOCK_SIZE;
  if(block_offset == clen) {
    memset(output, 0x00, BLOCK_SIZE);
    output[0] = 0x01;
    return;
  }
  const SIZE r_clen  = clen - block_offset;
  if(BLOCK_SIZE <= r_clen) { 
    memcpy(output, c + block_offset, BLOCK_SIZE);
  } 
  else { 
    if(r_clen > 0) 
      memcpy(output, c + block_offset, r_clen);
    memset(output + r_clen, 0x00, BLOCK_SIZE - r_clen);
    output[r_clen] = 0x01;
  }
}

void crypto_aead_impl(
  BYTE* c, BYTE* tag, const BYTE* m, SIZE mlen, const BYTE* ad, SIZE adlen,
  const BYTE* npub, const BYTE* k, int encrypt)
{
  const SIZE nblocks_c  = 1 + mlen / BLOCK_SIZE;
  const SIZE nblocks_m  = (mlen % BLOCK_SIZE) ? nblocks_c : nblocks_c - 1;
  const SIZE nblocks_ad = 1 + (CRYPTO_NPUBBYTES + adlen) / BLOCK_SIZE;
  const SIZE nb_it = (nblocks_c + 1 > nblocks_ad - 1) ? nblocks_c + 1 : nblocks_ad - 1;

  BYTE expanded_key[BLOCK_SIZE] = {0};
  memcpy(expanded_key, k, CRYPTO_KEYBYTES);
  permutation(expanded_key);

  BYTE mask_buffer_1[BLOCK_SIZE] = {0};
  BYTE mask_buffer_2[BLOCK_SIZE] = {0};
  BYTE mask_buffer_3[BLOCK_SIZE] = {0};
  memcpy(mask_buffer_2, expanded_key, BLOCK_SIZE);

  BYTE* previous_mask = mask_buffer_1;
  BYTE* current_mask = mask_buffer_2;
  BYTE* next_mask = mask_buffer_3;

  BYTE buffer[BLOCK_SIZE];

  BYTE tag_buffer[BLOCK_SIZE] = {0};
  get_ad_block(tag_buffer, ad, adlen, npub, 0);

  SIZE offset = 0;
  for(SIZE i = 0; i < nb_it; ++i) {
    lfsr_step(next_mask, current_mask);
    if(i < nblocks_m) {
      memcpy(buffer, npub, CRYPTO_NPUBBYTES);
      memset(buffer + CRYPTO_NPUBBYTES, 0, BLOCK_SIZE - CRYPTO_NPUBBYTES);
      xor_block(buffer, current_mask, BLOCK_SIZE);
      xor_block(buffer, next_mask, BLOCK_SIZE);
      permutation(buffer);
      xor_block(buffer, current_mask, BLOCK_SIZE);
      xor_block(buffer, next_mask, BLOCK_SIZE);
      const SIZE r_size = (i == nblocks_m - 1) ? mlen - offset : BLOCK_SIZE;
      xor_block(buffer, m + offset, r_size);
      memcpy(c + offset, buffer, r_size);
    }

    if(i > 0 && i <= nblocks_c) {
      get_c_block(buffer, encrypt ? c : m, mlen, i - 1);
      xor_block(buffer, previous_mask, BLOCK_SIZE);
      xor_block(buffer, next_mask, BLOCK_SIZE);
      permutation(buffer);
      xor_block(buffer, previous_mask, BLOCK_SIZE);
      xor_block(buffer, next_mask, BLOCK_SIZE);
      xor_block(tag_buffer, buffer, BLOCK_SIZE);
    }

    if(i + 1 < nblocks_ad) {
      get_ad_block(buffer, ad, adlen, npub, i + 1);
      xor_block(buffer, next_mask, BLOCK_SIZE);
      permutation(buffer);
      xor_block(buffer, next_mask, BLOCK_SIZE);
      xor_block(tag_buffer, buffer, BLOCK_SIZE);
    }

    BYTE* const temp = previous_mask;
    previous_mask = current_mask;
    current_mask = next_mask;
    next_mask = temp;

    offset += BLOCK_SIZE;
  }

  xor_block(tag_buffer, expanded_key, BLOCK_SIZE);
  permutation(tag_buffer);
  xor_block(tag_buffer, expanded_key, BLOCK_SIZE);
  memcpy(tag, tag_buffer, CRYPTO_ABYTES);
}

int crypto_aead_encrypt(
  unsigned char *c, unsigned long long *clen,
  const unsigned char *m, unsigned long long mlen,
  const unsigned char *ad, unsigned long long adlen,
  const unsigned char *nsec,
  const unsigned char *npub,
  const unsigned char *k)
{
  (void)nsec;
  *clen = mlen + CRYPTO_ABYTES;
  BYTE tag[CRYPTO_ABYTES];
  crypto_aead_impl(c, tag, m, mlen, ad, adlen, npub, k, 1);
  memcpy(c + mlen, tag, CRYPTO_ABYTES);
  return 0;
}

int crypto_aead_decrypt(
  unsigned char *m, unsigned long long *mlen,
  unsigned char *nsec,
  const unsigned char *c, unsigned long long clen,
  const unsigned char *ad, unsigned long long adlen,
  const unsigned char *npub,
  const unsigned char *k)
{
  (void)nsec;
  if(clen < CRYPTO_ABYTES)
    return -1;
  *mlen = clen - CRYPTO_ABYTES;
  BYTE tag[CRYPTO_ABYTES];
  crypto_aead_impl(m, tag, c, *mlen, ad, adlen, npub, k, 0);
  return (constcmp(c + *mlen, tag, CRYPTO_ABYTES) == 0) ? 0 : -1;
}

void encryptTemperature(float temperature, unsigned char* ciphertext, unsigned long long clen) {
  unsigned long long dlen;
  char temperatureStr[MSG_BUFFER_SIZE * 2];
  char encryptedTemperatureStr[MSG_BUFFER_SIZE * 2];

  sprintf(temperatureStr, "%.2f", temperature);
  crypto_aead_encrypt(ciphertext, &clen, (const unsigned char*)temperatureStr, 
                      strlen((char *)temperatureStr), ad, 
                      strlen((char *)ad), NULL, nonce, key);

  Serial.print("Encrypted Temperature: ");
  for (int i = 0; i < clen; i++) {
    sprintf(&encryptedTemperatureStr[i * 2], "%02x", ciphertext[i]);
  }
  Serial.println(encryptedTemperatureStr);
  client.publish(topic, encryptedTemperatureStr);

  decryptTemperature(ciphertext, clen, dlen);
}

void decryptTemperature(unsigned char* ciphertext, unsigned long long clen, unsigned long long dlen) {
  unsigned char decryptedTemperature[MSG_BUFFER_SIZE * 2];
  crypto_aead_decrypt(decryptedTemperature, &dlen, NULL, ciphertext, 
                      clen, ad, strlen((char *)ad), nonce, key);

  decryptedTemperature[dlen] = '\0';
  Serial.print("Decrypted Temperature: ");
  Serial.println((char *)decryptedTemperature);
  client.publish(topic, (char *)decryptedTemperature);
  delay(2000);
}

void setup() {
  Serial.begin(115200);
  setup_wifi();
  client.setServer(mqtt_server, 1883);
  dht.begin();
}

void loop() {
  if (!client.connected()) {
    reconnect();
  }
  client.loop();

  float temperature = dht.readTemperature();
  if (isnan(temperature)) {
    Serial.println("Failed to read temperature from DHT sensor!");
    return;
  }

  unsigned long long clen;
  unsigned char ciphertext[MSG_BUFFER_SIZE * 2];
  encryptTemperature(temperature, ciphertext, clen);
}