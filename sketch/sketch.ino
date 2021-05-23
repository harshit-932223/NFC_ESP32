/*
 * Write personal data of a MIFARE RFID card using a RFID-RC522 reader
 * Uses MFRC522 - Library to use ARDUINO RFID MODULE KIT 13.56 MHZ WITH TAGS SPI W AND R BY COOQROBOT. 
 * -----------------------------------------------------------------------------------------
 *             MFRC522      Arduino       Arduino   Arduino    Arduino          Arduino
 *             Reader/PCD   Uno/101       Mega      Nano v3    Leonardo/Micro   Pro Micro
 * Signal      Pin          Pin           Pin       Pin        Pin              Pin
 * -----------------------------------------------------------------------------------------
 * RST/Reset   RST          9             5         D9         RESET/ICSP-5     RST
 * SPI SS      SDA(SS)      10            53        D10        10               10
 * SPI MOSI    MOSI         11 / ICSP-4   51        D11        ICSP-4           16
 * SPI MISO    MISO         12 / ICSP-1   50        D12        ICSP-1           14
 * SPI SCK     SCK          13 / ICSP-3   52        D13        ICSP-3           15
 *
 * Hardware required:
 * Arduino
 * PCD (Proximity Coupling Device): NXP MFRC522 Contactless Reader IC
 * PICC (Proximity Integrated Circuit Card): A card or tag using the ISO 14443A interface, eg Mifare or NTAG203.
 * The reader can be found on eBay for around 5 dollars. Search for "mf-rc522" on ebay.com. 
 */

#include <SPI.h>
#include <MFRC522.h>

#define BUFF_SIZE       48
#define RST_PIN         22           // Configurable, see typical pin layout above
#define SS_PIN          21          // Configurable, see typical pin layout above

MFRC522 mfrc522(SS_PIN, RST_PIN);   // Create MFRC522 instance

void setup() {
  Serial.begin(9600);        // Initialize serial communications with the PC
  Serial.println(F("HARSHIT: SPI Init "));
  SPI.begin();               // Init SPI bus
  Serial.println(F("HARSHIT: PCD Init "));
  mfrc522.PCD_Init();        // Init MFRC522 card
  Serial.println(F("HARSHIT: Write personal data on a MIFARE PICC "));
}

void loop() {
  // Reset the loop if no new card present on the sensor/reader. This saves the entire process when idle.
  if ( ! mfrc522.PICC_IsNewCardPresent()) {
    return;
  }

  // Select one of the cards
  if ( ! mfrc522.PICC_ReadCardSerial()) {
    return;
  }

  Serial.print(F("Card UID:"));    //Dump UID
  for (byte i = 0; i < mfrc522.uid.size; i++) {
    Serial.print(mfrc522.uid.uidByte[i] < 0x10 ? " 0" : " ");
    Serial.print(mfrc522.uid.uidByte[i], HEX);
  }
  Serial.print(F(" PICC type: "));   // Dump PICC type
  MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
  Serial.println(mfrc522.PICC_GetTypeName(piccType));

  byte buffer[BUFF_SIZE], read_buffer[BUFF_SIZE];
  byte block;
  MFRC522::StatusCode status;
  byte len;

  if(read_data(0, read_buffer)==0){
    for (uint8_t i = 0; i < BUFF_SIZE; i++) {
      Serial.write(read_buffer[i]);
    }
  }else{
    Serial.println("READ FAILURE");
    return;
  }

  Serial.setTimeout(20000L) ;     // wait until 20 seconds for input from serial
  
  Serial.println(F("Type Data, ending with #"));
  len = Serial.readBytesUntil('#', (char *) buffer, BUFF_SIZE) ; // read data from serial
  for (byte i = len; i < BUFF_SIZE; i++) buffer[i] = ' ';     // pad with spaces

  if(write_data(0, buffer)==0){
    Serial.println("SUCCESS");
  }else{
    Serial.println("FAILURE");
  }

  Serial.println(" ");
  mfrc522.PICC_HaltA(); // Halt PICC
  mfrc522.PCD_StopCrypto1();  // Stop encryption on PCD

}

int write_data(int sector, byte* buff){
  int block = 0;
  int buff_idx=0;
  MFRC522::StatusCode status;

  // Prepare key - all keys are set to FFFFFFFFFFFFh at chip delivery from the factory.
  MFRC522::MIFARE_Key key;
  for (byte i = 0; i < 6; i++) key.keyByte[i] = 0xFF;
  
  if(sector<0 || sector >=15){
    return -1;
  }else if(sector==0){
    block=1;
  }else{
    block = 4*sector;
  }
  
  while(block%4!=3){
    //Serial.println(F("Authenticating using key A..."));
    status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
      Serial.print(F("PCD_Authenticate() failed: "));
      Serial.println(mfrc522.GetStatusCodeName(status));
      return -1;
    }
    else Serial.println(F("PCD_Authenticate() success: "));
  
    // Write block
    status = mfrc522.MIFARE_Write(block, &buff[buff_idx], 16);
    if (status != MFRC522::STATUS_OK) {
      Serial.print(F("MIFARE_Write() failed: "));
      Serial.println(mfrc522.GetStatusCodeName(status));
      return -2;
    }
    else Serial.println(F("MIFARE_Write() success: "));
    buff_idx+=16;
    block++;
  }
  return 0;
}


int read_data(int sector, byte* buff){
  int block = 0;
  byte buff_size;
  MFRC522::StatusCode status;

  // Prepare key - all keys are set to FFFFFFFFFFFFh at chip delivery from the factory.
  MFRC522::MIFARE_Key key;
  for (byte i = 0; i < 6; i++) key.keyByte[i] = 0xFF;
  
  if(sector<0 || sector >=15){
    return -1;
  }else if(sector==0){
    block=1;
    buff_size=32;
  }else{
    block = 4*sector;
    buff_size = 48;
  }
  //Serial.println(F("Authenticating using key A..."));
  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, &key, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("PCD_Authenticate() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return -1;
  }
  else Serial.println(F("PCD_Authenticate() success: "));

  // Read block
  status = mfrc522.MIFARE_Read(block, buff, &buff_size);
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("MIFARE_Read() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return -2;
  }
  else Serial.println(F("MIFARE_Read() success: "));
  
  return 0;
}
