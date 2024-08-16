// gcc main.c -lpcsclite -I/usr/local/include/PCSC

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <winscard.h>

#define SIZE 18

SCARDCONTEXT applicationContext;
LPSTR reader = NULL;
SCARDHANDLE connectionHandler;
DWORD activeProtocol;

// read procedure
void performReadOperation(char *protocol, char *option);
void readDataFromCard(uint8_t *dataFromCard, char *protocol, uint8_t cardNumber);
void mifareClassicRead(uint8_t *dataFromCard, uint8_t cardNumber);
void mifareUltralightRead(uint8_t *dataFromCard, uint8_t cardNumber);

// write procedure
void performWriteOperation(char *protocol);
void writeDataToCard(const uint8_t *dataToWrite, char *protocol, uint8_t cardNumber);
void mifareClassicWrite(const uint8_t *dataToWrite, uint8_t cardNumber);
void mifareUltralightWrite(const uint8_t *dataToWrite, uint8_t cardNumber);

// comum procedure
void establishContext();
void listReaders();
void connectToCard();
void mifareClassicAuthenticateToCard(uint8_t blockNumber);
void sendCommand(uint8_t command[], unsigned short commandLength);
void disconnectFromCard();
void freeListReader();
void releaseContext();

// others (not in use)
void getCardInformation();

uint8_t response[SIZE];
unsigned long responseLength = sizeof(response);

int main(int argc, char *argv[]) {
	if (argc != 4) {
        printf("Usage: %s <read|write> <classic|ultra> <debug|main>\n", argv[0]);
        return 1;
    }

	if (strcmp(argv[1], "read") == 0) {
        printf("Performing read operation...\n");
        performReadOperation(argv[2], argv[3]);
    } else if (strcmp(argv[1], "write") == 0) {
        printf("Performing write operation...\n");
        performWriteOperation(argv[2]);
    } else {
        printf("Invalid operation: %s\n", argv[1]);
        return 1;
    }

    return 0;
}

///////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// read procedure //////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////

void performReadOperation(char *protocol, char *option){
	establishContext();
	listReaders();
	connectToCard();

	uint8_t dataFromCard[SIZE];
	uint8_t cardNumber = 0x00;

	FILE *file = fopen("card_data.txt", "w");
    if (file == NULL) {
        printf("Error opening file for writing.\n");
		exit(1);
    }
	int key = 0;
	for (int j = 0; j < 64; j++) {
		readDataFromCard(dataFromCard, protocol, cardNumber);
		if (key <= 2 && j >= 4) {
			// Write card information to the binary file
			for (int i = 0; i < SIZE; i++) {
				fprintf(file, "%02X ", dataFromCard[i]);
			}
			if (strcmp(option, "debug") == 0) {
				fprintf(file, "\n");
			}
			key++;
		}
		else
		{
			key = 0;
		}
		cardNumber++;
	}
	fclose(file);
	
	disconnectFromCard();
	freeListReader();
	releaseContext();
}

void readDataFromCard(uint8_t *dataFromCard, char *protocol, uint8_t cardNumber) {
	if (strcmp(protocol, "classic") == 0) {
		mifareClassicRead(dataFromCard, cardNumber);
	}
	else if (strcmp(protocol, "ultra") == 0) {
		mifareUltralightRead(dataFromCard, cardNumber);
	} else {
		printf("Invalid protocol: %s\n", protocol);
		exit(1);
	}
}

void mifareClassicRead(uint8_t *dataFromCard, uint8_t cardNumber) {
	uint8_t blockNumber = cardNumber;

	mifareClassicAuthenticateToCard(blockNumber);

	// Read 1 blocks (16 bytes) at blockNumber
	uint8_t readCommand[] = { 0xFF, 0xB0, 0x00, blockNumber, 0x10 };
	unsigned short readCommandLength = sizeof(readCommand);
	sendCommand(readCommand, readCommandLength);

	memcpy(dataFromCard, response, SIZE);
}

void mifareUltralightRead(uint8_t *dataFromCard, uint8_t cardNumber) {
	uint8_t pageNumber = cardNumber;
	
	// Read 4 blocks (16 bytes) starting from pageNumber
	uint8_t readCommand[] = { 0xFF, 0xB0, 0x00, pageNumber, 0x10 };
	unsigned short readCommandLength = sizeof(readCommand);
	sendCommand(readCommand, readCommandLength);
}

///////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// write procedure /////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////


void performWriteOperation(char *protocol){
	establishContext();
	listReaders();
	connectToCard();

	FILE *file = fopen("card_data.txt", "r");
	if (file == NULL) {
		printf("Error opening file for reading.\n");
		exit(1);
	}

	uint8_t cardNumber = 0x04;
	uint8_t dataToWrite[SIZE];
	int key = 0;
	for (int j = 0; j < 64; j++) {
		if(key <= 2 && j >= 4) {
			for (int i = 0; i < SIZE; i++) {
				fscanf(file, "%02hhX", &dataToWrite[i]);
				printf("%02hhX ", dataToWrite[i]);
			}
			key++;
			printf("\n%02hhX\n\n", cardNumber);
		}
		else
		{
			key = 0;
		}
		cardNumber++;
		// writeDataToCard(dataToWrite, protocol, cardNumber);
	}
	fclose(file);


	disconnectFromCard();
	freeListReader();
	releaseContext();
}

void writeDataToCard(const uint8_t *dataToWrite, char *protocol, uint8_t cardNumber) {
    if (strcmp(protocol, "classic") == 0) {
		mifareClassicWrite(dataToWrite, cardNumber);
	}
	else if (strcmp(protocol, "ultra") == 0) {
		mifareUltralightWrite(dataToWrite, cardNumber);
	} else {
		printf("Invalid protocol: %s\n", protocol);
		exit(1);
	}
}

void mifareClassicWrite(const uint8_t *dataToWrite, uint8_t cardNumber) {
	uint8_t blockNumber = cardNumber;

	mifareClassicAuthenticateToCard(blockNumber);

	// Write 1 blocks (16 bytes) at blockNumber
	// uint8_t data[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	uint8_t writeCommand[21] = { 0xFF, 0xD6, 0x00, blockNumber, 0x10 };
	unsigned short writeCommandLength = sizeof(writeCommand);
	for (int i=0; i<16; i++) {
		writeCommand[i+5] = dataToWrite[i];
	}
	sendCommand(writeCommand, writeCommandLength);
}

void mifareUltralightWrite(const uint8_t *dataToWrite, uint8_t cardNumber) {
	printf("### MIFARE Ultralight ###\n");
	uint8_t pageNumber = cardNumber;
	
	// Write 1 block (4 bytes) to pageNumber
	uint8_t data[] = { 0x00, 0x01, 0x02, 0x03 };
	uint8_t writeCommand[9] = { 0xFF, 0xD6, 0x00, pageNumber, 0x04 };
	unsigned short writeCommandLength = sizeof(writeCommand);
	for (int i=0; i<4; i++) {
		writeCommand[i+5] = data[i];
	}
	sendCommand(writeCommand, writeCommandLength);
}

///////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// common procedure ////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////

void establishContext() {
	LONG status = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &applicationContext);
	if (status == SCARD_S_SUCCESS) {
		printf("Context established\n");
	} else {
		printf("Establish context error: %s\n", pcsc_stringify_error(status));
		exit(1);
	}
}

void listReaders() {
	DWORD readers = SCARD_AUTOALLOCATE;
	LONG status = SCardListReaders(applicationContext, NULL, (LPSTR)&reader, &readers);
	
	if (status == SCARD_S_SUCCESS) {
		char *p = reader;
		while (*p) {
			printf("Reader found: %s\n", p);
			p += strlen(p) +1;
		}
	} else {
		printf("List reader error: %s\n", pcsc_stringify_error(status));
		exit(1);
	}
}

void connectToCard() {
	activeProtocol = -1;

	LONG status = SCardConnect(applicationContext, reader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &connectionHandler, &activeProtocol);
	if (status == SCARD_S_SUCCESS) {
		printf("Connected to card\n");
	} else {
		printf("Card connection error: %s\n", pcsc_stringify_error(status));
		exit(1);
	}
}

void mifareClassicAuthenticateToCard(uint8_t blockNumber) {
	// Load Authentication Keys
	uint8_t key[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
	uint8_t authenticationKeysCommand[11] = { 0xFF, 0x82, 0x00, 0x00, 0x06 };
	unsigned short authenticationKeysCommandLength = sizeof(authenticationKeysCommand);
	for (int i=0; i<6; i++) {
		authenticationKeysCommand[i+5] = key[i];
	}
	sendCommand(authenticationKeysCommand, authenticationKeysCommandLength);
	
	// Authenticate
	uint8_t authenticateCommand[] = { 0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, blockNumber, 0x60, 0x00 };
	unsigned short authenticateCommandLength = sizeof(authenticateCommand);
	sendCommand(authenticateCommand, authenticateCommandLength);

	// Read 1 blocks (16 bytes) at blockNumber
	uint8_t readCommand[] = { 0xFF, 0xB0, 0x00, blockNumber, 0x10 };
	unsigned short readCommandLength = sizeof(readCommand);
	sendCommand(readCommand, readCommandLength);
}

void sendCommand(uint8_t command[], unsigned short commandLength) {
    const SCARD_IO_REQUEST *pioSendPci;
    SCARD_IO_REQUEST pioRecvPci;
    
	// Allocate a buffer large enough to handle the maximum expected response size
    unsigned long dynamicResponseLength = SIZE;  // Adjust the size as needed
    uint8_t *dynamicResponse = malloc(dynamicResponseLength);

    if (dynamicResponse == NULL) {
        printf("Memory allocation error\n");
        exit(1);
    }

    switch (activeProtocol) {
        case SCARD_PROTOCOL_T0:
            pioSendPci = SCARD_PCI_T0;
            break;
        case SCARD_PROTOCOL_T1:
            pioSendPci = SCARD_PCI_T1;
            break;
        default:
            printf("Protocol not found\n");
            exit(1);
    }
    
    LONG status = SCardTransmit(connectionHandler, pioSendPci, command, commandLength, &pioRecvPci, dynamicResponse, &dynamicResponseLength);
    
    if (status == SCARD_S_SUCCESS) {
        printf("Command sent: \n");
        for (int i = 0; i < commandLength; i++) {
            printf("%02X ", command[i]);
        }
        printf("\nResponse: \n");
        for (int i = 0; i < dynamicResponseLength; i++) {
            printf("%02X ", dynamicResponse[i]);
        }
        printf("\n\n");
    } else {
        printf("Send command error: %s\n", pcsc_stringify_error(status));
        free(dynamicResponse);  // Free memory before exiting
        exit(1);
    }

    // Use dynamicResponse as needed
	memcpy(response, dynamicResponse, SIZE);

    // Don't forget to free the allocated memory when done
    free(dynamicResponse);
}

void disconnectFromCard() {
	LONG status = SCardDisconnect(connectionHandler, SCARD_LEAVE_CARD);
	if (status == SCARD_S_SUCCESS) {
		printf("Disconnected from card\n");
	} else {
		printf("Card deconnection error: %s\n", pcsc_stringify_error(status));
		exit(1);
	}
}

void freeListReader() {
	LONG status = SCardFreeMemory(applicationContext, reader);
	if (status == SCARD_S_SUCCESS) {
		printf("Reader list free\n");
	} else {
		printf("Free reader list error: %s\n", pcsc_stringify_error(status));
		exit(1);
	}
}

void releaseContext() {
	LONG status = SCardReleaseContext(applicationContext);
	if (status == SCARD_S_SUCCESS) {
		printf("Context released\n");
	} else {
		printf("Release context error: %s\n", pcsc_stringify_error(status));
		exit(1);
	}
}

///////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////// others ///////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////

void getCardInformation() {
	BYTE ATR[MAX_ATR_SIZE] = "";
	DWORD ATRLength = sizeof(ATR);
	char readerName[MAX_READERNAME] = "";
	DWORD readerLength = sizeof(readerName);
	DWORD readerState;
	DWORD readerProtocol;
	
	LONG status = SCardStatus(connectionHandler, readerName, &readerLength, &readerState, &readerProtocol, ATR, &ATRLength);
	if (status == SCARD_S_SUCCESS) {
		printf("\n");
		printf("Name of the reader: %s\n", readerName);
		printf("ATR: ");
		for (int i=0; i<ATRLength; i++) {
			printf("%02X ", ATR[i]);
		}
		printf("\n\n");
	} else {
		printf("Get card information error: %s\n", pcsc_stringify_error(status));
		exit(1);
	}
}