#include <iostream>
#include <cstring>
#include "structures.h"

using namespace std;

void eAddRoundKey(unsigned char * state, unsigned char * roundKey) {
	for (int i = 0; i < 16; i++) {
		state[i] ^= roundKey[i];
	}
}

void eSubBytes(unsigned char * state) {
	for (int i = 0; i < 16; i++) { // Perform substitution to each of the 16 bytes
		state[i] = s[state[i]];
	}
}

void eShiftRows(unsigned char * state) {
	unsigned char tmp[16];

	/* Column 1 */
	tmp[0] = state[0];
	tmp[1] = state[5];
	tmp[2] = state[10];
	tmp[3] = state[15];

	/* Column 2 */
	tmp[4] = state[4];
	tmp[5] = state[9];
	tmp[6] = state[14];
	tmp[7] = state[3];

	/* Column 3 */
	tmp[8] = state[8];
	tmp[9] = state[13];
	tmp[10] = state[2];
	tmp[11] = state[7];

	/* Column 4 */
	tmp[12] = state[12];
	tmp[13] = state[1];
	tmp[14] = state[6];
	tmp[15] = state[11];

	for (int i = 0; i < 16; i++) {
		state[i] = tmp[i];
	}
}
void eMixColumns(unsigned char * state) {
	unsigned char tmp[16];

	tmp[0] = (unsigned char)mul2[state[0]] ^ mul3[state[1]] ^ state[2] ^ state[3];
	tmp[1] = (unsigned char)state[0] ^ mul2[state[1]] ^ mul3[state[2]] ^ state[3];
	tmp[2] = (unsigned char)state[0] ^ state[1] ^ mul2[state[2]] ^ mul3[state[3]];
	tmp[3] = (unsigned char)mul3[state[0]] ^ state[1] ^ state[2] ^ mul2[state[3]];

	tmp[4] = (unsigned char)mul2[state[4]] ^ mul3[state[5]] ^ state[6] ^ state[7];
	tmp[5] = (unsigned char)state[4] ^ mul2[state[5]] ^ mul3[state[6]] ^ state[7];
	tmp[6] = (unsigned char)state[4] ^ state[5] ^ mul2[state[6]] ^ mul3[state[7]];
	tmp[7] = (unsigned char)mul3[state[4]] ^ state[5] ^ state[6] ^ mul2[state[7]];

	tmp[8] = (unsigned char)mul2[state[8]] ^ mul3[state[9]] ^ state[10] ^ state[11];
	tmp[9] = (unsigned char)state[8] ^ mul2[state[9]] ^ mul3[state[10]] ^ state[11];
	tmp[10] = (unsigned char)state[8] ^ state[9] ^ mul2[state[10]] ^ mul3[state[11]];
	tmp[11] = (unsigned char)mul3[state[8]] ^ state[9] ^ state[10] ^ mul2[state[11]];

	tmp[12] = (unsigned char)mul2[state[12]] ^ mul3[state[13]] ^ state[14] ^ state[15];
	tmp[13] = (unsigned char)state[12] ^ mul2[state[13]] ^ mul3[state[14]] ^ state[15];
	tmp[14] = (unsigned char)state[12] ^ state[13] ^ mul2[state[14]] ^ mul3[state[15]];
	tmp[15] = (unsigned char)mul3[state[12]] ^ state[13] ^ state[14] ^ mul2[state[15]];

	for (int i = 0; i < 16; i++) {
		state[i] = tmp[i];
	}
}

void eRound(unsigned char * state, unsigned char * key) {
	eSubBytes(state);
	eShiftRows(state);
	eMixColumns(state);
	eAddRoundKey(state, key);
}

void eFinalRound(unsigned char * state, unsigned char * key) {
	eSubBytes(state);
	eShiftRows(state);
	eAddRoundKey(state, key);
}


void AESEncrypt(unsigned char * message, unsigned char * expandedKey, unsigned char * encryptedMessage) {
	unsigned char state[16]; // Stores the first 16 bytes of original message

	for (int i = 0; i < 16; i++) {
		state[i] = message[i];
	}

	int numberOfRounds = 9;

	eAddRoundKey(state, expandedKey); // Initial round

	for (int i = 0; i < numberOfRounds; i++) {
		eRound(state, expandedKey + (16 * (i + 1)));
	}

	//eRound(state, expandedKey);
	//eRound(state, expandedKey + 16);

	eFinalRound(state, expandedKey + 160);

	// Copy encrypted state to buffer
	for (int i = 0; i < 16; i++) {
		encryptedMessage[i] = state[i];
	}
}

/* Addition is same as subtraction for GF it's just XOR */
void dSubRoundKey(unsigned char * state, unsigned char * roundKey) {
	for (int i = 0; i < 16; i++) {
		state[i] ^= roundKey[i];
	}
}

void dInverseMixColumns(unsigned char * state) {
	unsigned char tmp[16];

	tmp[0] = (unsigned char)mul14[state[0]] ^ mul11[state[1]] ^ mul13[state[2]] ^ mul9[state[3]];
	tmp[1] = (unsigned char)mul9[state[0]] ^ mul14[state[1]] ^ mul11[state[2]] ^ mul13[state[3]];
	tmp[2] = (unsigned char)mul13[state[0]] ^ mul9[state[1]] ^ mul14[state[2]] ^ mul11[state[3]];
	tmp[3] = (unsigned char)mul11[state[0]] ^ mul13[state[1]] ^ mul9[state[2]] ^ mul14[state[3]];

	tmp[4] = (unsigned char)mul14[state[4]] ^ mul11[state[5]] ^ mul13[state[6]] ^ mul9[state[7]];
	tmp[5] = (unsigned char)mul9[state[4]] ^ mul14[state[5]] ^ mul11[state[6]] ^ mul13[state[7]];
	tmp[6] = (unsigned char)mul13[state[4]] ^ mul9[state[5]] ^ mul14[state[6]] ^ mul11[state[7]];
	tmp[7] = (unsigned char)mul11[state[4]] ^ mul13[state[5]] ^ mul9[state[6]] ^ mul14[state[7]];

	tmp[8] = (unsigned char)mul14[state[8]] ^ mul11[state[9]] ^ mul13[state[10]] ^ mul9[state[11]];
	tmp[9] = (unsigned char)mul9[state[8]] ^ mul14[state[9]] ^ mul11[state[10]] ^ mul13[state[11]];
	tmp[10] = (unsigned char)mul13[state[8]] ^ mul9[state[9]] ^ mul14[state[10]] ^ mul11[state[11]];
	tmp[11] = (unsigned char)mul11[state[8]] ^ mul13[state[9]] ^ mul9[state[10]] ^ mul14[state[11]];

	tmp[12] = (unsigned char)mul14[state[12]] ^ mul11[state[13]] ^ mul13[state[14]] ^ mul9[state[15]];
	tmp[13] = (unsigned char)mul9[state[12]] ^ mul14[state[13]] ^ mul11[state[14]] ^ mul13[state[15]];
	tmp[14] = (unsigned char)mul13[state[12]] ^ mul9[state[13]] ^ mul14[state[14]] ^ mul11[state[15]];
	tmp[15] = (unsigned char)mul11[state[12]] ^ mul13[state[13]] ^ mul9[state[14]] ^ mul14[state[15]];

	for (int i = 0; i < 16; i++) {
		state[i] = tmp[i];
	}
}

/* Shifts rows right (rather than left) for decryption */
void dShiftRows(unsigned char * state) {
	unsigned char tmp[16];

	/* Column 1 */
	tmp[0] = state[0];
	tmp[1] = state[13];
	tmp[2] = state[10];
	tmp[3] = state[7];

	/* Column 2 */
	tmp[4] = state[4];
	tmp[5] = state[1];
	tmp[6] = state[14];
	tmp[7] = state[11];

	/* Column 3 */
	tmp[8] = state[8];
	tmp[9] = state[5];
	tmp[10] = state[2];
	tmp[11] = state[15];

	/* Column 4 */
	tmp[12] = state[12];
	tmp[13] = state[9];
	tmp[14] = state[6];
	tmp[15] = state[3];

	for (int i = 0; i < 16; i++) {
		state[i] = tmp[i];
	}
}

void dSubBytes(unsigned char * state) {
	for (int i = 0; i < 16; i++) { // Perform substitution to each of the 16 bytes
		state[i] = inv_s[state[i]];
	}
}


void dRound(unsigned char * state, unsigned char * key) {
	dSubRoundKey(state, key);
	dInverseMixColumns(state);
	dShiftRows(state);
	dSubBytes(state);
}

void dInitialRound(unsigned char * state, unsigned char * key) {
	dSubRoundKey(state, key);
	dShiftRows(state);
	dSubBytes(state);
}

void AESDecrypt(unsigned char * encryptedMessage, unsigned char * expandedKey, unsigned char * decryptedMessage)
{
	unsigned char state[16]; // Stores the first 16 bytes of encrypted message

	for (int i = 0; i < 16; i++) {
		state[i] = encryptedMessage[i];
	}

	dInitialRound(state, expandedKey+160);

	int numberOfRounds = 9;

	/*
	 * This is what was wrong before;
	 * to do the reverse for decryption 
	 * i must start at 8 and go backwards instead!
	 */
	for (int i = 8; i>=0; i--) {
		dRound(state, expandedKey + (16 * (i + 1)));
	}
	
	dSubRoundKey(state, expandedKey); // Final round
	
	// Copy decrypted state to buffer
	for (int i = 0; i < 16; i++) {
		decryptedMessage[i] = state[i];
	}
}

int main() {

	unsigned char key[16] =
	{
		1, 2, 3, 4,
		5, 6, 7, 8,
		9, 10, 11, 12,
		13, 14, 15, 16
	};
	unsigned char expandedKey[176];

	KeyExpansion(key, expandedKey);


	/* TEST EACH FUNCTION STEP BY STEP */

	unsigned char message[] = "Byebye World!!";

	/* Pad message*/
	int originalLen = strlen((const char *)message);
	cout << "Original len:" << originalLen << endl;

	int paddedMessageLen = originalLen;

	if ((paddedMessageLen % 16) != 0) {
		paddedMessageLen = (paddedMessageLen / 16 + 1) * 16;
	}

	unsigned char * paddedMessage = new unsigned char[paddedMessageLen];
	for (int i = 0; i < paddedMessageLen; i++) {
		if (i >= originalLen) {
			paddedMessage[i] = 0;
		}
		else {
			paddedMessage[i] = message[i];
		}
	}
	cout << "Padded Len:" << paddedMessageLen << endl;

	unsigned char state[16]; // Stores the first 16 bytes of original message

	for (int i = 0; i < 16; i++) {
		state[i] = message[i];
	}

	unsigned char * encryptedMessage = new unsigned char[paddedMessageLen];
	unsigned char * decryptedMessage = new unsigned char[paddedMessageLen];

	AESEncrypt(state, key, encryptedMessage);

	AESDecrypt(encryptedMessage, key, decryptedMessage);

	cout << decryptedMessage << endl;

	delete[] encryptedMessage;
	delete[] decryptedMessage;
	// Test the function eSubBytes
	/*eSubBytes(state);
	for (int i = 0; i < 16; i++) {
		message[i] = state[i];
	}
	cout << "State of message is now: ";
	for (int i = 0; i < paddedMessageLen; i++) {
		cout << hex << (int)message[i];
		cout << " ";
	}
	cout << " after eSubBytes." << endl;
	cout << "State of message is now: " << message << " after eSubBytes." << endl;

	eRound(state, expandedKey + 16);
	for (int i = 0; i < 16; i++) {
		message[i] = state[i];
	}
	cout << "State of message is now: ";
	for (int i = 0; i < paddedMessageLen; i++) {
		cout << hex << (int)message[i];
		cout << " ";
	}
	cout << " after 1 eRound." << endl;
	cout << "State of message is now: " << message << " after 1 eRound." << endl;

	// Now decrypt

	dRound(state, expandedKey + 16);
	for (int i = 0; i < 16; i++) {
		message[i] = state[i];
	}
	cout << "State of message is now: ";
	for (int i = 0; i < paddedMessageLen; i++) {
		cout << hex << (int)message[i];
		cout << " ";
	}
	cout << " after 1 dRound." << endl;
	cout << "State of message is now: " << message << " after 1 dRound." << endl;

	dSubBytes(state);
	for (int i = 0; i < 16; i++) {
		message[i] = state[i];
	}
	cout << "State of message is now: ";
	for (int i = 0; i < paddedMessageLen; i++) {
		cout << hex << (int)message[i];
		cout << " ";
	}
	cout << " after dSubBytes." << endl;

	cout << "State of message is now: " << message << " after dSubBytes." << endl;

	cout << "Len is: "  << (int) strlen((const char *)message) << endl;*/

	return 0;
}