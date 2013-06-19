#pragma once
class Aes
{
public:
	Aes(void){}
	Aes(const char* password);
	~Aes(void){}
	
	unsigned char State[4][4];  
	void Cipher(unsigned char* input, unsigned char* output);  // encipher 16-bit input  
	void InvCipher(unsigned char* input, unsigned char* output);  // decipher 16-bit input

// 	static int EncryptFile(const char *filename, 
// 		const char *password, 
// 		const char *newname = NULL);
// 	static int DecryptFile(const char *filename, const char *password);

private:  
	int Nb;         // block size in 32-bit words.  Always 4 for AES.  (128 bits).  
	int Nk;         // key size in 32-bit words.  4, 6, 8.  (128, 192, 256 bits).  
	int Nr;         // number of rounds. 10, 12, 14.  

	unsigned char key[32];  
	unsigned char w[16*15];  

	void SetNbNkNr(int keySize);  
	void AddRoundKey(int round);      //����Կ��  
	void SubBytes();                  //S���ֽڴ���  
	void InvSubBytes();               //��S���ֽڴ���  
	void ShiftRows();                 //����λ  
	void InvShiftRows();  
	void MixColumns();                //�л���  
	void InvMixColumns();  
	unsigned char gfmultby01(unsigned char b);  
	unsigned char gfmultby02(unsigned char b);  
	unsigned char gfmultby03(unsigned char b);  
	unsigned char gfmultby09(unsigned char b);  
	unsigned char gfmultby0b(unsigned char b);  
	unsigned char gfmultby0d(unsigned char b);  
	unsigned char gfmultby0e(unsigned char b);  
	void KeyExpansion();              //��Կ��չ  
	unsigned char* SubWord(unsigned char* word);         //��ԿS���ִ���  
	unsigned char* RotWord(unsigned char* word);         //��Կ��λ  
};

