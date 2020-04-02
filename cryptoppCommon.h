
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "cryptopp/aes.h"
#include "cryptopp/base64.h"
#include "cryptopp/config.h"  
#include "cryptopp/eccrypto.h" 
#include "cryptopp/files.h"
#include "cryptopp/filters.h"
#include "cryptopp/gzip.h"
#include "cryptopp/hex.h" 
#include "cryptopp/hmac.h" 
#include "cryptopp/md5.h" 
#include "cryptopp/modes.h" 
#include "cryptopp/oids.h" 
#include "cryptopp/osrng.h" 
#include "cryptopp/randpool.h"  
#include "cryptopp/rsa.h" 
#include "cryptopp/sha.h" 

#include <iostream>   
  
using namespace std; 
// NAMESPACE_BEGIN(CryptoPP)
using namespace CryptoPP;

class CryptoppCommon
{
public:
	CryptoppCommon(){};
	~CryptoppCommon(){};

	//------------------------   
	//生成 RSA 密钥对  
	//------------------------  
	void GenerateRSAKey(unsigned int keyLength, const char *privFilename, const char *pubFilename, const char *seed);   
 	
	//------------------------   
	// RSA 加密  
	//------------------------ 
 	string RSAEncryptString(const char *pubFilename, const char *seed, const char *message);   
	
	//------------------------   
	// RSA  解密  
	//------------------------ 
	string RSADecryptString(const char *privFilename, const char *ciphertext);   
	
	//------------------------   
	// 定义全局的随机数池  
	//------------------------ 
	RandomPool & GlobalRNG();

	//------------------------   
	// md5数据加密 
	//------------------------ 
	string md5(std::string text);

	//------------------------   
	// md5数据解密 
	//------------------------ 
	string md5Decrypt(std::string text);

	//------------------------   
	// md5文件加密 
	//------------------------ 
	string md5Source(std::string filename);

	//------------------------   
	// base64数据加密 
	//------------------------ 
	string base64Encode(string text);

	//------------------------   
	// base64数据加密 
	//------------------------ 
	string base64Decode(string text);


	//------------------------   
	// sha256数据加密 
	//------------------------ 
	string sha256Encode(string text);

	//------------------------   
	// sha256文件加密 
	//------------------------ 
	string sha256FileEncode(string filename);

	//------------------------   
	// sha256数据加密 
	//------------------------ 
	string sha256Decode(string text);

	//------------------------   
	// 压缩文件 
	//------------------------ 
	void zipFile(string srcFile, string zipFile);

	//------------------------   
	// 解压文件 
	//------------------------ 
	void GunzipFile(const char *in, const char *out);

	//------------------------   
	// AES数据加密 
	//------------------------ 
	string AESEncryptString(const char *hexKey, const char *hexIV, string infile);

	//------------------------   
	// AES数据解密
	//------------------------ 
	string AESDecryptString(const char *hexKey, const char *hexIV, string infile);

	//------------------------   
	// hmacsha256
	//------------------------ 
	string Hash256(string text, string key);

	//------------------------   
	//生成 ECC 密钥对  
	//------------------------ 
	//void GenerateEccKeys(string& privateKey, string& publicKey);

	//------------------------   
	//ECC加密  
	//------------------------ 
    	//string EccEncrypt(const string& publicKey, const string& text);

    	//ECC解密
    	//string EccDecrypt(const string& privateKey, const string& text);
};
// NAMESPACE_END  // CryptoPP
