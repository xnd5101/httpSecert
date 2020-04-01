
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "cryptopp/base64.h"
#include "cryptopp/config.h"  
#include "cryptopp/files.h"
#include "cryptopp/filters.h"
#include "cryptopp/gzip.h"
#include "cryptopp/hex.h" 
#include "cryptopp/md5.h" 
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
	// md5数据加密 
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
};
// NAMESPACE_END  // CryptoPP