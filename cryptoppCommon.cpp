#include "cryptoppCommon.h"

// NAMESPACE_BEGIN(CryptoPP)

void CryptoppCommon::GenerateRSAKey(unsigned int keyLength, const char *privFilename, const char *pubFilename, const char *seed)
{
	CryptoPP::RandomPool randPool;
	randPool.IncorporateEntropy((byte *)seed, strlen(seed));   

	RSAES_OAEP_SHA_Decryptor priv(randPool, keyLength);   
	HexEncoder privFile(new FileSink(privFilename));   
	priv.AccessMaterial().Save(privFile);   
	privFile.MessageEnd();   

	RSAES_OAEP_SHA_Encryptor pub(priv);   
	HexEncoder pubFile(new FileSink(pubFilename));   
	pub.AccessMaterial().Save(pubFile);   
	pubFile.MessageEnd();  
} 
 	
string CryptoppCommon::RSAEncryptString(const char *pubFilename, const char *seed, const char *message)
{
	FileSource pubFile(pubFilename, true, new HexDecoder);  
	RSAES_OAEP_SHA_Encryptor pub(pubFile);  

	RandomPool randPool;  
	randPool.IncorporateEntropy((byte *)seed, strlen(seed));  

	string result;  
	StringSource(message, true, new PK_EncryptorFilter(randPool, pub, new HexEncoder(new StringSink(result))));  
	return result; 
}  

string CryptoppCommon::RSADecryptString(const char *privFilename, const char *ciphertext)
{
	FileSource privFile(privFilename, true, new HexDecoder);  
	RSAES_OAEP_SHA_Decryptor priv(privFile);  

	string result;  
	StringSource(ciphertext, true, new HexDecoder(new PK_DecryptorFilter(GlobalRNG(), priv, new StringSink(result))));  
	return result;
}  

RandomPool & CryptoppCommon::GlobalRNG()
{
	static RandomPool randomPool;  
	return randomPool;  
}

string CryptoppCommon::md5(std::string text)
{
	std::string digest;
	CryptoPP::Weak1::MD5 md5;
	CryptoPP::HashFilter hashfilter(md5);
	hashfilter.Attach(new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest), false));
	hashfilter.Put(reinterpret_cast<const unsigned char*>(text.c_str()), text.length());
	hashfilter.MessageEnd();
	return digest;
}

string CryptoppCommon::md5Decrypt(std::string text)
{
	std::string digest;
	return digest;
}

string CryptoppCommon::md5Source(std::string filename)
{
	std::string digest;
	CryptoPP::Weak1::MD5 md5;
	CryptoPP::HashFilter hashfilter(md5);
	hashfilter.Attach(new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest), false));
	CryptoPP::FileSource(filename.c_str(), true, &hashfilter);
	return digest;
}

string CryptoppCommon::base64Encode(std::string text)
{
	string encode;
    StringSource(text, true, new Base64Encoder(new StringSink(encode)));
    return encode;
}

string CryptoppCommon::base64Decode(std::string text)
{
	string decode;
    StringSource(text, true, new Base64Decoder(new StringSink(decode)));
    return decode;
}

string CryptoppCommon::sha256Encode(string text)
{
	SHA256 sha256;
	string encode;
    StringSource(text, true, new HashFilter(sha256, new HexEncoder(new StringSink(encode))));

 //    string Digest;
 //    SHA256 sha256Tmp;
	// int DigestSize = sha256Tmp.DigestSize();
	// char* byDigest = new char[ DigestSize ];
	// sha256Tmp.CalculateDigest((byte*)byDigest, (const byte *)text.c_str(), text.size());
	// Digest = byDigest;
	// delete []byDigest;
	// byDigest = NULL;
	// cout <<"Digest==========:" <<Digest << endl;
    return encode;
}

string CryptoppCommon::sha256FileEncode(string filename)
{
	SHA256 sha256;
	string encode;
    FileSource(filename.c_str(), true, new HashFilter(sha256, new HexEncoder(new StringSink(encode))));
    return encode;
}

string CryptoppCommon::sha256Decode(string text)
{
	SHA256 sha256;
	string decode;
    StringSource(text, true, new HashFilter(sha256, new HexDecoder(new StringSink(decode))));
    return decode;
}

void CryptoppCommon::zipFile(string srcFile, string zipFile)
{
	FileSource(srcFile.c_str(), true, new Gzip(new FileSink(zipFile.c_str())));
}

void CryptoppCommon::GunzipFile(const char *in, const char *out)
{
	FileSource(in, true, new Gunzip(new FileSink(out)));
}

// NAMESPACE_END  // CryptoPP