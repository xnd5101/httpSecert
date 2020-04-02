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
	CryptoPP::Weak1::MD5 md5;
	string decode;
    // StringSource(text, true, new HashFilter(md5, new HexDecoder(new StringSink(decode))));
    return decode;
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

SecByteBlock HexDecodeString(const char *hex)
{
	StringSource ss(hex, true, new HexDecoder);
	SecByteBlock result((size_t)ss.MaxRetrievable());
	ss.Get(result, result.size());
	return result;
}

string CryptoppCommon::AESEncryptString(const char *hexKey, const char *hexIV, string text)
{
	string result;
	// SecByteBlock key = HexDecodeString(hexKey);
	// SecByteBlock iv = HexDecodeString(hexIV);
	// byte iv[AES::BLOCKSIZE]="123456";

    AES::Encryption aesEncryption((byte *)hexKey, AES::DEFAULT_KEYLENGTH);
	CFB_Mode_ExternalCipher::Encryption cfbEncryption(aesEncryption, (byte*)hexIV);
    StreamTransformationFilter cfbEncryptor(cfbEncryption, new HexEncoder(new StringSink(result)));
    cfbEncryptor.Put((byte *)text.c_str(), text.length());
    cfbEncryptor.MessageEnd();

    return result;
}


string CryptoppCommon::AESDecryptString(const char *hexKey, const char *hexIV, string text)
{
	string result;
	// SecByteBlock key = HexDecodeString(hexKey);
	// SecByteBlock iv = HexDecodeString(hexIV);
	// byte iv[AES::BLOCKSIZE]="123456";

	CFB_Mode<AES >::Decryption cfbDecryption((byte *)hexKey, AES::DEFAULT_KEYLENGTH, (byte*)hexIV);
    HexDecoder decryptor(new StreamTransformationFilter(cfbDecryption, new StringSink(result)));
    decryptor.Put((byte *)text.c_str(), text.length());
    decryptor.MessageEnd();
	return result;
}

string CryptoppCommon::Hash256(string text, string key)
{
	string mac;
	HMAC<SHA256> hmac((const byte*)key.data(), key.size());  
    StringSource(text, true, new HashFilter(hmac, new StringSink(mac)));  
 
    string encoder; 
    StringSource(mac, true, new HexEncoder(new StringSink(encoder)));  
    return encoder;
}

/*
void CryptoppCommon::GenerateEccKeys(string& sPrivateKey, string& sPublicKey)
{
	using namespace CryptoPP;
    // Random pool, the second parameter is the length of key
    // 随机数池，第二个参数是生成密钥的长
    AutoSeededRandomPool rnd(false, 256);
    //AutoSeededRandomPool rnd;

    ECIES<ECP>::PrivateKey  privateKey;
    ECIES<ECP>::PublicKey   publicKey;
    // Generate private key
    // 生成私钥
    privateKey.Initialize(rnd, ASN1::secp521r1());
    // Generate public key using private key
    // 用私钥生成密钥
    privateKey.MakePublicKey(publicKey);

    ECIES<ECP>::Encryptor encryptor(publicKey);
    HexEncoder pubEncoder(new StringSink(sPublicKey));
    //encryptor.DEREncode(pubEncoder);
    publicKey.DEREncode(pubEncoder);
    pubEncoder.MessageEnd();

    ECIES<ECP>::Decryptor decryptor(privateKey);
    HexEncoder prvEncoder(new StringSink(sPrivateKey));
    // decryptor.DEREncode(prvEncoder);
    privateKey.DEREncode(prvEncoder);
    prvEncoder.MessageEnd();
}

string CryptoppCommon::EccEncrypt(const string& publicKey, const string& text)
{
	cout << "11111" << endl;
    // If to save the keys into a file, FileSource should be replace StringSource
    // 如果需要把密钥保存到文件里，可以用 FileSource
    StringSource pubString(publicKey, true, new HexDecoder);
    cout << "5555" << endl;
    ECIES<ECP>::Encryptor encryptor(pubString);
    cout << "222222" << endl;
 
    // Calculate the length of cipher text
    // 计算加密后密文的长度
    size_t uiCipherTextSize = encryptor.CiphertextLength(text.length());
    std::string sCipherText;
    sCipherText.resize(uiCipherTextSize);
    cout << "333333" << endl;
    RandomPool rnd;
    encryptor.Encrypt(rnd, (byte*)(text.c_str()), text.length(), (byte*)(sCipherText.data()));
    cout << "4444" << endl;
    return sCipherText;
}

string CryptoppCommon::EccDecrypt(const string& privateKey, const string& text)
{

    StringSource privString(privateKey, true, new HexDecoder);
    ECIES<ECP>::Decryptor decryptor(privString);
 
    auto sPlainTextLen = decryptor.MaxPlaintextLength(text.size());
    std::string sDecryText;
    sDecryText.resize(sPlainTextLen);
    RandomPool rnd;
    decryptor.Decrypt(rnd, (byte*)text.c_str(), text.size(), (byte*)sDecryText.data());
    return sDecryText;
}
*/
// NAMESPACE_END  // CryptoPP
