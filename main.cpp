
#include "base64.h"
#include "cryptoppCommon.h"

int main(int argc, char *argv[])
{
	//base64验证
    cout << "base64 test =======" << endl;
	string key = "123456";
	string encodeStr = base64Encode((unsigned char*)key.c_str(), key.length());
	cout << encodeStr << endl;
	string decodeStr = base64Decode(encodeStr);
	cout << decodeStr << endl << endl;

	//rsa验证
    cout<<"rsa test ==========="<<endl; 
	CryptoppCommon item;
	char priKey[128] = {0};   
    char pubKey[128] = {0};   
    char seed[1024] = {0};   
  
    // 生成 RSA 密钥对  
    strcpy(priKey, "pri"); // 生成的私钥文件  
    strcpy(pubKey, "pub"); // 生成的公钥文件  
    strcpy(seed, "seed");   
    item.GenerateRSAKey(1024, priKey, pubKey, seed);   
  
    //RSA 加解密  
    char message[1024] = {0};     
    strcpy(message, "ras test!");   
    string encryptedText = item.RSAEncryptString(pubKey, seed, message); // RSA 加密  
    cout<<"Encrypted Text:"<<encryptedText<<endl;   
    string decryptedText = item.RSADecryptString(priKey, encryptedText.c_str()); // RSA  解密  
    cout<<"Decrypted Text:"<<decryptedText<<endl << endl;

    cout<<"md5 test ==========="<<endl; 
    string md5Test = "md5Test";
    string md5Encrypt = item.md5(md5Test);
    cout<<"md5Encrypt Text:"<<md5Encrypt<<endl << endl;

    cout<<"base64 test ==========="<<endl; 
    string base64Test = "baseTest";
    string encode = item.base64Encode(base64Test);
    cout<<"base64encode Text:"<<encode; 
    string decode = item.base64Decode(encode);
    cout<<"base64decode Text:"<<decode<<endl << endl; 

    cout<<"sha256 test ==========="<<endl; 
    string sha256Test = "shaTest";
    string shaEncode = item.sha256Encode(sha256Test);
    cout<<"encode Text:"<<shaEncode<<endl; 
    // string shaDecode = item.sha256Decode(shaEncode);
    // cout<<"decode Text:"<<shaDecode<<endl << endl; 

    // cout<<"zip test ==========="<<endl; 
    // string srcFile = "README.md";
    // string zipFile = "test.tar.gz";
    // string unzipFile = "t.md";
    // cout<<"zipFile Name:"<<zipFile<<endl;  
    // item.zipFile(srcFile, zipFile);
    // cout<<"unzipFile Name:"<<unzipFile << endl;
    // item.GunzipFile(zipFile.c_str(), unzipFile.c_str());
    
    cout<<"aes test ==========="<<endl; 
    string keyAes = "123456";
    string iv = "abcd";
    string aesTest = "aesTest";
    string aesEncode = item.AESEncryptString(keyAes.c_str(), iv.c_str(), aesTest);
    cout<<"aes encode Text:"<<aesEncode <<endl; 
    iv = "abcd";
    string aesDecode = item.AESDecryptString(keyAes.c_str(), iv.c_str(), aesEncode);
    cout<<"aes decode Text:"<<aesDecode <<endl << endl; 

    cout<<"hmacsha256 test ==========="<<endl; 
    string hmacTest = "hmacTest";
    string keyHmac = "123456";
    string hmacEncrypt = item.Hash256(keyHmac, hmacTest);
    cout<<"hmacEncrypt Text:"<<hmacEncrypt <<endl << endl; 
    /*
    std::string sPrivateKey, sPublicKey;
    item.GenerateEccKeys(sPrivateKey, sPublicKey);
    string eccMsg = "EccTest";
    cout << "sPrivateKey:" << sPrivateKey << endl;
    cout << "sPublickey:" << sPublicKey << endl;
    string EccEncryptedText = item.EccEncrypt(sPrivateKey, eccMsg);
    cout<<"EccEncryptedText Text:"<<EccEncryptedText<<endl;   
    string EccDecryptedText = item.EccDecrypt(sPrivateKey, EccEncryptedText);  
    cout<<"EccDecryptedText Text:"<<EccDecryptedText<<endl << endl;
    */
	return 0;
}
