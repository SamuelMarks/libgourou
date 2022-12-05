/*
  Copyright (c) 2021, Grégory Soutadé

  All rights reserved.
  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:
  
  * Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
  * Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
  * Neither the name of the copyright holder nor the
    names of its contributors may be used to endorse or promote products
    derived from this software without specific prior written permission.
  
  THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY
  EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE REGENTS AND CONTRIBUTORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef _DRMPROCESSORCLIENTIMPL_H_
#define _DRMPROCESSORCLIENTIMPL_H_

#include <string>

#if OPENSSL_VERSION_MAJOR >= 3
#include <openssl/provider.h>
#endif

#include <drmprocessorclient.h>

class DRMProcessorClientImpl : public gourou::DRMProcessorClient
{
public:
    DRMProcessorClientImpl();
    ~DRMProcessorClientImpl();
    
    /* Digest interface */
    virtual void* createDigest(const std::string& digestName);
    virtual void digestUpdate(void* handler, unsigned char* data, unsigned length);
    virtual void digestFinalize(void* handler,unsigned char* digestOut);
    virtual void digest(const std::string& digestName, unsigned char* data, unsigned length, unsigned char* digestOut);

    /* Random interface */
    virtual void randBytes(unsigned char* bytesOut, unsigned length);

    /* HTTP interface */
    virtual std::string sendHTTPRequest(const std::string& URL, const std::string& POSTData=std::string(""), const std::string& contentType=std::string(""), std::map<std::string, std::string>* responseHeaders=0, int fd=0, bool resume=false);

    virtual void RSAPrivateEncrypt(const unsigned char* RSAKey, unsigned RSAKeyLength,
				   const RSA_KEY_TYPE keyType, const std::string& password,
				   const unsigned char* data, unsigned dataLength,
				   unsigned char* res);
			    
    virtual void RSAPrivateDecrypt(const unsigned char* RSAKey, unsigned RSAKeyLength,
				   const RSA_KEY_TYPE keyType, const std::string& password,
				   const unsigned char* data, unsigned dataLength,
				   unsigned char* res);

    virtual void RSAPublicEncrypt(const unsigned char* RSAKey, unsigned RSAKeyLength,
				  const RSA_KEY_TYPE keyType,
				  const unsigned char* data, unsigned dataLength,
				  unsigned char* res);

    virtual void* generateRSAKey(int keyLengthBits);
    virtual void destroyRSAHandler(void* handler);
    
    virtual void extractRSAPublicKey(void* RSAKeyHandler, unsigned char** keyOut, unsigned* keyOutLength);
    virtual void extractRSAPrivateKey(void* RSAKeyHandler, unsigned char** keyOut, unsigned* keyOutLength);
    virtual void extractCertificate(const unsigned char* RSAKey, unsigned RSAKeyLength,
				    const RSA_KEY_TYPE keyType, const std::string& password,
				    unsigned char** certOut, unsigned* certOutLength);
				 
    /* Crypto interface */
    virtual void encrypt(CRYPTO_ALGO algo, CHAINING_MODE chaining,
			 const unsigned char* key, unsigned keyLength,
			 const unsigned char* iv, unsigned ivLength,
			 const unsigned char* dataIn, unsigned dataInLength,
			 unsigned char* dataOut, unsigned* dataOutLength);

    virtual void* encryptInit(CRYPTO_ALGO algo, CHAINING_MODE chaining,
			      const unsigned char* key, unsigned keyLength,
			      const unsigned char* iv=0, unsigned ivLength=0);


    virtual void encryptUpdate(void* handler, const unsigned char* dataIn, unsigned dataInLength,
				   unsigned char* dataOut, unsigned* dataOutLength);
    virtual void encryptFinalize(void* handler, unsigned char* dataOut, unsigned* dataOutLength);

    virtual void decrypt(CRYPTO_ALGO algo, CHAINING_MODE chaining,
			 const unsigned char* key, unsigned keyLength,
			 const unsigned char* iv, unsigned ivLength,
			 const unsigned char* dataIn, unsigned dataInLength,
			 unsigned char* dataOut, unsigned* dataOutLength);

    virtual void* decryptInit(CRYPTO_ALGO algo, CHAINING_MODE chaining,
			      const unsigned char* key, unsigned keyLength,
			      const unsigned char* iv=0, unsigned ivLength=0);

    virtual void decryptUpdate(void* handler, const unsigned char* dataIn, unsigned dataInLength,
			       unsigned char* dataOut, unsigned* dataOutLength);
    virtual void decryptFinalize(void* handler, unsigned char* dataOut, unsigned* dataOutLength);

    /* ZIP Interface */
    virtual void* zipOpen(const std::string& path);
    
    virtual void zipReadFile(void* handler, const std::string& path, gourou::ByteArray& result, bool decompress=true);
    
    virtual void zipWriteFile(void* handler, const std::string& path, gourou::ByteArray& content);
    
    virtual void zipDeleteFile(void* handler, const std::string& path);
    
    virtual void zipClose(void* handler);
    
    virtual void inflate(gourou::ByteArray& data, gourou::ByteArray& result,
			 int wbits=-15);
	
    virtual void deflate(gourou::ByteArray& data, gourou::ByteArray& result,
			 int wbits=-15, int compressionLevel=8);

private:

    void padWithPKCS1(unsigned char* out, unsigned outLength,
		      const unsigned char* in, unsigned inLength);
    
#if OPENSSL_VERSION_MAJOR >= 3
    OSSL_PROVIDER *legacy, *deflt;
#else
    void *legacy, *deflt;
#endif
};

#endif
