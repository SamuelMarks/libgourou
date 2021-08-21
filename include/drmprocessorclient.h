/*
  Copyright 2021 Grégory Soutadé

  This file is part of libgourou.

  libgourou is free software: you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  libgourou is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with libgourou. If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _DRMPROCESSORCLIENT_H_
#define _DRMPROCESSORCLIENT_H_

#include <string>
#include <bytearray.h>

namespace gourou
{
    /**
     * @brief All fucntions that must be implemented by a client
     * This allow libgourou to have only few external libraries dependencies
     * and improve code portability
     */

    class DigestInterface
    {
    public:
	/**
	 * @brief Create a digest handler (for now only SHA1 is used)
	 *
	 * @param digestName      Digest name to instanciate
	 */
	virtual void* createDigest(const std::string& digestName) = 0;

	/**
	 * @brief Update digest engine with new data
	 *
	 * @param handler         Digest handler
	 * @param data            Data to digest
	 * @param length          Length of data
	 *
	 * @return OK/KO
	 */
	virtual int digestUpdate(void* handler, unsigned char* data, unsigned int length) = 0;

	/**
	 * @brief Finalize digest with remained buffered data and destroy handler
	 *
	 * @param handler         Digest handler
	 * @param digestOut       Digest result (buffer must be pre allocated with right size)
	 *
	 * @return OK/KO
	 */
	virtual int digestFinalize(void* handler, unsigned char* digestOut) = 0;

	/**
	 * @brief Global digest function
	 *
	 * @param digestName      Digest name to instanciate
	 * @param data            Data to digest
	 * @param length          Length of data
	 * @param digestOut       Digest result (buffer must be pre allocated with right size)
	 *
	 * @return OK/KO
	 */
	virtual int digest(const std::string& digestName, unsigned char* data, unsigned int length, unsigned char* digestOut) = 0;
    };

    class RandomInterface
    {
    public:
	/**
	 * @brief Generate random bytes
	 *
	 * @param bytesOut        Buffer to fill with random bytes
	 * @param length          Length of bytesOut
	 */
	virtual void randBytes(unsigned char* bytesOut, unsigned int length) = 0;
    };

    class HTTPInterface
    {
    public:
	
	/**
	 * @brief Send HTTP (GET or POST) request
	 *
	 * @param URL             HTTP URL
	 * @param POSTData        POST data if needed, if not set, a GET request is done
	 * @param contentType     Optional content type of POST Data
	 * @param responseHeaders Optional Response headers of HTTP request
	 *
	 * @return data of HTTP response
	 */
	virtual std::string sendHTTPRequest(const std::string& URL, const std::string& POSTData=std::string(""), const std::string& contentType=std::string(""), std::map<std::string, std::string>* responseHeaders=0) = 0;
    };

    class RSAInterface
    {
    public:
	enum RSA_KEY_TYPE {
	    RSA_KEY_PKCS12 = 0,
	    RSA_KEY_X509
	};

	/**
	 * @brief Encrypt data with RSA private key. Data is padded using PKCS1.5
	 *
	 * @param RSAKey         RSA key in binary form
	 * @param RSAKeyLength   RSA key length
	 * @param keyType        Key type
	 * @param password       Optional password for RSA PKCS12 certificate
	 * @param data           Data to encrypt
	 * @param dataLength     Data length
	 * @param res            Encryption result (pre allocated buffer)
	 */
	virtual void RSAPrivateEncrypt(const unsigned char* RSAKey, unsigned int RSAKeyLength,
				       const RSA_KEY_TYPE keyType, const std::string& password,
				       const unsigned char* data, unsigned dataLength,
				       unsigned char* res) = 0;
			    
	/**
	 * @brief Encrypt data with RSA public key. Data is padded using PKCS1.5
	 *
	 * @param RSAKey         RSA key in binary form
	 * @param RSAKeyLength   RSA key length
	 * @param keyType        Key type
	 * @param password       Optional password for RSA PKCS12 certificate
	 * @param data           Data to encrypt
	 * @param dataLength     Data length
	 * @param res            Encryption result (pre allocated buffer)
	 */
	virtual void RSAPublicEncrypt(const unsigned char* RSAKey, unsigned int RSAKeyLength,
				      const RSA_KEY_TYPE keyType,
				      const unsigned char* data, unsigned dataLength,
				      unsigned char* res) = 0;

	/**
	 * @brief Generate RSA key. Expnonent is fixed (65537 / 0x10001)
	 *
	 * @param keyLengthBits  Length of key (in bits) to generate
	 *
	 * @return generatedKey
	 */
	virtual void* generateRSAKey(int keyLengthBits) = 0;

	/**
	 * @brief Destroy key previously generated
	 *
	 * @param handler        Key to destroy
	 */
 	virtual void destroyRSAHandler(void* handler) = 0;

	/**
	 * @brief Extract public key (big number) from RSA handler
	 *
	 * @param handler        RSA handler (generated key)
	 * @param keyOut         Pre allocated buffer (if *keyOut != 0). If *keyOut is 0, memory is internally allocated (must be freed)
	 * @param keyOutLength   Length of result
	 */
	virtual void extractRSAPublicKey(void* handler, unsigned char** keyOut, unsigned int* keyOutLength) = 0;

	/**
	 * @brief Extract private key (big number) from RSA handler
	 *
	 * @param handler        RSA handler (generated key)
	 * @param keyOut         Pre allocated buffer (if *keyOut != 0). If *keyOut is 0, memory is internally allocated (must be freed)
	 * @param keyOutLength   Length of result
	 */
	virtual void extractRSAPrivateKey(void* handler, unsigned char** keyOut, unsigned int* keyOutLength) = 0;

	/**
	 * @brief Extract certificate from PKCS12 blob
	 *
	 * @param RSAKey         RSA key in binary form
	 * @param RSAKeyLength   RSA key length
	 * @param keyType        Key type
	 * @param password       Optional password for RSA PKCS12 certificate
	 * @param certOut        Result certificate
	 * @param certOutLength  Result certificate length
	 */
	virtual void extractCertificate(const unsigned char* RSAKey, unsigned int RSAKeyLength,
					const RSA_KEY_TYPE keyType, const std::string& password,
					unsigned char** certOut, unsigned int* certOutLength) = 0;
    };

    class CryptoInterface
    {
    public:
	enum CHAINING_MODE {
	    CHAIN_ECB=0,
	    CHAIN_CBC
	};
	
	/**
	 * @brief Do AES encryption. If length of data is not multiple of 16, PKCS#5 padding is done
	 *
	 * @param chaining       Chaining mode
	 * @param key            AES key
	 * @param keyLength      AES key length
	 * @param iv             IV key
	 * @param ivLength       IV key length
	 * @param dataIn         Data to encrypt
	 * @param dataInLength   Data length
	 * @param dataOut        Encrypted data
	 * @param dataOutLength  Length of encrypted data
	 */
	virtual void AESEncrypt(CHAINING_MODE chaining,
				const unsigned char* key, unsigned int keyLength,
				const unsigned char* iv, unsigned int ivLength,
				const unsigned char* dataIn, unsigned int dataInLength,
				unsigned char* dataOut, unsigned int* dataOutLength) = 0;

	/**
	 * @brief Init AES CBC encryption
	 *
	 * @param chaining       Chaining mode
	 * @param key            AES key
	 * @param keyLength      AES key length
	 * @param iv             IV key
	 * @param ivLength       IV key length
	 *
	 * @return AES handler
	 */
	virtual void* AESEncryptInit(CHAINING_MODE chaining,
				     const unsigned char* key, unsigned int keyLength,
				     const unsigned char* iv=0, unsigned int ivLength=0) = 0;

	/**
	 * @brief Encrypt data
	 *
	 * @param handler        AES handler
	 * @param dataIn         Data to encrypt
	 * @param dataInLength   Data length
	 * @param dataOut        Encrypted data
	 * @param dataOutLength  Length of encrypted data
	 */
	virtual void AESEncryptUpdate(void* handler, const unsigned char* dataIn, unsigned int dataInLength,
			 unsigned char* dataOut, unsigned int* dataOutLength) = 0;

	/**
	 * @brief Finalize AES encryption (pad and encrypt last block if needed)
	 * Destroy handler at the end
	 *
	 * @param handler        AES handler
	 * @param dataOut        Last block of encrypted data
	 * @param dataOutLength  Length of encrypted data
	 */
	virtual void AESEncryptFinalize(void* handler, unsigned char* dataOut, unsigned int* dataOutLength) = 0;

	/**
	 * @brief Do AES decryption. If length of data is not multiple of 16, PKCS#5 padding is done
	 *
	 * @param chaining       Chaining mode
	 * @param key            AES key
	 * @param keyLength      AES key length
	 * @param iv             IV key
	 * @param ivLength       IV key length
	 * @param dataIn         Data to encrypt
	 * @param dataInLength   Data length
	 * @param dataOut        Encrypted data
	 * @param dataOutLength  Length of encrypted data
	 */
	virtual void AESDecrypt(CHAINING_MODE chaining,
				const unsigned char* key, unsigned int keyLength,
				const unsigned char* iv, unsigned int ivLength,
				const unsigned char* dataIn, unsigned int dataInLength,
				unsigned char* dataOut, unsigned int* dataOutLength) = 0;

	/**
	 * @brief Init AES decryption
	 *
	 * @param chaining       Chaining mode
	 * @param key            AES key
	 * @param keyLength      AES key length
	 * @param iv             IV key
	 * @param ivLength       IV key length
	 *
	 * @return AES handler
	 */
	virtual void* AESDecryptInit(CHAINING_MODE chaining,
				     const unsigned char* key, unsigned int keyLength,
				     const unsigned char* iv=0, unsigned int ivLength=0) = 0;

	/**
	 * @brief Decrypt data
	 *
	 * @param handler        AES handler
	 * @param dataIn         Data to decrypt
	 * @param dataInLength   Data length
	 * @param dataOut        Decrypted data
	 * @param dataOutLength  Length of decrypted data
	 */
	virtual void AESDecryptUpdate(void* handler, const unsigned char* dataIn, unsigned int dataInLength,
				 unsigned char* dataOut, unsigned int* dataOutLength) = 0;
	/**
	 * @brief Finalize AES decryption (decrypt last block and remove padding if it is set).
	 * Destroy handler at the end
	 *
	 * @param handler        AES handler
	 * @param dataOut        Last block decrypted data
	 * @param dataOutLength  Length of decrypted data
	 */
	virtual void AESDecryptFinalize(void* handler, unsigned char* dataOut, unsigned int* dataOutLength) = 0;
    };


    class ZIPInterface
    {
    public:
	/**
	 * @brief Open a zip file and return an handler
	 *
	 * @param path           Path of zip file
	 *
	 * @return ZIP file handler
	 */
	virtual void* zipOpen(const std::string& path) = 0;
	
	/**
	 * @brief Read zip internal file
	 *
	 * @param handler        ZIP file handler
	 * @param path           Internal path inside zip file
	 *
	 * @return File content
	 */
	virtual std::string zipReadFile(void* handler, const std::string& path) = 0;
	
	/**
	 * @brief Write zip internal file
	 *
	 * @param handler        ZIP file handler
	 * @param path           Internal path inside zip file
	 * @param content        Internal file content
	 */
	virtual void zipWriteFile(void* handler, const std::string& path, const std::string& content) = 0;

	/**
	 * @brief Delete zip internal file
	 *
	 * @param handler        ZIP file handler
	 * @param path           Internal path inside zip file
	 */
	virtual void zipDeleteFile(void* handler, const std::string& path) = 0;

	/**
	 * @brief Close ZIP file handler
	 *
	 * @param handler        ZIP file handler
	 */
	virtual void zipClose(void* handler) = 0;

	/**
	 * @brief Inflate algorithm
	 *
	 * @param data           Data to inflate
	 * @param result         Zipped data
	 * @param wbits          Window bits value for libz
	 */
	virtual void inflate(std::string data, gourou::ByteArray& result,
			     int wbits=-15) = 0;
	
	/**
	 * @brief Deflate algorithm
	 *
	 * @param data           Data to deflate
	 * @param result         Unzipped data
	 * @param wbits          Window bits value for libz
	 * @param compressionLevel Compression level for libz
	 */
	virtual void deflate(std::string data, gourou::ByteArray& result,
			     int wbits=-15, int compressionLevel=8) = 0;
    };
    
    class DRMProcessorClient: public DigestInterface, public RandomInterface, public HTTPInterface, \
			      public RSAInterface, public CryptoInterface, public ZIPInterface
    {};
}
#endif
