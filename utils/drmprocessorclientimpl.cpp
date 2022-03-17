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
#include <bytearray.h>

#include <algorithm> 
#include <cctype>
#include <locale>

#include <openssl/rand.h>
#include <openssl/pkcs12.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <curl/curl.h>

#include <zlib.h>
#include <zip.h>

#include <libgourou_common.h>
#include <libgourou_log.h>
#include "drmprocessorclientimpl.h"

// https://stackoverflow.com/questions/216823/how-to-trim-a-stdstring
// trim from start (in place)
static inline void ltrim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
}

// trim from end (in place)
static inline void rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), s.end());
}

// trim from both ends (in place)
static inline void trim(std::string &s) {
    ltrim(s);
    rtrim(s);
}

/* Digest interface */
void* DRMProcessorClientImpl::createDigest(const std::string& digestName)
{
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_get_digestbyname(digestName.c_str());

    if (EVP_DigestInit(md_ctx, md) != 1)
    {
	EVP_MD_CTX_free(md_ctx);
	return 0;
    }

    return md_ctx;
}

int DRMProcessorClientImpl::digestUpdate(void* handler, unsigned char* data, unsigned int length)
{
    return (EVP_DigestUpdate((EVP_MD_CTX *)handler, data, length)) ? 0 : -1;
}

int DRMProcessorClientImpl::digestFinalize(void* handler, unsigned char* digestOut)
{
    int res = EVP_DigestFinal((EVP_MD_CTX *)handler, digestOut, NULL);
    EVP_MD_CTX_free((EVP_MD_CTX *)handler);
    return (res == 1) ? 0 : -1;
}

int DRMProcessorClientImpl::digest(const std::string& digestName, unsigned char* data, unsigned int length, unsigned char* digestOut)
{
    void* handler = createDigest(digestName);
    if (!handler)
	return -1;
    if (digestUpdate(handler, data, length))
	return -1;
    return digestFinalize(handler, digestOut);
}

/* Random interface */
void DRMProcessorClientImpl::randBytes(unsigned char* bytesOut, unsigned int length)
{
    RAND_bytes(bytesOut, length);
}

/* HTTP interface */
#define DISPLAY_THRESHOLD 10*1024 // Threshold to display download progression

static int downloadProgress(void *clientp, curl_off_t dltotal, curl_off_t dlnow,
			    curl_off_t ultotal, curl_off_t ulnow)
{
// For "big" files only
    if (dltotal >= DISPLAY_THRESHOLD && gourou::logLevel >= gourou::WARN)
    {
	int percent = 0;
	if (dltotal)
	    percent = (dlnow * 100) / dltotal;

	std::cout << "\rDownload " << percent << "%" << std::flush;
    }

    return 0;
}

static size_t curlRead(void *data, size_t size, size_t nmemb, void *userp)
{
    gourou::ByteArray* replyData = (gourou::ByteArray*) userp;
    
    replyData->append((unsigned char*)data, size*nmemb);

    return size*nmemb;
}

static size_t curlReadFd(void *data, size_t size, size_t nmemb, void *userp)
{
    int fd = *(int*) userp;

    size_t res = write(fd, data, size*nmemb);

    downloadedBytes += res;

    return res;
}

static size_t curlHeaders(char *buffer, size_t size, size_t nitems, void *userdata)
{
    std::map<std::string, std::string>* responseHeaders = (std::map<std::string, std::string>*)userdata;
    std::string::size_type pos = 0;
    std::string buf(buffer, size*nitems);

    pos = buf.find(":", pos);

    if (pos != std::string::npos)
    {
	std::string key   = std::string(buffer, pos);
	std::string value = std::string(&buffer[pos+1], (size*nitems)-(pos+1));

	trim(key);
	trim(value);

	(*responseHeaders)[key] = value;
    
	if (gourou::logLevel >= gourou::DEBUG)
	    std::cout << key << " : "  << value << std::endl;
    }
    
    return size*nitems;
}

std::string DRMProcessorClientImpl::sendHTTPRequest(const std::string& URL, const std::string& POSTData, const std::string& contentType, std::map<std::string, std::string>* responseHeaders, int fd)
{
    gourou::ByteArray replyData;
    std::map<std::string, std::string> localHeaders;

    if (!responseHeaders)
	responseHeaders = &localHeaders;
    
    GOUROU_LOG(gourou::INFO, "Send request to " << URL);
    if (POSTData.size())
    {
	GOUROU_LOG(gourou::DEBUG, "<<< " << std::endl << POSTData);
    }

    CURL *curl = curl_easy_init();
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, URL.c_str());
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "book2png");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);

    
    struct curl_slist *list = NULL;
    list = curl_slist_append(list, "Accept: */*");
    std::string _contentType;
    if (contentType.size())
    {
	_contentType = "Content-Type: " + contentType;
	list = curl_slist_append(list, _contentType.c_str());
    }

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);

    if (POSTData.size())
    {
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, POSTData.size());
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, POSTData.data());
    }

    if (fd)
    {
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlReadFd);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&fd);
    }
    else
    {
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlRead);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&replyData);
    }
    
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, curlHeaders);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void*)responseHeaders);
    
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, downloadProgress);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0);
    
    res = curl_easy_perform(curl);
    curl_slist_free_all(list);
    curl_easy_cleanup(curl);
   
    if (res != CURLE_OK)
	EXCEPTION(gourou::CLIENT_NETWORK_ERROR, "Error " << curl_easy_strerror(res));
    
    if (replyData.size() >= DISPLAY_THRESHOLD && gourou::logLevel >= gourou::WARN)
	std::cout << std::endl;

    if ((*responseHeaders)["Content-Type"] == "application/vnd.adobe.adept+xml")
    {
	GOUROU_LOG(gourou::DEBUG, ">>> " << std::endl << replyData.data());
    }
	
    return std::string((char*)replyData.data(), replyData.length());
}

void DRMProcessorClientImpl::RSAPrivateEncrypt(const unsigned char* RSAKey, unsigned int RSAKeyLength,
					       const RSA_KEY_TYPE keyType, const std::string& password,
					       const unsigned char* data, unsigned dataLength,
					       unsigned char* res)
{
    PKCS12 * pkcs12;
    EVP_PKEY* pkey;
    X509* cert;
    STACK_OF(X509)* ca;
    RSA * rsa;

    pkcs12 = d2i_PKCS12(NULL, &RSAKey, RSAKeyLength);
    if (!pkcs12)
	EXCEPTION(gourou::CLIENT_INVALID_PKCS12, ERR_error_string(ERR_get_error(), NULL));
    PKCS12_parse(pkcs12, password.c_str(), &pkey, &cert, &ca);
    rsa = EVP_PKEY_get1_RSA(pkey);

    int ret = RSA_private_encrypt(dataLength, data, res, rsa, RSA_PKCS1_PADDING);

    if (ret < 0)
	EXCEPTION(gourou::CLIENT_RSA_ERROR, ERR_error_string(ERR_get_error(), NULL));

    if (gourou::logLevel >= gourou::DEBUG)
    {
	printf("Encrypted : ");
	for(int i=0; i<ret; i++)
	    printf("%02x ", res[i]);
	printf("\n");
    }
}
			    
void DRMProcessorClientImpl::RSAPrivateDecrypt(const unsigned char* RSAKey, unsigned int RSAKeyLength,
					       const RSA_KEY_TYPE keyType, const std::string& password,
					       const unsigned char* data, unsigned dataLength,
					       unsigned char* res)
{
    BIO* mem=BIO_new_mem_buf(RSAKey, RSAKeyLength);
    PKCS8_PRIV_KEY_INFO* p8inf = d2i_PKCS8_PRIV_KEY_INFO_bio(mem, NULL);

    if (!p8inf)
	EXCEPTION(gourou::CLIENT_INVALID_PKCS8, ERR_error_string(ERR_get_error(), NULL));

    EVP_PKEY* pkey = EVP_PKCS82PKEY(p8inf);
    RSA * rsa;
    int ret;

    rsa = EVP_PKEY_get1_RSA(pkey);

    ret = RSA_private_decrypt(dataLength, data, res, rsa, RSA_NO_PADDING);

    if (ret < 0)
	EXCEPTION(gourou::CLIENT_RSA_ERROR, ERR_error_string(ERR_get_error(), NULL));

    if (gourou::logLevel >= gourou::DEBUG)
    {
	printf("Decrypted : ");
	for(int i=0; i<ret; i++)
	    printf("%02x ", res[i]);
	printf("\n");
    }
}

void DRMProcessorClientImpl::RSAPublicEncrypt(const unsigned char* RSAKey, unsigned int RSAKeyLength,
					      const RSA_KEY_TYPE keyType,
					      const unsigned char* data, unsigned dataLength,
					      unsigned char* res)
{
    X509 * x509 = d2i_X509(0, &RSAKey, RSAKeyLength);
    if (!x509)
	EXCEPTION(gourou::CLIENT_INVALID_CERTIFICATE, "Invalid certificate");
	
    EVP_PKEY * evpKey = X509_get_pubkey(x509);
    RSA* rsa = EVP_PKEY_get1_RSA(evpKey);
    EVP_PKEY_free(evpKey);

    if (!rsa)
	EXCEPTION(gourou::CLIENT_NO_PRIV_KEY, "No private key in certificate");

    int ret = RSA_public_encrypt(dataLength, data, res, rsa, RSA_PKCS1_PADDING);
    if (ret < 0)
	EXCEPTION(gourou::CLIENT_RSA_ERROR, ERR_error_string(ERR_get_error(), NULL));
}

void* DRMProcessorClientImpl::generateRSAKey(int keyLengthBits)
{
    BIGNUM * bn = BN_new();
    RSA * rsa = RSA_new();
    BN_set_word(bn, 0x10001);
    RSA_generate_key_ex(rsa, keyLengthBits, bn, 0);
    BN_free(bn);

    return rsa;
}

void DRMProcessorClientImpl::destroyRSAHandler(void* handler)
{
    RSA_free((RSA*)handler);
}

void DRMProcessorClientImpl::extractRSAPublicKey(void* handler, unsigned char** keyOut, unsigned int* keyOutLength)
{
    EVP_PKEY * evpKey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(evpKey, (RSA*)handler);
    X509_PUBKEY *x509_pubkey = 0;
    X509_PUBKEY_set(&x509_pubkey, evpKey);

    *keyOutLength = i2d_X509_PUBKEY(x509_pubkey, keyOut);

    X509_PUBKEY_free(x509_pubkey);
    EVP_PKEY_free(evpKey);
}

void DRMProcessorClientImpl::extractRSAPrivateKey(void* handler, unsigned char** keyOut, unsigned int* keyOutLength)
{
    EVP_PKEY * evpKey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(evpKey, (RSA*)handler);
    PKCS8_PRIV_KEY_INFO * privKey = EVP_PKEY2PKCS8(evpKey);

    *keyOutLength = i2d_PKCS8_PRIV_KEY_INFO(privKey, keyOut);

    PKCS8_PRIV_KEY_INFO_free(privKey);
    EVP_PKEY_free(evpKey);
}
				 
void DRMProcessorClientImpl::extractCertificate(const unsigned char* RSAKey, unsigned int RSAKeyLength,
						const RSA_KEY_TYPE keyType, const std::string& password,
						unsigned char** certOut, unsigned int* certOutLength)
{
    PKCS12 * pkcs12;
    EVP_PKEY* pkey = 0;
    X509* cert = 0;
    STACK_OF(X509)* ca;

    pkcs12 = d2i_PKCS12(NULL, &RSAKey, RSAKeyLength);
    if (!pkcs12)
	EXCEPTION(gourou::CLIENT_INVALID_PKCS12, ERR_error_string(ERR_get_error(), NULL));
    PKCS12_parse(pkcs12, password.c_str(), &pkey, &cert, &ca);

    *certOutLength = i2d_X509(cert, certOut);

    EVP_PKEY_free(pkey);
}

/* Crypto interface */
void DRMProcessorClientImpl::Encrypt(CRYPTO_ALGO algo, CHAINING_MODE chaining,
				     const unsigned char* key, unsigned int keyLength,
				     const unsigned char* iv, unsigned int ivLength,
				     const unsigned char* dataIn, unsigned int dataInLength,
				     unsigned char* dataOut, unsigned int* dataOutLength)
{
    void* handler = EncryptInit(algo, chaining, key, keyLength, iv, ivLength);
    EncryptUpdate(handler, dataIn, dataInLength, dataOut, dataOutLength);
    EncryptFinalize(handler, dataOut+*dataOutLength, dataOutLength);
}

void* DRMProcessorClientImpl::EncryptInit(CRYPTO_ALGO algo, CHAINING_MODE chaining,
					  const unsigned char* key, unsigned int keyLength,
					  const unsigned char* iv, unsigned int ivLength)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (algo == ALGO_AES)
    {
	switch(keyLength)
	{
	case 16:
	    switch(chaining)
	    {
	    case CHAIN_ECB:
		EVP_EncryptInit(ctx, EVP_aes_128_ecb(), key, iv);
		break;
	    case CHAIN_CBC:
		EVP_EncryptInit(ctx, EVP_aes_128_cbc(), key, iv);
		break;
	    default:
		EXCEPTION(gourou::CLIENT_BAD_CHAINING, "Unknown chaining mode " << chaining);
	    }
	    break;
	default:
	    EVP_CIPHER_CTX_free(ctx);
	    EXCEPTION(gourou::CLIENT_BAD_KEY_SIZE, "Invalid key size " << keyLength);
	}
    }
    else if (algo == ALGO_RC4)
    {
	if (keyLength != 16)
	{
	    EVP_CIPHER_CTX_free(ctx);
	    EXCEPTION(gourou::CLIENT_BAD_KEY_SIZE, "Invalid key size " << keyLength);
	}
	EVP_DecryptInit(ctx, EVP_rc4(), key, iv);
    }
    return ctx;
}

void* DRMProcessorClientImpl::DecryptInit(CRYPTO_ALGO algo, CHAINING_MODE chaining,
					     const unsigned char* key, unsigned int keyLength,
					     const unsigned char* iv, unsigned int ivLength)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (algo == ALGO_AES)
    {
	switch(keyLength)
	{
	case 16:
	    switch(chaining)
	    {
	    case CHAIN_ECB:
		EVP_DecryptInit(ctx, EVP_aes_128_ecb(), key, iv);
		break;
	    case CHAIN_CBC:
		EVP_DecryptInit(ctx, EVP_aes_128_cbc(), key, iv);
		break;
	    default:
		EXCEPTION(gourou::CLIENT_BAD_CHAINING, "Unknown chaining mode " << chaining);
	    }
	    break;
	default:
	    EVP_CIPHER_CTX_free(ctx);
	    EXCEPTION(gourou::CLIENT_BAD_KEY_SIZE, "Invalid key size " << keyLength);
	}
    }
    else if (algo == ALGO_RC4)
    {
	if (keyLength != 16)
	{
	    EVP_CIPHER_CTX_free(ctx);
	    EXCEPTION(gourou::CLIENT_BAD_KEY_SIZE, "Invalid key size " << keyLength);
	}
	EVP_DecryptInit(ctx, EVP_rc4(), key, iv);
    }
    
    return ctx;
}

void DRMProcessorClientImpl::EncryptUpdate(void* handler, const unsigned char* dataIn, unsigned int dataInLength,
					   unsigned char* dataOut, unsigned int* dataOutLength)
{
    EVP_EncryptUpdate((EVP_CIPHER_CTX*)handler, dataOut, (int*)dataOutLength, dataIn, dataInLength);
}

void DRMProcessorClientImpl::EncryptFinalize(void* handler,
					     unsigned char* dataOut, unsigned int* dataOutLength)
{
    int len;
    EVP_EncryptFinal_ex((EVP_CIPHER_CTX*)handler, dataOut, &len);
    *dataOutLength += len;
    EVP_CIPHER_CTX_free((EVP_CIPHER_CTX*)handler);
}

void DRMProcessorClientImpl::Decrypt(CRYPTO_ALGO algo, CHAINING_MODE chaining,
				     const unsigned char* key, unsigned int keyLength,
				     const unsigned char* iv, unsigned int ivLength,
				     const unsigned char* dataIn, unsigned int dataInLength,
				     unsigned char* dataOut, unsigned int* dataOutLength)
{
    void* handler = DecryptInit(algo, chaining, key, keyLength, iv, ivLength);
    DecryptUpdate(handler, dataIn, dataInLength, dataOut, dataOutLength);
    DecryptFinalize(handler, dataOut+*dataOutLength, dataOutLength);
}

void DRMProcessorClientImpl::DecryptUpdate(void* handler, const unsigned char* dataIn, unsigned int dataInLength,
					   unsigned char* dataOut, unsigned int* dataOutLength)
{
    EVP_DecryptUpdate((EVP_CIPHER_CTX*)handler, dataOut, (int*)dataOutLength, dataIn, dataInLength);
}

void DRMProcessorClientImpl::DecryptFinalize(void* handler, unsigned char* dataOut, unsigned int* dataOutLength)
{
    int len;
    EVP_DecryptFinal_ex((EVP_CIPHER_CTX*)handler, dataOut, &len);
    *dataOutLength += len;
    EVP_CIPHER_CTX_free((EVP_CIPHER_CTX*)handler);
}

void* DRMProcessorClientImpl::zipOpen(const std::string& path)
{
    zip_t* handler = zip_open(path.c_str(), 0, 0);

    if (!handler)
	EXCEPTION(gourou::CLIENT_BAD_ZIP_FILE, "Invalid zip file " << path);

    return handler;
}

void DRMProcessorClientImpl::zipReadFile(void* handler, const std::string& path, gourou::ByteArray& result, bool decompress)
{
    std::string res;
    zip_stat_t sb;
    
    if (zip_stat((zip_t *)handler, path.c_str(), 0, &sb) < 0)
	EXCEPTION(gourou::CLIENT_ZIP_ERROR, "Zip error, no file " << path << ", " << zip_strerror((zip_t *)handler));

    if (!(sb.valid & (ZIP_STAT_INDEX|ZIP_STAT_SIZE)))
	EXCEPTION(gourou::CLIENT_ZIP_ERROR, "Required fields missing");

    result.resize(sb.size);
    
    zip_file_t *f = zip_fopen_index((zip_t *)handler, sb.index, (decompress)?0:ZIP_FL_COMPRESSED);
    zip_fread(f, result.data(), sb.size);
    zip_fclose(f);
}

void DRMProcessorClientImpl::zipWriteFile(void* handler, const std::string& path, gourou::ByteArray& content)
{
    zip_int64_t ret;
    
    zip_source_t* s = zip_source_buffer((zip_t*)handler, content.takeShadowData(), content.length(), 1);

    zip_int64_t idx = zip_name_locate((zip_t*)handler, path.c_str(), 0);

    // File doesn't exists
    if (idx == -1)
	ret = zip_file_add((zip_t*)handler, path.c_str(), s, 0);
    else
	ret = zip_file_replace((zip_t*)handler, idx, s, ZIP_FL_OVERWRITE);

    if (ret < 0)
    {
	zip_source_free(s);
	EXCEPTION(gourou::CLIENT_ZIP_ERROR, "Zip error " << zip_strerror((zip_t *)handler));
    }
}

void DRMProcessorClientImpl::zipDeleteFile(void* handler, const std::string& path)
{
    zip_int64_t idx = zip_name_locate((zip_t*)handler, path.c_str(), 0);

    if (idx < 0)
	EXCEPTION(gourou::CLIENT_ZIP_ERROR, "No such file " << path.c_str());
    
    if (zip_delete((zip_t*)handler, idx))
	EXCEPTION(gourou::CLIENT_ZIP_ERROR, "Zip error " << zip_strerror((zip_t *)handler));
}

void DRMProcessorClientImpl::zipClose(void* handler)
{
    zip_close((zip_t*)handler);
}

void DRMProcessorClientImpl::inflate(gourou::ByteArray& data, gourou::ByteArray& result,
				     int wbits)
{
    unsigned int dataSize = data.size()*2;
    unsigned char* buffer = new unsigned char[dataSize];
    
    z_stream infstream;

    infstream.zalloc = Z_NULL;
    infstream.zfree  = Z_NULL;
    infstream.opaque = Z_NULL;

    infstream.avail_in  = (uInt)data.size();
    infstream.next_in   = (Bytef *)data.data(); // input char array
    infstream.avail_out = (uInt)dataSize; // size of output
    infstream.next_out  = (Bytef *)buffer; // output char array

    int ret = inflateInit2(&infstream, wbits);

    if (ret != Z_OK)
	EXCEPTION(gourou::CLIENT_ZIP_ERROR, "Inflate error, code " << zError(ret) << ", msg " << infstream.msg);

    ret = ::inflate(&infstream, Z_FINISH);
    while (ret == Z_OK || ret == Z_STREAM_END || ret == Z_BUF_ERROR)
    {
	// Real error
	if (ret == Z_BUF_ERROR && infstream.avail_out == (uInt)dataSize)
	    break;

	result.append(buffer, dataSize-infstream.avail_out);
	    
	if ((ret == Z_OK && infstream.avail_out != 0) || ret == Z_STREAM_END)
	    break;
	infstream.avail_out = (uInt)dataSize; // size of output
	infstream.next_out = (Bytef *)buffer; // output char array
	ret = ::inflate(&infstream, Z_FINISH);
    }

    if (ret == Z_STREAM_END)
	ret = inflateEnd(&infstream);

    delete[] buffer;

    if (ret != Z_OK && ret != Z_STREAM_END)
	EXCEPTION(gourou::CLIENT_ZIP_ERROR, "Inflate error, code " << zError(ret) << ", msg " << infstream.msg);
}
	
void DRMProcessorClientImpl::deflate(gourou::ByteArray& data, gourou::ByteArray& result,
				     int wbits, int compressionLevel)
{
    unsigned int dataSize = data.size();
    unsigned char* buffer = new unsigned char[dataSize];
    
    z_stream defstream;

    defstream.zalloc = Z_NULL;
    defstream.zfree  = Z_NULL;
    defstream.opaque = Z_NULL;

    defstream.avail_in  = (uInt)dataSize;
    defstream.next_in   = (Bytef *)data.data(); // input char array
    defstream.avail_out = (uInt)dataSize; // size of output
    defstream.next_out  = (Bytef *)buffer; // output char array

    int ret = deflateInit2(&defstream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, wbits,
			   compressionLevel, Z_DEFAULT_STRATEGY);

    if (ret != Z_OK)
	EXCEPTION(gourou::CLIENT_ZIP_ERROR, "Deflate error, code " << zError(ret) << ", msg " << defstream.msg);
    
    ret = ::deflate(&defstream, Z_FINISH);
    while (ret == Z_OK || ret == Z_STREAM_END)
    {
	result.append(buffer, dataSize-defstream.avail_out);
	if ((ret == Z_OK && defstream.avail_out != 0) || ret == Z_STREAM_END)
	    break;
	defstream.avail_out = (uInt)dataSize; // size of output
	defstream.next_out = (Bytef *)buffer; // output char array
	ret = ::deflate(&defstream, Z_FINISH);
    }

    if (ret == Z_STREAM_END)
	ret = deflateEnd(&defstream);

    delete[] buffer;

    if (ret != Z_OK && ret != Z_STREAM_END)
	EXCEPTION(gourou::CLIENT_ZIP_ERROR, "Deflate error, code " << zError(ret) << ", msg " << defstream.msg);
}
