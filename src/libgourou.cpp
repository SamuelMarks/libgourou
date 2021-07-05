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
  along with libgourou.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>

#include <libgourou.h>
#include <libgourou_common.h>
#include <libgourou_log.h>

#define ASN_NONE        0x00
#define ASN_NS_TAG      0x01
#define ASN_CHILD       0x02
#define ASN_END_TAG     0x03
#define ASN_TEXT        0x04
#define ASN_ATTRIBUTE   0x05

namespace gourou
{
    GOUROU_LOG_LEVEL logLevel = WARN;
    const std::string DRMProcessor::VERSION = LIBGOUROU_VERSION;
    
    DRMProcessor::DRMProcessor(DRMProcessorClient* client):client(client), device(0), user(0)
    {
	if (!client)
	    EXCEPTION(GOUROU_INVALID_CLIENT, "DRMProcessorClient is NULL");
    }

    DRMProcessor::DRMProcessor(DRMProcessorClient* client,
			       const std::string& deviceFile, const std::string& activationFile,
			       const std::string& deviceKeyFile):
	client(client), device(0), user(0)
    {
	if (!client)
	    EXCEPTION(GOUROU_INVALID_CLIENT, "DRMProcessorClient is NULL");
	
	device = new Device(this, deviceFile, deviceKeyFile);
	user = new User(this, activationFile);

	if (user->getDeviceFingerprint() != "" &&
	    (*device)["fingerprint"] != user->getDeviceFingerprint())
	    EXCEPTION(GOUROU_DEVICE_DOES_NOT_MATCH, "User and device fingerprint does not match");
    }

    DRMProcessor::~DRMProcessor()
    {
	if (device) delete device;
	if (user) delete user;
    }

    DRMProcessor* DRMProcessor::createDRMProcessor(DRMProcessorClient* client, bool randomSerial, const std::string& dirName,
						   const std::string& hobbes, const std::string& ACSServer)
    {
	DRMProcessor* processor = new DRMProcessor(client);

	Device* device = Device::createDevice(processor, dirName, hobbes, randomSerial);
	processor->device = device;

	User* user = User::createUser(processor, dirName, ACSServer);
	processor->user = user;
	
	return processor;
    }

    
    void DRMProcessor::pushString(void* sha_ctx, const std::string& string)
    {
	int length = string.length();
	uint16_t nlength = htons(length);
	char c;

	if (logLevel >= TRACE)
	    printf("%02x %02x ", ((uint8_t*)&nlength)[0], ((uint8_t*)&nlength)[1]);
	
	client->digestUpdate(sha_ctx, (unsigned char*)&nlength, sizeof(nlength));

	for(int i=0; i<length; i++)
	{
	    c = string[i];
	    client->digestUpdate(sha_ctx, (unsigned char*)&c, 1);
	    if (logLevel >= TRACE)
		printf("%c", c);
	}
	if (logLevel >= TRACE)
	    printf("\n");
    }

    void DRMProcessor::pushTag(void* sha_ctx, uint8_t tag)
    {
	client->digestUpdate(sha_ctx, &tag, sizeof(tag));
	if (logLevel >= TRACE)
	    printf("%02x ", tag);
    }

    void DRMProcessor::hashNode(const pugi::xml_node& root, void *sha_ctx, std::map<std::string,std::string> nsHash)
    {
	switch(root.type())
	{
	case pugi::node_element:
	{
	    std::string name = root.name();

	    // Look for "xmlns[:]" attribute
	    for (pugi::xml_attribute_iterator ait = root.attributes_begin();
		 ait != root.attributes_end(); ++ait)
	    {
		std::string attrName(ait->name());

		if (attrName.find("xmlns") == 0)
		{
		    std::string ns("GENERICNS");
		    // Compound xmlns:Name attribute
		    if (attrName.find(':') != std::string::npos)
			ns = attrName.substr(attrName.find(':')+1);

		    nsHash[ns] = ait->value();
		    break;
		}
	    }

	    // Remove namespace from tag
	    // If we have a namespace for the first time, put it to hash
	    if (name.find(':') != std::string::npos)
	    {
		size_t nsIndex = name.find(':');
		std::string nodeNS = name.substr(0, nsIndex);

		pushTag(sha_ctx, ASN_NS_TAG);
		pushString(sha_ctx, nsHash[nodeNS]);
		
		name = name.substr(nsIndex+1);
	    }
	    // Global xmlns, always send to hash
	    else if (nsHash.find("GENERICNS") != nsHash.end())
	    {
		pushTag(sha_ctx, ASN_NS_TAG);
		pushString(sha_ctx, nsHash["GENERICNS"]);
	    }
	    
	    pushString(sha_ctx, name);

	    // Must be parsed in reverse order
	    for (pugi::xml_attribute attr = root.last_attribute();
		 attr; attr = attr.previous_attribute())
	    {
		if (std::string(attr.name()).find("xmlns") != std::string::npos)
		    continue;
		    
		pushTag(sha_ctx, ASN_ATTRIBUTE);
		pushString(sha_ctx, "");
		
		pushString(sha_ctx, attr.name());
		pushString(sha_ctx, attr.value());
	    }

	    pushTag(sha_ctx, ASN_CHILD);

	    for (pugi::xml_node child : root.children())
		hashNode(child, sha_ctx, nsHash);

	    pushTag(sha_ctx, ASN_END_TAG);
	    
	    break;
	}
	case pugi::node_pcdata:
	{
	    std::string trimmed = root.value();
	    trimmed = trim(trimmed);

	    if (trimmed.length())
	    {
		pushTag(sha_ctx, ASN_TEXT);
		pushString(sha_ctx, trimmed);
	    }

	    break;
	}
	default:
	    break;
	}
    }
		
    void DRMProcessor::hashNode(const pugi::xml_node& root, unsigned char* sha_out)
    {
	void* sha_ctx = client->createDigest("SHA1");
	
	std::map<std::string, std::string> nsHash;

	hashNode(root, sha_ctx, nsHash);

	client->digestFinalize(sha_ctx, sha_out);
	
	if (logLevel >= DEBUG)
	{
	    printf("\nSHA OUT : ");
	    for(int i=0; i<(int)SHA1_LEN; i++)
		printf("%02x ", sha_out[i]);
	    printf("\n");
	}
    }
    
    ByteArray DRMProcessor::sendRequest(const std::string& URL, const std::string& POSTdata, const char* contentType)
    {
	if (contentType == 0)
	    contentType = "";
	std::string reply = client->sendHTTPRequest(URL, POSTdata, contentType);

	pugi::xml_document replyDoc;
	replyDoc.load_buffer(reply.c_str(), reply.length());

	pugi::xml_node root = replyDoc.first_child();
	if (std::string(root.name()) == "error")
	{
	    EXCEPTION(GOUROU_ADEPT_ERROR, root.attribute("data").value());
	}
	
	return ByteArray(reply);
    }

    ByteArray DRMProcessor::sendRequest(const pugi::xml_document& document, const std::string& url)
    {
	StringXMLWriter xmlWriter;
	document.save(xmlWriter, "  ");
	std::string xmlStr = xmlWriter.getResult();

	return sendRequest(url, xmlStr, (const char*)"application/vnd.adobe.adept+xml");
    }
    
    void DRMProcessor::buildFulfillRequest(pugi::xml_document& acsmDoc, pugi::xml_document& fulfillReq)
    {
	pugi::xml_node decl = fulfillReq.append_child(pugi::node_declaration);
	decl.append_attribute("version") = "1.0";
	
	pugi::xml_node root = fulfillReq.append_child("adept:fulfill");
	root.append_attribute("xmlns:adept") = ADOBE_ADEPT_NS;

	appendTextElem(root, "adept:user",       user->getUUID());
	appendTextElem(root, "adept:device",     user->getDeviceUUID());
	appendTextElem(root, "adept:deviceType", (*device)["deviceType"]);

	root.append_copy(acsmDoc.first_child());

	pugi::xml_node targetDevice = root.append_child("adept:targetDevice");
	appendTextElem(targetDevice, "adept:softwareVersion", (*device)["hobbes"]);
	appendTextElem(targetDevice, "adept:clientOS",        (*device)["clientOS"]);
	appendTextElem(targetDevice, "adept:clientLocale",    (*device)["clientLocale"]);
	appendTextElem(targetDevice, "adept:clientVersion",   (*device)["deviceClass"]);
	appendTextElem(targetDevice, "adept:deviceType",      (*device)["deviceType"]);
	appendTextElem(targetDevice, "adept:fingerprint",     (*device)["fingerprint"]);
	
	pugi::xml_node activationToken = targetDevice.append_child("adept:activationToken");
	appendTextElem(activationToken, "adept:user",   user->getUUID());
	appendTextElem(activationToken, "adept:device", user->getDeviceUUID());
    }

    FulfillmentItem* DRMProcessor::fulfill(const std::string& ACSMFile)
    {
	if (!user->getPKCS12().length())
	    EXCEPTION(FF_NOT_ACTIVATED, "Device not activated");
	
	pugi::xml_document acsmDoc;

	if (!acsmDoc.load_file(ACSMFile.c_str(), pugi::parse_ws_pcdata_single))
	    EXCEPTION(FF_INVALID_ACSM_FILE, "Invalid ACSM file " << ACSMFile);

	GOUROU_LOG(INFO, "Fulfill " << ACSMFile);
	
	// Build req file
	pugi::xml_document fulfillReq;

	buildFulfillRequest(acsmDoc, fulfillReq);
	pugi::xpath_node root = fulfillReq.select_node("//adept:fulfill");
	pugi::xml_node rootNode = root.node();

	// Remove HMAC
	pugi::xpath_node xpathRes = fulfillReq.select_node("//hmac");

	if (!xpathRes)
	    EXCEPTION(FF_NO_HMAC_IN_ACSM_FILE, "hmac tag not found in ACSM file");

	pugi::xml_node hmacNode = xpathRes.node();
	pugi::xml_node hmacParentNode = hmacNode.parent();
	
	hmacParentNode.remove_child(hmacNode);

	// Compute hash
	unsigned char sha_out[SHA1_LEN];

	hashNode(rootNode, sha_out);
	    
	// Sign with private key
	unsigned char res[RSA_KEY_SIZE];
	ByteArray deviceKey(device->getDeviceKey(), Device::DEVICE_KEY_SIZE);
	std::string pkcs12 = user->getPKCS12();
	ByteArray privateRSAKey = ByteArray::fromBase64(pkcs12);
	
	client->RSAPrivateEncrypt(privateRSAKey.data(), privateRSAKey.length(),
				  RSAInterface::RSA_KEY_PKCS12, deviceKey.toBase64().data(),
				  sha_out, sizeof(sha_out), res);
	if (logLevel >= DEBUG)
	{
	    printf("Sig : ");
	    for(int i=0; i<(int)sizeof(res); i++)
		printf("%02x ", res[i]);
	    printf("\n");
	}
	
	// Add removed HMAC
	appendTextElem(hmacParentNode, hmacNode.name(), hmacNode.first_child().value());
	
	// Add base64 encoded signature
	ByteArray signature(res, sizeof(res));
	std::string b64Signature = signature.toBase64();

	appendTextElem(rootNode, "adept:signature", b64Signature);

	pugi::xpath_node node = acsmDoc.select_node("//operatorURL");
	if (!node)
	    EXCEPTION(FF_NO_OPERATOR_URL, "OperatorURL not found in ACSM document");
	
	std::string operatorURL = node.node().first_child().value();
	operatorURL = trim(operatorURL) + "/Fulfill";

	ByteArray replyData = sendRequest(fulfillReq, operatorURL);

	pugi::xml_document fulfillReply;

	fulfillReply.load_string((const char*)replyData.data());
	
	return new FulfillmentItem(fulfillReply, user);
    }

    void DRMProcessor::download(FulfillmentItem* item, std::string path)
    {
	if (!item)
	    EXCEPTION(DW_NO_ITEM, "No item");
	
	ByteArray replyData = sendRequest(item->getDownloadURL());

	writeFile(path, replyData);

	GOUROU_LOG(INFO, "Download into " << path);

	std::string rightsStr = item->getRights();

	void* handler = client->zipOpen(path);
	client->zipWriteFile(handler, "META-INF/rights.xml", rightsStr);
	client->zipClose(handler);
    }

    void DRMProcessor::buildSignInRequest(pugi::xml_document& signInRequest,
					  const std::string& adobeID, const std::string& adobePassword,
					  const std::string& authenticationCertificate)
    {
	pugi::xml_node decl = signInRequest.append_child(pugi::node_declaration);
	decl.append_attribute("version") = "1.0";
	pugi::xml_node signIn = signInRequest.append_child("adept:signIn");
	signIn.append_attribute("xmlns:adept") = ADOBE_ADEPT_NS;
	signIn.append_attribute("method") = user->getLoginMethod().c_str();

	unsigned char encryptedSignInData[RSA_KEY_SIZE];
	const unsigned char* deviceKey = device->getDeviceKey();

	ByteArray _authenticationCertificate = ByteArray::fromBase64(authenticationCertificate);

	// Build buffer <deviceKey> <len username> <username> <len password> <password>
	ByteArray ar(deviceKey, Device::DEVICE_KEY_SIZE);
	ar.append((unsigned char)adobeID.length());
	ar.append(adobeID);
	ar.append((unsigned char)adobePassword.length());
	ar.append(adobePassword);

	// Encrypt with authentication certificate (public part)
	client->RSAPublicEncrypt(_authenticationCertificate.data(),
				 _authenticationCertificate.length(),
				 RSAInterface::RSA_KEY_X509,
				 ar.data(), ar.length(), encryptedSignInData);

	ar = ByteArray(encryptedSignInData, sizeof(encryptedSignInData));
	appendTextElem(signIn, "adept:signInData", ar.toBase64());
	
	// Generate Auth key and License Key
	void* rsaAuth = client->generateRSAKey(RSA_KEY_SIZE_BITS);
	void* rsaLicense = client->generateRSAKey(RSA_KEY_SIZE_BITS);

	std::string serializedData = serializeRSAPublicKey(rsaAuth);
	appendTextElem(signIn, "adept:publicAuthKey", serializedData);
	serializedData = serializeRSAPrivateKey(rsaAuth);
	appendTextElem(signIn, "adept:encryptedPrivateAuthKey", serializedData.data());

	serializedData = serializeRSAPublicKey(rsaLicense);
	appendTextElem(signIn, "adept:publicLicenseKey", serializedData.data());
	serializedData = serializeRSAPrivateKey(rsaLicense);
	appendTextElem(signIn, "adept:encryptedPrivateLicenseKey", serializedData.data());

	client->destroyRSAHandler(rsaAuth);
	client->destroyRSAHandler(rsaLicense);
    }
    
    void DRMProcessor::signIn(const std::string& adobeID, const std::string& adobePassword)
    {
	pugi::xml_document signInRequest;
	std::string authenticationCertificate = user->getAuthenticationCertificate();
	
	buildSignInRequest(signInRequest, adobeID, adobePassword, authenticationCertificate);

	GOUROU_LOG(INFO, "SignIn " << adobeID);
	
	std::string signInURL = user->getProperty("//adept:authURL");
	signInURL += "/SignInDirect";

	ByteArray credentials = sendRequest(signInRequest, signInURL);
	
	pugi::xml_document credentialsDoc;
	if (!credentialsDoc.load_buffer(credentials.data(), credentials.length()))
	    EXCEPTION(SIGN_INVALID_CREDENTIALS, "Invalid credentials reply");

	struct adeptWalker: pugi::xml_tree_walker
	{
	    void changeName(pugi::xml_node& node)
	    {
		std::string name = std::string("adept:") + node.name();
		node.set_name(name.c_str());
	    }
	    
	    bool begin(pugi::xml_node& node)
	    {
		changeName(node);
		return true;
	    }
	    
	    virtual bool for_each(pugi::xml_node& node)
	    {
		if (node.type() == pugi::node_element)
		    changeName(node);
		return true; // continue traversal
	    }
	} adeptWalker;

	pugi::xml_node credentialsNode = credentialsDoc.first_child();

	if (std::string(credentialsNode.name()) != "credentials")
	    EXCEPTION(SIGN_INVALID_CREDENTIALS, "Invalid credentials reply");
	
	pugi::xpath_node encryptedPrivateLicenseKey = credentialsNode.select_node("encryptedPrivateLicenseKey");
	const char* privateKeyData = encryptedPrivateLicenseKey.node().first_child().value();
	ByteArray privateKeyDataStr = ByteArray::fromBase64(privateKeyData);
	ByteArray privateKey = decryptWithDeviceKey(privateKeyDataStr.data(), privateKeyDataStr.length());
	credentialsNode.remove_child(encryptedPrivateLicenseKey.node());
	appendTextElem(credentialsNode, "privateLicenseKey", privateKey.toBase64().data());

	// Add "adept:" prefix to all nodes
	credentialsNode.remove_attribute("xmlns");
	credentialsNode.append_attribute("xmlns:adept") = ADOBE_ADEPT_NS;
	credentialsNode.traverse(adeptWalker);
	
	appendTextElem(credentialsNode, "adept:authenticationCertificate", authenticationCertificate.data());

	pugi::xml_document activationDoc;
	user->readActivation(activationDoc);
	pugi::xml_node activationInfo = activationDoc.select_node("activationInfo").node();
	activationInfo.append_copy(credentialsNode);

	user->updateActivationFile(activationDoc);
    }
    
    void DRMProcessor::buildActivateReq(pugi::xml_document& activateReq)
    {
	pugi::xml_node decl = activateReq.append_child(pugi::node_declaration);
	decl.append_attribute("version") = "1.0";
	
	pugi::xml_node root = activateReq.append_child("adept:activate");
	root.append_attribute("xmlns:adept") = ADOBE_ADEPT_NS;
	root.append_attribute("requestType") = "initial";

	appendTextElem(root, "adept:fingerprint",   (*device)["fingerprint"]);
	appendTextElem(root, "adept:deviceType",    (*device)["deviceType"]);
	appendTextElem(root, "adept:clientOS",      (*device)["clientOS"]);
	appendTextElem(root, "adept:clientLocale",  (*device)["clientLocale"]);
	appendTextElem(root, "adept:clientVersion", (*device)["deviceClass"]);

	pugi::xml_node targetDevice = root.append_child("adept:targetDevice");
	appendTextElem(targetDevice, "adept:softwareVersion", (*device)["hobbes"]);
	appendTextElem(targetDevice, "adept:clientOS",        (*device)["clientOS"]);
	appendTextElem(targetDevice, "adept:clientLocale",    (*device)["clientLocale"]);
	appendTextElem(targetDevice, "adept:clientVersion",   (*device)["deviceClass"]);
	appendTextElem(targetDevice, "adept:deviceType",      (*device)["deviceType"]);
	appendTextElem(targetDevice, "adept:fingerprint",     (*device)["fingerprint"]);

	/*
	  r4 = tp->time
	  r3 = 0
	  r2 = tm->militime
	  r0 = 0x6f046000
	  r1 = 0x388a
  
	  r3 += high(r4*1000)
	  r2 += low(r4*1000)
  
	  r0 += r2
	  r1 += r3
	 */
	struct timeval tv;
	gettimeofday(&tv, 0);
	uint32_t nonce32[2] = {0x6f046000, 0x388a};
	uint64_t bigtime = tv.tv_sec*1000;
	nonce32[0] += (bigtime & 0xFFFFFFFF) + (tv.tv_usec/1000);
	nonce32[1] += ((bigtime >> 32) & 0xFFFFFFFF);
	
	ByteArray nonce((const unsigned char*)&nonce32, sizeof(nonce32));
	uint32_t tmp = 0;
	nonce.append((const unsigned char*)&tmp, sizeof(tmp));
	appendTextElem(root, "adept:nonce", nonce.toBase64().data());

	time_t _time = time(0) + 10*60; // Cur time + 10 minutes
	struct tm* tm_info = localtime(&_time);
	char buffer[32];

	strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", tm_info);
	appendTextElem(root, "adept:expiration", buffer);
	
	appendTextElem(root, "adept:user", user->getUUID());
    }
    
    void DRMProcessor::activateDevice()
    {
	pugi::xml_document activateReq;

	GOUROU_LOG(INFO, "Activate device");

	buildActivateReq(activateReq);
	
	// Compute hash
	unsigned char sha_out[SHA1_LEN];

	pugi::xml_node root = activateReq.select_node("adept:activate").node();
	hashNode(root, sha_out);

	// Sign with private key
	ByteArray RSAKey = ByteArray::fromBase64(user->getPKCS12());
	unsigned char res[RSA_KEY_SIZE];
	ByteArray deviceKey(device->getDeviceKey(), Device::DEVICE_KEY_SIZE);
	
	client->RSAPrivateEncrypt(RSAKey.data(), RSAKey.length(), RSAInterface::RSA_KEY_PKCS12,
				  deviceKey.toBase64().c_str(),
				  sha_out, sizeof(sha_out),
				  res);

	// Add base64 encoded signature
	ByteArray signature(res, sizeof(res));
	std::string b64Signature = signature.toBase64();

	root = activateReq.select_node("adept:activate").node();
	appendTextElem(root, "adept:signature", b64Signature);

	pugi::xml_document activationDoc;
	user->readActivation(activationDoc);

	std::string activationURL = user->getProperty("//adept:activationURL");
	activationURL += "/Activate";
	
	ByteArray reply = sendRequest(activateReq, activationURL);

	pugi::xml_document activationToken;
	activationToken.load_buffer(reply.data(), reply.length());
	
	root = activationDoc.select_node("activationInfo").node();
	root.append_copy(activationToken.first_child());
	user->updateActivationFile(activationDoc);
    }
    
    ByteArray DRMProcessor::encryptWithDeviceKey(const unsigned char* data, unsigned int len)
    {
	const unsigned char* deviceKey = device->getDeviceKey();
	unsigned int outLen;
	int remain = 0;
	if ((len % 16))
	    remain = 16 - (len%16);
	int encrypted_data_len = 16 + len + remain; // IV + data + pad
	unsigned char* encrypted_data = new unsigned char[encrypted_data_len];
	
	// Generate IV in front
	client->randBytes(encrypted_data, 16);
	    
	client->AESEncrypt(CryptoInterface::CHAIN_CBC,
			   deviceKey, 16, encrypted_data, 16,
			   data, len,
			   encrypted_data+16, &outLen);

	ByteArray res(encrypted_data, outLen+16);

	delete[] encrypted_data;

	return res;
    }

    /* First 16 bytes of data is IV for CBC chaining */
    ByteArray DRMProcessor::decryptWithDeviceKey(const unsigned char* data, unsigned int len)
    {
	unsigned int outLen;
	const unsigned char* deviceKey = device->getDeviceKey();
	unsigned char* decrypted_data = new unsigned char[len-16];

	client->AESDecrypt(CryptoInterface::CHAIN_CBC,
			   deviceKey, 16, data, 16,
			   data+16, len-16,
			   decrypted_data, &outLen);

	ByteArray res(decrypted_data, outLen);

	delete[] decrypted_data;

	return res;
    }

    std::string DRMProcessor::serializeRSAPublicKey(void* rsa)
    {
	unsigned char* data = 0;
	unsigned int len;
	
	client->extractRSAPublicKey(rsa, &data, &len);

	ByteArray res(data, len);

	free(data);
	
	return res.toBase64();
    }
    
    std::string DRMProcessor::serializeRSAPrivateKey(void* rsa)
    {
	unsigned char* data = 0;
	unsigned int len;
	
	client->extractRSAPrivateKey(rsa, &data, &len);

	ByteArray res = encryptWithDeviceKey(data, len);

	free(data);
	
	return res.toBase64();
    }

    int DRMProcessor::getLogLevel() {return (int)gourou::logLevel;}
    void DRMProcessor::setLogLevel(int logLevel) {gourou::logLevel = (GOUROU_LOG_LEVEL)logLevel;}
}
