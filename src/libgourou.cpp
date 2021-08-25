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

#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>
#include <vector>

#include <uPDFParser.h>

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
		    // Don't break here because we may multiple xmlns definitions
		    // break;
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

	    std::vector<std::string> attributes;
	    pugi::xml_attribute attr;
	    
	    for (attr = root.first_attribute();
		 attr; attr = attr.next_attribute())
	    {
		if (std::string(attr.name()).find("xmlns") != std::string::npos)
		    continue;

		attributes.push_back(attr.name());
	    }

	    // Attributes must be handled in alphabetical order
	    std::sort(attributes.begin(), attributes.end());

	    std::vector<std::string>::iterator attributesIt;
	    for(attributesIt = attributes.begin();
		attributesIt != attributes.end();
		attributesIt++)
	    {
		attr = root.attribute(attributesIt->c_str());
		
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

    std::string DRMProcessor::signNode(const pugi::xml_node& rootNode)
    {
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

	ByteArray signature(res, sizeof(res));

	return signature.toBase64();
    }

    void DRMProcessor::addNonce(pugi::xml_node& root)
    {
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
	struct tm* tm_info = gmtime(&_time);
	char buffer[32];

	strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", tm_info);
	appendTextElem(root, "adept:expiration", buffer);
    }
    
    ByteArray DRMProcessor::sendRequest(const std::string& URL, const std::string& POSTdata, const char* contentType, std::map<std::string, std::string>* responseHeaders)
    {
	if (contentType == 0)
	    contentType = "";
	std::string reply = client->sendHTTPRequest(URL, POSTdata, contentType, responseHeaders);

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
    
    void DRMProcessor::buildAuthRequest(pugi::xml_document& authReq)
    {
	pugi::xml_node decl = authReq.append_child(pugi::node_declaration);
	decl.append_attribute("version") = "1.0";
	
	pugi::xml_node root = authReq.append_child("adept:credentials");
	root.append_attribute("xmlns:adept") = ADOBE_ADEPT_NS;

	appendTextElem(root, "adept:user",       user->getUUID());

	ByteArray deviceKey(device->getDeviceKey(), Device::DEVICE_KEY_SIZE);
	unsigned char* pkcs12 = 0;
	unsigned int pkcs12Length;
	ByteArray pkcs12Cert = ByteArray::fromBase64(user->getPKCS12());
	
	client->extractCertificate(pkcs12Cert.data(), pkcs12Cert.length(),
				   RSAInterface::RSA_KEY_PKCS12, deviceKey.toBase64().data(),
				   &pkcs12, &pkcs12Length);
	ByteArray privateCertificate(pkcs12, pkcs12Length);
	free(pkcs12);

	appendTextElem(root, "adept:certificate",               privateCertificate.toBase64());
	appendTextElem(root, "adept:licenseCertificate",        user->getProperty("//adept:licenseCertificate"));
	appendTextElem(root, "adept:authenticationCertificate", user->getProperty("//adept:authenticationCertificate"));
    }
    
    void DRMProcessor::buildInitLicenseServiceRequest(pugi::xml_document& initLicReq, std::string operatorURL)
    {
	pugi::xml_node decl = initLicReq.append_child(pugi::node_declaration);
	decl.append_attribute("version") = "1.0";
	
	pugi::xml_node root = initLicReq.append_child("adept:licenseServiceRequest");
	root.append_attribute("xmlns:adept") = ADOBE_ADEPT_NS;
	root.append_attribute("identity") = "user";

	appendTextElem(root, "adept:operatorURL", operatorURL);
	addNonce(root);
	appendTextElem(root, "adept:user",        user->getUUID());

	std::string signature = signNode(root);
	appendTextElem(root, "adept:signature",   signature);
    }
    
    void DRMProcessor::doOperatorAuth(std::string operatorURL)
    {
	pugi::xml_document authReq;
	buildAuthRequest(authReq);
	std::string authURL = operatorURL;
	unsigned int fulfillPos = authURL.rfind("Fulfill");
	if (fulfillPos == (authURL.size() - (sizeof("Fulfill")-1)))
	    authURL = authURL.substr(0, fulfillPos-1);
	ByteArray replyData = sendRequest(authReq, authURL + "/Auth");

	pugi::xml_document initLicReq;
	std::string activationURL = user->getProperty("//adept:activationURL");
	buildInitLicenseServiceRequest(initLicReq, authURL);
	sendRequest(initLicReq, activationURL + "/InitLicenseService");
    }
    
    void DRMProcessor::operatorAuth(std::string operatorURL)
    {
	pugi::xpath_node_set operatorList = user->getProperties("//adept:operatorURL");
	
	for (pugi::xpath_node_set::const_iterator operatorIt = operatorList.begin();
	     operatorIt != operatorList.end(); ++operatorIt)
	{
	    std::string value = operatorIt->node().first_child().value();
	    if (trim(value) == operatorURL)
	    {
		GOUROU_LOG(DEBUG, "Already authenticated to operator " << operatorURL);
		return;
	    }
	}
	
	doOperatorAuth(operatorURL);
	
	// Add new operatorURL to list
	pugi::xml_document activationDoc;
	user->readActivation(activationDoc);

	pugi::xml_node root;
	pugi::xpath_node xpathRes = activationDoc.select_node("//adept:operatorURLList");

	// Create adept:operatorURLList if it doesn't exists
	if (!xpathRes)
	{
	    xpathRes = activationDoc.select_node("/activationInfo");
	    root = xpathRes.node();
	    root = root.append_child("adept:operatorURLList");
	    root.append_attribute("xmlns:adept") = ADOBE_ADEPT_NS;

	    appendTextElem(root, "adept:user",       user->getUUID());
	}
	else
	    root = xpathRes.node();

	appendTextElem(root, "adept:operatorURL", operatorURL);

	user->updateActivationFile(activationDoc);
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

    void DRMProcessor::fetchLicenseServiceCertificate(const std::string& licenseURL,
						      const std::string& operatorURL)
    {
	if (user->getLicenseServiceCertificate(licenseURL) != "")
	    return;

	std::string licenseServiceInfoReq = operatorURL + "/LicenseServiceInfo?licenseURL=" + licenseURL;
	
	ByteArray replyData;
	replyData = sendRequest(licenseServiceInfoReq);

	pugi::xml_document licenseServicesDoc;
	licenseServicesDoc.load_buffer(replyData.data(), replyData.length());

	// Add new license certificate
	pugi::xml_document activationDoc;
	user->readActivation(activationDoc);

	pugi::xml_node root;
	pugi::xpath_node xpathRes = activationDoc.select_node("//adept:licenseServices");

	// Create adept:licenseServices if it doesn't exists
	if (!xpathRes)
	{
	    xpathRes = activationDoc.select_node("/activationInfo");
	    root = xpathRes.node();
	    root = root.append_child("adept:licenseServices");
	    root.append_attribute("xmlns:adept") = ADOBE_ADEPT_NS;
	}
	else
	    root = xpathRes.node();

	root = root.append_child("adept:licenseServiceInfo");

	std::string certificate = extractTextElem(licenseServicesDoc,
						  "/licenseServiceInfo/certificate");

	appendTextElem(root, "adept:licenseURL", licenseURL);
	appendTextElem(root, "adept:certificate", certificate);

	user->updateActivationFile(activationDoc);
    }
    
    FulfillmentItem* DRMProcessor::fulfill(const std::string& ACSMFile)
    {
	if (!user->getPKCS12().length())
	    EXCEPTION(FF_NOT_ACTIVATED, "Device not activated");
	
	pugi::xml_document acsmDoc;

	if (!acsmDoc.load_file(ACSMFile.c_str(), pugi::parse_ws_pcdata_single|pugi::parse_escapes, pugi::encoding_utf8))
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

	std::string signature = signNode(rootNode);
	
	// Add removed HMAC
	appendTextElem(hmacParentNode, hmacNode.name(), hmacNode.first_child().value());
	
	appendTextElem(rootNode, "adept:signature", signature);

	pugi::xpath_node node = acsmDoc.select_node("//operatorURL");
	if (!node)
	    EXCEPTION(FF_NO_OPERATOR_URL, "OperatorURL not found in ACSM document");
	
	std::string operatorURL = node.node().first_child().value();
	operatorURL = trim(operatorURL);
	std::string fulfillURL = operatorURL + "/Fulfill";

	operatorAuth(fulfillURL);
	
	ByteArray replyData;

	try
	{
	    replyData = sendRequest(fulfillReq, fulfillURL);
	}
	catch (gourou::Exception& e)
	{
	    /*
	      Operator requires authentication even if it's already in 
	      our operator list
	    */
	    std::string errorMsg(e.what());
	    if (e.getErrorCode() == GOUROU_ADEPT_ERROR &&
		errorMsg.find("E_ADEPT_DISTRIBUTOR_AUTH") != std::string::npos)
	    {
		doOperatorAuth(fulfillURL);
		replyData = sendRequest(fulfillReq, fulfillURL);
	    }
	    else
	    {
		throw e;
	    }
	}

	pugi::xml_document fulfillReply;

	fulfillReply.load_string((const char*)replyData.data());

	std::string licenseURL = extractTextElem(fulfillReply, "//licenseToken/licenseURL");
	
	fetchLicenseServiceCertificate(licenseURL, operatorURL);

	return new FulfillmentItem(fulfillReply, user);
    }

    DRMProcessor::ITEM_TYPE DRMProcessor::download(FulfillmentItem* item, std::string path)
    {
	ITEM_TYPE res = EPUB;
	
	if (!item)
	    EXCEPTION(DW_NO_ITEM, "No item");

	std::map<std::string, std::string> headers;
	
	ByteArray replyData = sendRequest(item->getDownloadURL(), "", 0, &headers);

	writeFile(path, replyData);

	GOUROU_LOG(INFO, "Download into " << path);

	std::string rightsStr = item->getRights();

	if (headers.count("Content-Type") && headers["Content-Type"] == "application/pdf")
	    res = PDF;

	if (res == EPUB)
	{
	    void* handler = client->zipOpen(path);
	    client->zipWriteFile(handler, "META-INF/rights.xml", rightsStr);
	    client->zipClose(handler);
	}
	else if (res == PDF)
	{
	    uPDFParser::Parser parser;

	    try
	    {
		GOUROU_LOG(DEBUG, "Parse PDF");
		parser.parse(path);
	    }
	    catch(std::invalid_argument& e)
	    {
		GOUROU_LOG(ERROR, "Invalid PDF");
		return res;
	    }

	    std::vector<uPDFParser::Object*> objects = parser.objects();
	    std::vector<uPDFParser::Object*>::reverse_iterator it;

	    for(it = objects.rbegin(); it != objects.rend(); it++)
	    {
		// Update EBX_HANDLER with rights
		if ((*it)->hasKey("Filter") && (**it)["Filter"]->str() == "/EBX_HANDLER")
		{
		    uPDFParser::Object* ebx = (*it)->clone();
		    (*ebx)["ADEPT_ID"] = new uPDFParser::String(item->getResource());
		    (*ebx)["EBX_BOOKID"] = new uPDFParser::String(item->getResource());
		    ByteArray zipped;
		    client->deflate(rightsStr, zipped);
		    (*ebx)["ADEPT_LICENSE"] = new uPDFParser::String(zipped.toBase64());
		    parser.addObject(ebx);
		    break;
		}
	    }

	    parser.write(path, true);
	}

	return res;
    }

    void DRMProcessor::buildSignInRequest(pugi::xml_document& signInRequest,
					  const std::string& adobeID, const std::string& adobePassword,
					  const std::string& authenticationCertificate)
    {
	pugi::xml_node decl = signInRequest.append_child(pugi::node_declaration);
	decl.append_attribute("version") = "1.0";
	pugi::xml_node signIn = signInRequest.append_child("adept:signIn");
	signIn.append_attribute("xmlns:adept") = ADOBE_ADEPT_NS;
	std::string loginMethod = user->getLoginMethod();
	if (loginMethod.size())
	    signIn.append_attribute("method") = loginMethod.c_str();
	else
	    signIn.append_attribute("method") = "AdobeID";

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

	addNonce(root);
	
	appendTextElem(root, "adept:user", user->getUUID());
    }
    
    void DRMProcessor::activateDevice()
    {
	pugi::xml_document activateReq;

	GOUROU_LOG(INFO, "Activate device");

	buildActivateReq(activateReq);

	pugi::xml_node root = activateReq.select_node("adept:activate").node();

	std::string signature = signNode(root);

	root = activateReq.select_node("adept:activate").node();
	appendTextElem(root, "adept:signature", signature);

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

    void DRMProcessor::exportPrivateLicenseKey(std::string path)
    {
	int fd = open(path.c_str(), O_CREAT|O_TRUNC|O_WRONLY, S_IRWXU);
	if (fd <= 0)
	    EXCEPTION(GOUROU_FILE_ERROR, "Unable to open " << path);

	ByteArray privateLicenseKey = ByteArray::fromBase64(user->getPrivateLicenseKey());
	/* In adobekey.py, we get base64 decoded data [26:] */
	write(fd, privateLicenseKey.data()+26, privateLicenseKey.length()-1-26);
	
	close(fd);
    }

    int DRMProcessor::getLogLevel() {return (int)gourou::logLevel;}
    void DRMProcessor::setLogLevel(int logLevel) {gourou::logLevel = (GOUROU_LOG_LEVEL)logLevel;}
}
