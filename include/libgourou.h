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

#ifndef _LIBGOUROU_H_
#define _LIBGOUROU_H_

#include "bytearray.h"
#include "device.h"
#include "user.h"
#include "fulfillment_item.h"
#include "drmprocessorclient.h"

#include <pugixml.hpp>

#ifndef HOBBES_DEFAULT_VERSION
#define HOBBES_DEFAULT_VERSION  "10.0.4"
#endif

#ifndef DEFAULT_ADEPT_DIR
#define DEFAULT_ADEPT_DIR       "./.adept"
#endif

#ifndef ACS_SERVER
#define ACS_SERVER              "http://adeactivate.adobe.com/adept"
#endif

namespace gourou
{
    /**
     * @brief Main class that handle all ADEPTS functions (fulfill, download, signIn, activate)
     */
    class DRMProcessor
    {
    public:

	/**
	 * @brief Main constructor. To be used once all is configured (user has signedIn, device is activated)
	 *
	 * @param client          Client processor
	 * @param deviceFile      Path of device.xml
	 * @param activationFile  Path of activation.xml
	 * @param deviceKeyFile   Path of devicesalt
	 */
        DRMProcessor(DRMProcessorClient* client, const std::string& deviceFile, const std::string& activationFile, const std::string& deviceKeyFile);
	
	~DRMProcessor();

	/**
	 * @brief Fulfill ACSM file to server in order to retrieve ePub fulfillment item
	 *
	 * @param ACSMFile       Path of ACSMFile
	 *
	 * @return a FulfillmentItem if all is OK
	 */
	FulfillmentItem* fulfill(const std::string& ACSMFile);

	/**
	 * @brief Once fulfilled, ePub file needs to be downloaded.
	 * During this operation, DRM information is added into downloaded file
	 *
	 * @param item            Item from fulfill() method
	 * @param path            Output file path 
	 */
	void download(FulfillmentItem* item, std::string path);

	/**
	 * @brief SignIn into ACS Server (required to activate device)
	 * 
	 * @param adobeID         AdobeID username
	 * @param adobePassword   Adobe password
	 */
	void signIn(const std::string& adobeID, const std::string& adobePassword);

	/**
	 * @brief Activate newly created device (user must have successfuly signedIn before)
	 */
	void activateDevice();

	/**
	 * @brief Create a new ADEPT environment (device.xml, devicesalt and activation.xml).
	 *
	 * @param client          Client processor
	 * @param randomSerial    Always generate a new device (or not)
	 * @param dirName         Directory where to put generated files (.adept)
	 * @param hobbes          Override hobbes default version
	 * @param ACSServer       Override main ACS server (default adeactivate.adobe.com)
	 */
        static DRMProcessor* createDRMProcessor(DRMProcessorClient* client,
						bool randomSerial=false, const std::string& dirName=std::string(DEFAULT_ADEPT_DIR),
						const std::string& hobbes=std::string(HOBBES_DEFAULT_VERSION),
						const std::string& ACSServer=ACS_SERVER);

	/**
	 * @brief Get current log level
	 */
	static int getLogLevel();

	/**
	 * @brief Set log level (higher number for verbose output)
	 */
	static void setLogLevel(int logLevel);

	/**
	 * Functions used internally, should not be called by user
	 */

	/**
	 * @brief Send HTTP (GET or POST) request
	 *
	 * @param URL            HTTP URL
	 * @param POSTData       POST data if needed, if not set, a GET request is done
	 * @param contentType    Optional content type of POST Data
	 */
	ByteArray sendRequest(const std::string& URL, const std::string& POSTData=std::string(), const char* contentType=0);

	/**
	 * @brief Send HTTP POST request to URL with document as POSTData
	 */
	ByteArray sendRequest(const pugi::xml_document& document, const std::string& url);

	/**
	 * @brief In place encrypt data with private device key
	 */
	ByteArray encryptWithDeviceKey(const unsigned char* data, unsigned int len);

	/**
	 * @brief In place decrypt data with private device key
	 */
	ByteArray decryptWithDeviceKey(const unsigned char* data, unsigned int len);

	/**
	 * @brief Return base64 encoded value of RSA public key
	 */
	std::string serializeRSAPublicKey(void* rsa);

	/**
	 * @brief Return base64 encoded value of RSA private key encrypted with private device key
	 */
	std::string serializeRSAPrivateKey(void* rsa);

	/**
	 * @brief Get current user
	 */
	User* getUser() { return user; }

	/**
	 * @brief Get current device
	 */
	Device* getDevice() { return device; }

	/**
	 * @brief Get current client
	 */
	DRMProcessorClient* getClient() { return client; }
		
    private:
	gourou::DRMProcessorClient* client;
        gourou::Device* device;
        gourou::User* user;
	
        DRMProcessor(DRMProcessorClient* client);
	
	void pushString(void* sha_ctx, const std::string& string);
	void pushTag(void* sha_ctx, uint8_t tag);
	void hashNode(const pugi::xml_node& root, void *sha_ctx, std::map<std::string,std::string> nsHash);
	void hashNode(const pugi::xml_node& root, unsigned char* sha_out);
	void buildFulfillRequest(pugi::xml_document& acsmDoc, pugi::xml_document& fulfillReq);
	void buildActivateReq(pugi::xml_document& activateReq);
	ByteArray sendFulfillRequest(const pugi::xml_document& document, const std::string& url);
	void buildSignInRequest(pugi::xml_document& signInRequest, const std::string& adobeID, const std::string& adobePassword, const std::string& authenticationCertificate);
    };
}

#endif
