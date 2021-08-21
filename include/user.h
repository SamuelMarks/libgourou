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

#ifndef _USER_H_
#define _USER_H_

#include <string>
#include <map>

#include "bytearray.h"

#include <pugixml.hpp>

namespace gourou
{
    class DRMProcessor;
    
    /**
     * @brief This class is a container for activation.xml (activation info). It should not be used by user.
     */
    class User
    {
    public:
        User(DRMProcessor* processor, const std::string& activationFile);

	/**
	 * @brief Retrieve some values from activation.xml 
	 */
	std::string& getUUID();
	std::string& getPKCS12();
	std::string& getDeviceUUID();
	std::string& getDeviceFingerprint();
	std::string& getUsername();
	std::string& getLoginMethod();
	std::string  getLicenseServiceCertificate(std::string url);
	std::string& getAuthenticationCertificate();
	std::string& getPrivateLicenseKey();

	/**
	 * @brief Read activation.xml and put result into doc
	 */
	void readActivation(pugi::xml_document& doc);

	/**
	 * @brief Update activation.xml with new data
	 */
	void updateActivationFile(const char* data);

	/**
	 * @brief Update activation.xml with doc data
	 */
	void updateActivationFile(const pugi::xml_document& doc);

	/**
	 * @brief Get one value of activation.xml 
	 */
	std::string getProperty(const std::string property);
	
	/**
	 * @brief Get all nodes with property name
	 */
	pugi::xpath_node_set getProperties(const std::string property);
	
	/**
	 * @brief Create activation.xml and devicesalt files if they did not exists
	 *
	 * @param processor      Instance of DRMProcessor
	 * @param dirName        Directory where to put files (.adept)
	 * @param ACSServer      Server used for signIn
	 */
	static User* createUser(DRMProcessor* processor, const std::string& dirName, const std::string& ACSServer);

    private:
	DRMProcessor* processor;
	pugi::xml_document activationDoc;
	
        std::string activationFile;
	std::string pkcs12;
	std::string uuid;
	std::string deviceUUID;
	std::string deviceFingerprint;
	std::string username;
	std::string loginMethod;
	std::map<std::string,std::string> licenseServiceCertificates;
	std::string authenticationCertificate;
	std::string privateLicenseKey;

	User(DRMProcessor* processor);
	
	void parseActivationFile(bool throwOnNull=true);
	ByteArray signIn(const std::string& adobeID, const std::string& adobePassword,
			 ByteArray authenticationCertificate);
    };
}

#endif
