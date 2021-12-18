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

#include <libgourou.h>
#include <libgourou_common.h>
#include <libgourou_log.h>
#include <user.h>

namespace gourou {
    User::User(DRMProcessor* processor):processor(processor) {}
    
    User::User(DRMProcessor* processor, const std::string& activationFile):
	processor(processor), activationFile(activationFile)
    {
	parseActivationFile();
    }

    void User::parseActivationFile(bool throwOnNull)
    {
	GOUROU_LOG(DEBUG, "Parse activation file " << activationFile);
	
	if (!activationDoc.load_file(activationFile.c_str()))
	{
	    if (throwOnNull)
		EXCEPTION(USER_INVALID_ACTIVATION_FILE, "Invalid activation file");
	    return;
	}

	try
	{
	    pkcs12      = gourou::extractTextElem(activationDoc, "//adept:pkcs12", throwOnNull);
	    uuid        = gourou::extractTextElem(activationDoc, "//adept:user", throwOnNull);
	    deviceUUID  = gourou::extractTextElem(activationDoc, "//device", throwOnNull);
	    deviceFingerprint = gourou::extractTextElem(activationDoc, "//fingerprint", throwOnNull);
	    authenticationCertificate = gourou::extractTextElem(activationDoc, "//adept:authenticationCertificate", throwOnNull);
	    privateLicenseKey = gourou::extractTextElem(activationDoc, "//adept:privateLicenseKey", throwOnNull);

	    pugi::xpath_node xpath_node = activationDoc.select_node("//adept:username");
	    if (xpath_node)
		loginMethod = xpath_node.node().attribute("method").value();
	    else
	    {
		if (throwOnNull)
		    EXCEPTION(USER_INVALID_ACTIVATION_FILE, "Invalid activation file");
	    }
	    
	    if (loginMethod == "anonymous")
		username = "anonymous";
	    else
		username    = gourou::extractTextElem(activationDoc, "//adept:username", throwOnNull);
	    
	    pugi::xpath_node_set nodeSet = activationDoc.select_nodes("//adept:licenseServices/adept:licenseServiceInfo");
	    for (pugi::xpath_node_set::const_iterator it = nodeSet.begin();
		 it != nodeSet.end(); ++it)
	    {
		std::string url = gourou::extractTextElem(it->node(), "adept:licenseURL");
		std::string certificate = gourou::extractTextElem(it->node(), "adept:certificate");
		licenseServiceCertificates[url] = certificate;
	    }
	}
	catch(gourou::Exception& e)
	{
	    EXCEPTION(USER_INVALID_ACTIVATION_FILE, "Invalid activation file");
	}
    }

    std::string& User::getUUID()              { return uuid; }
    std::string& User::getPKCS12()            { return pkcs12; }
    std::string& User::getDeviceUUID()        { return deviceUUID; }
    std::string& User::getDeviceFingerprint() { return deviceFingerprint; }
    std::string& User::getUsername()          { return username; }
    std::string& User::getLoginMethod()       { return loginMethod; }
    std::string& User::getAuthenticationCertificate() { return authenticationCertificate; }
    std::string& User::getPrivateLicenseKey() { return privateLicenseKey; }
    
    void User::readActivation(pugi::xml_document& doc)
    {
	if (!doc.load_file(activationFile.c_str()))
	    EXCEPTION(USER_INVALID_ACTIVATION_FILE, "Invalid activation file");
    }

    void User::updateActivationFile(const char* data)
    {
	GOUROU_LOG(INFO, "Update Activation file : " << std::endl << data);

	writeFile(activationFile, (unsigned char*)data, strlen(data));
	
	parseActivationFile(false);
    }
    
    void User::updateActivationFile(const pugi::xml_document& doc)
    {
	StringXMLWriter xmlWriter;
	doc.save(xmlWriter, "  ");
	updateActivationFile(xmlWriter.getResult().c_str());
    }

    std::string User::getProperty(const std::string property)
    {
	pugi::xpath_node xpathRes = activationDoc.select_node(property.c_str());
	if (!xpathRes)
	    EXCEPTION(USER_NO_PROPERTY, "Property " << property << " not found in activation.xml");

	std::string res = xpathRes.node().first_child().value();
	return trim(res);
    }
    
    pugi::xpath_node_set User::getProperties(const std::string property)
    {
	return activationDoc.select_nodes(property.c_str());
    }

    User* User::createUser(DRMProcessor* processor, const std::string& dirName, const std::string& ACSServer)
    {
	struct stat _stat;

	if (stat(dirName.c_str(), &_stat) != 0)
	{
	    if (mkdir_p(dirName.c_str(), S_IRWXU))
		EXCEPTION(USER_MKPATH, "Unable to create " << dirName)
	}

	User* user = new User(processor);
	bool doUpdate = false;
	
	user->activationFile = dirName + "/activation.xml";
	user->parseActivationFile(false);

	pugi::xpath_node nodeActivationInfo = user->activationDoc.select_node("activation_info");
	pugi::xpath_node nodeActivationServiceInfo = nodeActivationInfo.node().select_node("adept:activationServiceInfo");
	pugi::xml_node activationInfo;
	pugi::xml_node activationServiceInfo;
	
	if (nodeActivationInfo && nodeActivationServiceInfo)
	{
	    GOUROU_LOG(DEBUG, "Read previous activation configuration");
	    activationInfo = nodeActivationInfo.node();
	    activationServiceInfo = nodeActivationServiceInfo.node();
	}
	else
	{
	    GOUROU_LOG(DEBUG, "Create new activation");

	    user->activationDoc.reset();
	    
	    pugi::xml_node decl = user->activationDoc.append_child(pugi::node_declaration);
	    decl.append_attribute("version") = "1.0";
	    activationInfo = user->activationDoc.append_child("activationInfo");
	    activationInfo.append_attribute("xmlns") = ADOBE_ADEPT_NS;
	    activationServiceInfo = activationInfo.append_child("adept:activationServiceInfo");
	    activationServiceInfo.append_attribute("xmlns:adept") = ADOBE_ADEPT_NS;
	
	    // Go to activation Service Info
	    std::string activationURL = ACSServer + "/ActivationServiceInfo";
	    ByteArray activationServiceInfoReply = processor->sendRequest(activationURL);
	    pugi::xml_document docActivationServiceInfo;
	    docActivationServiceInfo.load_buffer(activationServiceInfoReply.data(),
						 activationServiceInfoReply.length());

	    pugi::xpath_node path = docActivationServiceInfo.select_node("//authURL");
	    appendTextElem(activationServiceInfo, "adept:authURL", path.node().first_child().value());
	    path = docActivationServiceInfo.select_node("//userInfoURL");
	    appendTextElem(activationServiceInfo, "adept:userInfoURL", path.node().first_child().value());
	    appendTextElem(activationServiceInfo, "adept:activationURL", ACSServer);
	    path = docActivationServiceInfo.select_node("//certificate");
	    appendTextElem(activationServiceInfo, "adept:certificate", path.node().first_child().value());
	    doUpdate = true;
	}
	
	pugi::xpath_node nodeAuthenticationCertificate = activationServiceInfo.select_node("adept:authenticationCertificate");

	if (!nodeAuthenticationCertificate)
	{
	    GOUROU_LOG(DEBUG, "Create new activation, authentication part");

	    pugi::xpath_node xpathRes = activationServiceInfo.select_node("adept:authURL");
	    if (!xpathRes)
		EXCEPTION(USER_NO_AUTHENTICATION_URL, "No authentication URL");
	
	    std::string authenticationURL = xpathRes.node().first_child().value();
	    authenticationURL = trim(authenticationURL) + "/AuthenticationServiceInfo";
	    
	    // Go to authentication Service Info
	    ByteArray authenticationServiceInfo = processor->sendRequest(authenticationURL);
	    pugi::xml_document docAuthenticationServiceInfo;
	    docAuthenticationServiceInfo.load_buffer(authenticationServiceInfo.data(), authenticationServiceInfo.length());
	    pugi::xpath_node path = docAuthenticationServiceInfo.select_node("//certificate");
	    appendTextElem(activationServiceInfo, "adept:authenticationCertificate", path.node().first_child().value());
	    doUpdate = true;
	}

	if (doUpdate)
	    user->updateActivationFile(user->activationDoc);
	    
	
	return user;
    }

    std::string User::getLicenseServiceCertificate(std::string url)
    {
	if (licenseServiceCertificates.count(trim(url)))
	    return licenseServiceCertificates[trim(url)];

	return "";
    }

}
