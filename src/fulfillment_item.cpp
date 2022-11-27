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

#include <cctype>
#include <fulfillment_item.h>
#include <libgourou_common.h>
#include "user.h"

namespace gourou
{
    FulfillmentItem::FulfillmentItem(pugi::xml_document& doc, User* user)
	: fulfillDoc(), loanToken(0)
    {
	fulfillDoc.reset(doc); /* We must keep a copy */
	metadatas = fulfillDoc.select_node("//metadata").node();
	
	if (!metadatas)
	    EXCEPTION(FFI_INVALID_FULFILLMENT_DATA, "No metadata tag in document");
	
	pugi::xml_node node = doc.select_node("/envelope/fulfillmentResult/resourceItemInfo/src").node();
	downloadURL = node.first_child().value();

	if (downloadURL == "")
	    EXCEPTION(FFI_INVALID_FULFILLMENT_DATA, "No download URL in document");
	
	node = doc.select_node("/envelope/fulfillmentResult/resourceItemInfo/resource").node();
	resource = node.first_child().value();

	if (resource == "")
	    EXCEPTION(FFI_INVALID_FULFILLMENT_DATA, "No resource in document");

	pugi::xml_node licenseToken = doc.select_node("/envelope/fulfillmentResult/resourceItemInfo/licenseToken").node();

	if (!licenseToken)
	    EXCEPTION(FFI_INVALID_FULFILLMENT_DATA, "Any license token in document");
	
	buildRights(licenseToken, user);

	node = doc.select_node("/envelope/fulfillmentResult/returnable").node();
	try
	{
	    if (node && node.first_child().value() == std::string("true"))
		loanToken = new LoanToken(doc);
	}
	catch(std::exception& e)
	{
	    GOUROU_LOG(ERROR, "Book is returnable, but contains invalid loan token");
	    GOUROU_LOG(ERROR, e.what());
	}
    }

    FulfillmentItem::~FulfillmentItem()
    {
	if (loanToken) delete loanToken;
    }
    
    void FulfillmentItem::buildRights(const pugi::xml_node& licenseToken, User* user)
    {
	pugi::xml_node decl = rights.append_child(pugi::node_declaration);
	decl.append_attribute("version") = "1.0";
	
	pugi::xml_node root = rights.append_child("adept:rights");
	root.append_attribute("xmlns:adept") = ADOBE_ADEPT_NS;
	
	pugi::xml_node newLicenseToken = root.append_copy(licenseToken);
	if (!newLicenseToken.attribute("xmlns"))
	    newLicenseToken.append_attribute("xmlns") = ADOBE_ADEPT_NS;

	pugi::xml_node licenseServiceInfo = root.append_child("adept:licenseServiceInfo");
	pugi::xml_node licenseURL = licenseToken.select_node("licenseURL").node();
	licenseURL.set_name("adept:licenseURL");
	licenseServiceInfo.append_copy(licenseURL);
	pugi::xml_node certificate = licenseServiceInfo.append_child("adept:certificate");
	const std::string certificateValue = user->getLicenseServiceCertificate(licenseURL.first_child().value());
	certificate.append_child(pugi::node_pcdata).set_value(certificateValue.c_str());
    }
    
    std::string FulfillmentItem::getMetadata(std::string name)
    {
	// https://stackoverflow.com/questions/313970/how-to-convert-an-instance-of-stdstring-to-lower-case
	#if __STDC_VERSION__ >= 201112L
	std::transform(name.begin(), name.end(), name.begin(),
		       [](unsigned char c){ return std::tolower(c); });
	#else
	std::transform(name.begin(), name.end(), name.begin(), tolower);
	#endif
	name = std::string("dc:") + name;
	pugi::xpath_node path = metadatas.select_node(name.c_str());

	if (!path)
	    return "";

	return path.node().first_child().value();
    }
    
    std::string FulfillmentItem::getRights()
    {
	StringXMLWriter xmlWriter;
	rights.save(xmlWriter, "  ");
	return xmlWriter.getResult();
    }
   
    std::string FulfillmentItem::getDownloadURL()
    {
	return downloadURL;
    }

    std::string FulfillmentItem::getResource()
    {
	return resource;
    }

    LoanToken* FulfillmentItem::getLoanToken()
    {
	return loanToken;
    }
}
