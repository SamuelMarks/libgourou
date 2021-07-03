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

#include <fulfillment_item.h>
#include <libgourou_common.h>
#include "user.h"

namespace gourou
{
    FulfillmentItem::FulfillmentItem(pugi::xml_document& doc, User* user)
    {
	metadatas = doc.select_node("//metadata").node();

	if (!metadatas)
	    EXCEPTION(FFI_INVALID_FULFILLMENT_DATA, "No metadata tag in document");
	
	pugi::xml_node node = doc.select_node("/envelope/fulfillmentResult/resourceItemInfo/src").node();
	downloadURL = node.first_child().value();

	if (downloadURL == "")
	    EXCEPTION(FFI_INVALID_FULFILLMENT_DATA, "No download URL in document");
	
	pugi::xml_node licenseToken = doc.select_node("/envelope/fulfillmentResult/resourceItemInfo/licenseToken").node();

	if (!licenseToken)
	    EXCEPTION(FFI_INVALID_FULFILLMENT_DATA, "Any license token in document");
	
	buildRights(licenseToken, user);
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
	
	pugi::xml_node licenseServiceInfo = root.append_child("licenseServiceInfo");
	licenseServiceInfo.append_attribute("xmlns") = ADOBE_ADEPT_NS;
	licenseServiceInfo.append_copy(licenseToken.select_node("licenseURL").node());
	pugi::xml_node certificate = licenseServiceInfo.append_child("certificate");
	certificate.append_child(pugi::node_pcdata).set_value(user->getCertificate().c_str());
    }
    
    std::string FulfillmentItem::getMetadata(std::string name)
    {
	// https://stackoverflow.com/questions/313970/how-to-convert-an-instance-of-stdstring-to-lower-case
	std::transform(name.begin(), name.end(), name.begin(),
		       [](unsigned char c){ return std::tolower(c); });
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
}
