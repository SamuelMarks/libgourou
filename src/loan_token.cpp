/*
  Copyright 2022 Grégory Soutadé

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

#include "libgourou_common.h"
#include "loan_token.h"

namespace gourou
{
    LoanToken::LoanToken(pugi::xml_document& doc)
    {
	pugi::xml_node node = doc.select_node("/envelope/loanToken").node();

	if (!node)
	    EXCEPTION(FFI_INVALID_LOAN_TOKEN, "No loanToken element in document");

	node = doc.select_node("/envelope/loanToken/loan").node();

	if (!node)
	    EXCEPTION(FFI_INVALID_LOAN_TOKEN, "No loanToken/loan element in document");

	properties["id"] = node.first_child().value();

	node = doc.select_node("/envelope/loanToken/operatorURL").node();

	if (!node)
	    EXCEPTION(FFI_INVALID_LOAN_TOKEN, "No loanToken/operatorURL element in document");

	properties["operatorURL"] = node.first_child().value();

	node = doc.select_node("/envelope/fulfillmentResult/resourceItemInfo/licenseToken/permissions/display/until").node();

	if (node)
	    properties["validity"] = node.first_child().value();
	else
	{
	    node = doc.select_node("/envelope/fulfillmentResult/resourceItemInfo/licenseToken/permissions/play/until").node();
	    if (node)
		properties["validity"] = node.first_child().value();
	    else
		EXCEPTION(FFI_INVALID_LOAN_TOKEN, "No loanToken/operatorURL element in document");
	}
    }

    std::string LoanToken::getProperty(const std::string& property, const std::string& _default)
    {
	if (properties.find(property) == properties.end())
	{
	    if (_default == "")
		EXCEPTION(GOUROU_INVALID_PROPERTY, "Invalid property " << property);

	    return _default;
	}

	return properties[property];
    }

    std::string LoanToken::operator[](const std::string& property)
    {
	return getProperty(property);
    }
}
