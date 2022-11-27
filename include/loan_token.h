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

#ifndef _LOAN_TOKEN_H_
#define _LOAN_TOKEN_H_

#include <map>

#include <pugixml.hpp>

#include "libgourou_export.h"

namespace gourou
{
    /**
     * @brief This class is a container for a fulfillment object
     */
    LIBGOUROU_EXPORT class LoanToken
    {
    public:
	/**
	 * @brief Main constructor. Not to be called by user
	 *
	 * @param doc   Fulfill reply
	 */
	LoanToken(pugi::xml_document& doc);

	/**
	 * @brief Get a property (id, operatorURL, validity)
	 */
	std::string getProperty(const std::string& property, const std::string& _default=std::string(""));
	std::string operator[](const std::string& property);

    private:
	std::map<std::string, std::string> properties;
    };
}


#endif
