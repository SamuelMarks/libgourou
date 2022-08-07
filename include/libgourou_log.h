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

#ifndef _LIBGOUROU_LOG_H_
#define _LIBGOUROU_LOG_H_

#include <iostream>

namespace gourou {
    enum GOUROU_LOG_LEVEL {
	LG_LOG_ERROR,
	LG_LOG_WARN,
	LG_LOG_INFO,
	LG_LOG_DEBUG,
	LG_LOG_TRACE
    };

    extern GOUROU_LOG_LEVEL logLevel;

#define GOUROU_LOG(__lvl, __msg) if (gourou::LG_LOG_##__lvl <= gourou::logLevel) {std::cout << __msg << std::endl << std::flush;}
#define GOUROU_LOG_FUNC() GOUROU_LOG(TRACE, __FUNCTION__ << "() @ " << __FILE__ << ":" << __LINE__)

    /**
     * @brief Get current log level
     */
    GOUROU_LOG_LEVEL getLogLevel();

    /**
     * @brief Set log level
     */
    void setLogLevel(GOUROU_LOG_LEVEL level);
}

#endif
