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

#ifndef _LIBGOUROU_COMMON_H_
#define _LIBGOUROU_COMMON_H_

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <pugixml.hpp>

#include <exception>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>

#include <string.h>

#include <libgourou_log.h>
#include "bytearray.h"

namespace gourou
{
    /**
     * Some common utilities
     */
    
    #define ADOBE_ADEPT_NS  "http://ns.adobe.com/adept"

    static const int SHA1_LEN           = 20;
    static const int RSA_KEY_SIZE       = 128;
    static const int RSA_KEY_SIZE_BITS  = (RSA_KEY_SIZE*8);
    
    enum GOUROU_ERROR {
	GOUROU_DEVICE_DOES_NOT_MATCH = 0x1000,
	GOUROU_INVALID_CLIENT,
	GOUROU_TAG_NOT_FOUND,
	GOUROU_ADEPT_ERROR,
	GOUROU_FILE_ERROR,
	GOUROU_INVALID_PROPERTY
    };

    enum FULFILL_ERROR {
	FF_ACSM_FILE_NOT_EXISTS = 0x1100,
	FF_INVALID_ACSM_FILE,
	FF_NO_HMAC_IN_ACSM_FILE,
	FF_NOT_ACTIVATED,
	FF_NO_OPERATOR_URL
    };

    enum DOWNLOAD_ERROR {
	DW_NO_ITEM = 0x1200,
	DW_NO_EBX_HANDLER,
    };

    enum SIGNIN_ERROR {
	SIGN_INVALID_CREDENTIALS = 0x1300,
    };
    
    enum ACTIVATE_ERROR {
	ACTIVATE_NOT_SIGNEDIN = 0x1400
    };
    
    enum DEV_ERROR {
	DEV_MKPATH = 0x2000,
	DEV_MAC_ERROR,
	DEV_INVALID_DEVICE_FILE,
	DEV_INVALID_DEVICE_KEY_FILE,
	DEV_INVALID_DEV_PROPERTY,
    };

    enum USER_ERROR {
	USER_MKPATH = 0x3000,
	USER_INVALID_ACTIVATION_FILE,
	USER_NO_AUTHENTICATION_URL,
	USER_NO_PROPERTY,
	USER_INVALID_INPUT,
    };

    enum FULFILL_ITEM_ERROR {
	FFI_INVALID_FULFILLMENT_DATA = 0x4000,
	FFI_INVALID_LOAN_TOKEN
    };
    
    enum CLIENT_ERROR {
	CLIENT_BAD_PARAM = 0x5000,
	CLIENT_INVALID_PKCS12,
	CLIENT_INVALID_CERTIFICATE,
	CLIENT_NO_PRIV_KEY,
	CLIENT_RSA_ERROR,
	CLIENT_BAD_CHAINING,
	CLIENT_BAD_KEY_SIZE,
	CLIENT_BAD_ZIP_FILE,
	CLIENT_ZIP_ERROR,
	CLIENT_GENERIC_EXCEPTION,
	CLIENT_NETWORK_ERROR,
	CLIENT_INVALID_PKCS8,
	CLIENT_FILE_ERROR,
	CLIENT_OSSL_ERROR,
    };

    enum DRM_REMOVAL_ERROR {
	DRM_ERR_ENCRYPTION_KEY = 0x6000,
	DRM_VERSION_NOT_SUPPORTED,
	DRM_FILE_ERROR,
	DRM_FORMAT_NOT_SUPPORTED,
	DRM_IN_OUT_EQUALS,
	DRM_MISSING_PARAMETER,
	DRM_INVALID_KEY_SIZE
    };

    /**
     * Generic exception class
     */
    class Exception : public std::exception
    {
    public:
	Exception(int code, const char* message, const char* file, int line):
	    code(code), line(line), file(file)
	{
	    std::stringstream msg;
	    msg << "Exception code : 0x" << std::setbase(16) << code << std::endl;
	    msg << "Message        : " << message << std::endl;
	    if (logLevel >= DEBUG)
		msg << "File           : " << file << ":" << std::setbase(10) << line << std::endl;
	    fullmessage = strdup(msg.str().c_str());
	}

	Exception(const Exception& other)
	{
	    this->code = other.code;
	    this->line = line;
	    this->file = file;
	    this->fullmessage = strdup(other.fullmessage);
	}

	~Exception()
	{
	    free(fullmessage);
	}

	const char * what () const throw () { return fullmessage; }
	
	int getErrorCode() {return code;}
	
	private:
	int code, line;
	const char* message, *file;
	char* fullmessage;
    };

    /**
     * @brief Throw an exception
     */
#define EXCEPTION(code, message)					\
    {std::stringstream __msg;__msg << message; throw gourou::Exception(code, __msg.str().c_str(), __FILE__, __LINE__);}

    /**
     * Stream writer for pugi::xml
     */
    class StringXMLWriter : public pugi::xml_writer
    {
    public:
	virtual void write(const void* data, size_t size)
	{
	    result.append(static_cast<const char*>(data), size);
	}

	const std::string& getResult() {return result;}

    private:
	std::string result;
    };

    static const char* ws = " \t\n\r\f\v";

    /**
     * @brief trim from end of string (right)
     */
    inline std::string& rtrim(std::string& s, const char* t = ws)
    {
	s.erase(s.find_last_not_of(t) + 1);
	return s;
    }

    /**
     * @brief trim from beginning of string (left)
     */
    inline std::string& ltrim(std::string& s, const char* t = ws)
    {
	s.erase(0, s.find_first_not_of(t));
	return s;
    }

    /**
     * @brief trim from both ends of string (right then left)
     */
    inline std::string& trim(std::string& s, const char* t = ws)
    {
	return ltrim(rtrim(s, t), t);
    }

    /**
     * @brief Extract text node from tag in document
     * It can throw an exception if tag does not exists
     * or just return an empty value
     */
    static inline std::string extractTextElem(const pugi::xml_document& doc, const char* tagName, bool throwOnNull=true)
    {
        pugi::xpath_node xpath_node = doc.select_node(tagName);

        if (!xpath_node)
	{
	    if (throwOnNull)
		EXCEPTION(GOUROU_TAG_NOT_FOUND, "Tag " << tagName << " not found");
	    
            return "";
	}

	pugi::xml_node node = xpath_node.node().first_child();

	if (!node)
	{
	    if (throwOnNull)
		EXCEPTION(GOUROU_TAG_NOT_FOUND, "Text element for tag " << tagName << " not found");
	    
            return "";
	}

	std::string res = node.value();
        return trim(res);
    }

    static inline std::string extractTextElem(const pugi::xml_node& doc, const char* tagName, bool throwOnNull=true)
    {
        pugi::xpath_node xpath_node = doc.select_node(tagName);

        if (!xpath_node)
	{
	    if (throwOnNull)
		EXCEPTION(GOUROU_TAG_NOT_FOUND, "Tag " << tagName << " not found");
	    
            return "";
	}

	pugi::xml_node node = xpath_node.node().first_child();

	if (!node)
	{
	    if (throwOnNull)
		EXCEPTION(GOUROU_TAG_NOT_FOUND, "Text element for tag " << tagName << " not found");
	    
            return "";
	}

	std::string res = node.value();
        return trim(res);
    }

    /**
     * @brief Append an element to root with a sub text element
     *
     * @param root  Root node where to put child
     * @param name  Tag name for child
     * @param value Text child value of tag element
     */
    static inline void appendTextElem(pugi::xml_node& root, const std::string& name, const std::string& value)
    {
	pugi::xml_node node = root.append_child(name.c_str());
	node.append_child(pugi::node_pcdata).set_value(value.c_str());
    }

    /**
     * @brief Open a file descriptor on path. If it already exists and truncate == true, it's truncated
     *
     * @return Created fd, must be closed
     */
    static inline int createNewFile(std::string path, bool truncate=true)
    {
	int options = O_CREAT|O_WRONLY;
	if (truncate)
	    options |= O_TRUNC;
	else
	    options |= O_APPEND;

	int fd = open(path.c_str(), options, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH);

	if (fd <= 0)
	    EXCEPTION(GOUROU_FILE_ERROR, "Unable to create " << path);

	return fd;
    }
    
    /**
     * @brief Write data in a file. If it already exists, it's truncated
     */
    static inline void writeFile(std::string path, const unsigned char* data, unsigned int length)
    {
	int fd = createNewFile(path);
	
	if (write(fd, data, length) != length)
	    EXCEPTION(GOUROU_FILE_ERROR, "Write error for file " << path);

	close (fd);
    }

    /**
     * @brief Write data in a file. If it already exists, it's truncated
     */
    static inline void writeFile(std::string path, ByteArray& data)
    {
	writeFile(path, data.data(), data.length());
    }

    /**
     * @brief Write data in a file. If it already exists, it's truncated
     */
    static inline void writeFile(std::string path, const std::string& data)
    {
	writeFile(path, (const unsigned char*)data.c_str(), data.length());
    }

    /**
     * Read data from file
     */
    static inline void readFile(std::string path, const unsigned char* data, unsigned int length)
    {
	int fd = open(path.c_str(), O_RDONLY);

	if (fd <= 0)
	    EXCEPTION(GOUROU_FILE_ERROR, "Unable to open " << path);

	if (read(fd, (void*)data, length) != length)
	    EXCEPTION(GOUROU_FILE_ERROR, "Read error for file " << path);

	close (fd);
    }

#define PATH_MAX_STRING_SIZE 256

    // https://gist.github.com/ChisholmKyle/0cbedcd3e64132243a39
/* recursive mkdir */
    static inline int mkdir_p(const char *dir, const mode_t mode) {
	char tmp[PATH_MAX_STRING_SIZE];
	char *p = NULL;
	struct stat sb;
	size_t len;
    
	/* copy path */
	len = strnlen (dir, PATH_MAX_STRING_SIZE);
	if (len == 0 || len == PATH_MAX_STRING_SIZE) {
	    return -1;
	}
	memcpy (tmp, dir, len);
	tmp[len] = '\0';

	/* remove trailing slash */
	if(tmp[len - 1] == '/') {
	    tmp[len - 1] = '\0';
	}

	/* check if path exists and is a directory */
	if (stat (tmp, &sb) == 0) {
	    if (S_ISDIR (sb.st_mode)) {
		return 0;
	    }
	}
    
	/* recursive mkdir */
	for(p = tmp + 1; *p; p++) {
	    if(*p == '/') {
		*p = 0;
		/* test path */
		if (stat(tmp, &sb) != 0) {
		    /* path does not exist - create directory */
		    if (mkdir(tmp, mode) < 0) {
			return -1;
		    }
		} else if (!S_ISDIR(sb.st_mode)) {
		    /* not a directory */
		    return -1;
		}
		*p = '/';
	    }
	}
	/* test path */
	if (stat(tmp, &sb) != 0) {
	    /* path does not exist - create directory */
	    if (mkdir(tmp, mode) < 0) {
		return -1;
	    }
	} else if (!S_ISDIR(sb.st_mode)) {
	    /* not a directory */
	    return -1;
	}
	return 0;
    }
}

#endif
