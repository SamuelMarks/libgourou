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

#ifndef _BYTEARRAY_H_
#define _BYTEARRAY_H_

#include <map>
#include <string>

namespace gourou
{
    /**
     * @brief Utility class for byte array management.
     *
     * It's an equivalent of QByteArray
     *
     * Data handled is first copied in a newly allocated buffer
     * and then shared between all copies until last object is destroyed
     */
    class ByteArray
    {
    public:

	/**
	 * @brief Create an empty byte array
	 */
	ByteArray();

	/**
	 * @brief Initialize ByteArray with a copy of data
	 *
	 * @param data    Data to be copied
	 * @param length  Length of data
	 */
	ByteArray(const unsigned char* data, unsigned int length);

	/**
	 * @brief Initialize ByteArray with a copy of data
	 *
	 * @param data    Data to be copied
	 * @param length  Optional length of data. If length == -1, it use strlen(data) as length
	 */
	ByteArray(const char* data, int length=-1);

	/**
	 * @brief Initialize ByteArray with a copy of str
	 *
	 * @param str     Use internal data of str
	 */
	ByteArray(const std::string& str);

	ByteArray(const ByteArray& other);
	~ByteArray();

	/**
	 * @brief Encode "other" data into base64 and put it into a ByteArray
	 */
	static ByteArray fromBase64(const ByteArray& other);

	/**
	 * @brief Encode data into base64 and put it into a ByteArray
	 *
	 * @param data    Data to be encoded
	 * @param length  Optional length of data. If length == -1, it use strlen(data) as length
	 */
	static ByteArray fromBase64(const char* data, int length=-1);

	/**
	 * @brief Encode str into base64 and put it into a ByteArray
	 *
	 * @param str     Use internal data of str
	 */
	static ByteArray fromBase64(const std::string& str);

	/**
	 * @brief Return a string with base64 encoded internal data
	 */
	std::string toBase64();

	/**
	 * @brief Return a string with human readable hex encoded internal data
	 */
	std::string toHex();

	/**
	 * @brief Append a byte to internal data
	 */
	void append(unsigned char c);

	/**
	 * @brief Append data to internal data
	 */
	void append(const unsigned char* data, unsigned int length);

	/**
	 * @brief Append str to internal data
	 */
	void append(const char* str);

	/**
	 * @brief Append str to internal data
	 */
	void append(const std::string& str);

	/**
	 * @brief Get internal data. Must bot be modified nor freed
	 */
	const unsigned char* data() {return _data;}

	/**
	 * @brief Get internal data length
	 */
	unsigned int length() {return _length;}

	ByteArray& operator=(const ByteArray& other);
	
    private:
	void initData(const unsigned char* data, unsigned int length);
	void addRef();
	void delRef();
	
	const unsigned char* _data;
	unsigned int _length;
	static std::map<const unsigned char*, int> refCounter;
    };
}
#endif
