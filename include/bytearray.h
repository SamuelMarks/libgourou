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

#ifndef _BYTEARRAY_H_
#define _BYTEARRAY_H_

#include <map>
#include <string>

#include "libgourou_export.h"

namespace gourou
{
    /**
     * @brief Utility class for byte array management.
     *
     * It's an equivalent of QByteArray
     *
     * Data handled is first copied in a newly allocated buffer
     * and then shared between all copies until last object is destroyed
     * (internal reference counter == 0)
     */
    LIBGOUROU_EXPORT class ByteArray
    {
    public:

	/**
	 * @brief Create an empty byte array
	 *
	 * @param useMalloc If true, use malloc() instead of new[] for allocation
	 */
	ByteArray(bool useMalloc=false);

	/**
	 * @brief Create an empty byte array of length bytes
	 *
	 * @param length  Length of data
	 * @param useMalloc If true, use malloc() instead of new[] for allocation
	 */
	ByteArray(unsigned int length, bool useMalloc=false);

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
	 * @brief Convert hex string into bytes
	 *
	 * @param str     Hex string
	 */
	static ByteArray fromHex(const std::string& str);

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
	 * @brief Get internal data. Must not be freed
	 */
	unsigned char* data() {return _data;}

	/**
	 * @brief Get internal data and increment internal reference counter.
	 * Must bot be freed
	 */
	unsigned char* takeShadowData() {addRef() ; return _data;}

	/**
	 * @brief Release shadow data. It can now be freed by ByteArray
	 */
	void releaseShadowData() {delRef();}

	/**
	 * @brief Get internal data length
	 */
	unsigned int length() const {return _length;}

	/**
	 * @brief Get internal data length
	 */
	unsigned int size() const {return length();}

	/**
	 * @brief Increase or decrease internal buffer
	 * @param length New length of internal buffer
	 * @param keepData If true copy old data on new buffer, if false,
	 * create a new buffer with random data
	 */
	void resize(unsigned int length, bool keepData=true);

	ByteArray& operator=(const ByteArray& other);
	
    private:
	void initData(const unsigned char* data, unsigned int length);
	void addRef();
	void delRef();

	bool _useMalloc;
	unsigned char* _data;
	unsigned int _length;
	static std::map<unsigned char*, int> refCounter;
    };
}
#endif
