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
#include <string.h>
#include <stdexcept>

#include <Base64.h>

#include <bytearray.h>

namespace gourou
{
    std::map<unsigned char*, int> ByteArray::refCounter;
    
    ByteArray::ByteArray(bool useMalloc):_useMalloc(useMalloc), _data(0), _length(0)
    {}

    ByteArray::ByteArray(unsigned int length, bool useMalloc):
	_useMalloc(useMalloc)
    {
	initData(0, length);
    }
    
    ByteArray::ByteArray(const unsigned char* data, unsigned int length):
	_useMalloc(false)
    {
	initData(data, length);
    }
    
    ByteArray::ByteArray(const char* data, int length):
	_useMalloc(false)
    {
	if (length == -1)
	    length = strlen(data);

	initData((unsigned char*)data, (unsigned int) length);
    }
    
    ByteArray::ByteArray(const std::string& str):
	_useMalloc(false)
    {
	initData((unsigned char*)str.c_str(), (unsigned int)str.length());
    }

    void ByteArray::initData(const unsigned char* data, unsigned int length)
    {
	if (_useMalloc)
	    _data = (unsigned char*)malloc(length);
	else
	    _data = new unsigned char[length];

	if (data)
	    memcpy((void*)_data, data, length);

	_length = length;

	addRef();
    }
    
    ByteArray::ByteArray(const ByteArray& other)
    {
	this->_useMalloc = other._useMalloc;
	this->_data = other._data;
	this->_length = other._length;

	addRef();
    }

    ByteArray& ByteArray::operator=(const ByteArray& other)
    {
	delRef();
	
	this->_useMalloc = other._useMalloc;
	this->_data = other._data;
	this->_length = other._length;

	addRef();
	
	return *this;
    }
    
    ByteArray::~ByteArray()
    {
	delRef();
    }
	
    void ByteArray::addRef()
    {
	if (!_data) return;

	if (refCounter.count(_data) == 0)
	    refCounter[_data] = 1;
	else
	    refCounter[_data]++;
    }
    
    void ByteArray::delRef()
    {
	if (!_data) return;
	
	if (refCounter[_data] == 1)
	{
	    if (_useMalloc)
		free(_data);
	    else
		delete[] _data;
	    refCounter.erase(_data);
	}
	else
	    refCounter[_data]--;
    }

    ByteArray ByteArray::fromBase64(const ByteArray& other)
    {
	std::string b64;

	macaron::Base64::Decode(std::string((char*)other._data, other._length), b64);

	return ByteArray(b64);
    }
    
    ByteArray ByteArray::fromBase64(const char* data, int length)
    {
	std::string b64;

	if (length == -1)
	    length = strlen(data);
	
	macaron::Base64::Decode(std::string(data, length), b64);

	return ByteArray(b64);
    }
    
    ByteArray ByteArray::fromBase64(const std::string& str)
    {
	return ByteArray::fromBase64(str.c_str(), str.length());
    }
    
    std::string ByteArray::toBase64()
    {
	return macaron::Base64::Encode(std::string((char*)_data, _length));
    }

    ByteArray ByteArray::fromHex(const std::string& str)
    {
	if (str.size() % 2)
	    throw std::invalid_argument("Size of hex string not multiple of 2");

	ByteArray res((unsigned int)(str.size()/2));
	unsigned int i;

	unsigned char* data = res.data();
	unsigned char cur, tmp;
	
	for (i=0; i<str.size(); i+=2)
	{
	    cur = 0;

	    tmp = str[i];
	    if (tmp >= 'a' && tmp <= 'f')
		cur = (tmp - 'a' + 10) << 4;
	    else if (tmp >= 'A' && tmp <= 'F')
		cur = (tmp - 'A' + 10) << 4;
	    else if (tmp >= '0' && tmp <= '9')
		cur = (tmp - '0') << 4;
	    else
		throw std::invalid_argument("Invalid character in hex string");

	    tmp = str[i+1];
	    if (tmp >= 'a' && tmp <= 'f')
		cur += tmp - 'a' + 10;
	    else if (tmp >= 'A' && tmp <= 'F')
		cur += tmp - 'A' + 10;
	    else if (tmp >= '0' && tmp <= '9')
		cur += tmp - '0';
	    else
		throw std::invalid_argument("Invalid character in hex string");

	    data[i/2] = cur;
	}
	
	return res;
    }
    
    std::string ByteArray::toHex()
    {
	char* tmp = new char[_length*2+1];

	for(int i=0; i<(int)_length; i++)
	    sprintf(&tmp[i*2], "%02x", _data[i]);

	tmp[_length*2] = 0;

	std::string res = tmp;
	delete[] tmp;
	
	return res;
    }

    void ByteArray::append(const unsigned char* data, unsigned int length)
    {
	if (!length)
	    return;
	
	unsigned int oldLength = _length;

	resize(_length+length, true);

	memcpy(&_data[oldLength], data, length);	
    }
    
    void ByteArray::append(unsigned char c) { append(&c, 1);}
    void ByteArray::append(const char* str) { append((const unsigned char*)str, strlen(str));}
    void ByteArray::append(const std::string& str) { append((const unsigned char*)str.c_str(), str.length()); }

    void ByteArray::resize(unsigned length, bool keepData)
    {
	if (length == _length)
	    return;
	else if (length < _length)
	    _length = length ; // Don't touch data
	else // New size >
	{
	    unsigned char* newData;

	    if (_useMalloc)
		newData = (unsigned char*)malloc(_length+length);
	    else
		newData = new unsigned char[_length+length];

	    if (keepData)
		memcpy(newData, _data, _length);
	
	    delRef();

	    _length = length;
	    _data = newData;
	
	    addRef();
	}
    }
}
