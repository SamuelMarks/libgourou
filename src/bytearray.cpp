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
#include <string.h>

#include <base64/Base64.h>

#include <bytearray.h>

namespace gourou
{
    std::map<const unsigned char*, int> ByteArray::refCounter;
    
    ByteArray::ByteArray():_data(0), _length(0)
    {}

    ByteArray::ByteArray(const unsigned char* data, unsigned int length)
    {
	initData(data, length);
    }
    
    ByteArray::ByteArray(const char* data, int length)
    {
	if (length == -1)
	    length = strlen(data) + 1;

	initData((const unsigned char*)data, (unsigned int) length);
    }
    
    ByteArray::ByteArray(const std::string& str)
    {
	initData((unsigned char*)str.c_str(), (unsigned int)str.length() + 1);
    }

    void ByteArray::initData(const unsigned char* data, unsigned int length)
    {
	_data = new unsigned char[length];
	memcpy((void*)_data, data, length);
	_length = length;

	addRef();
    }
    
    ByteArray::ByteArray(const ByteArray& other)
    {
	this->_data = other._data;
	this->_length = other._length;

	addRef();
    }

    ByteArray& ByteArray::operator=(const ByteArray& other)
    {
	delRef();
	
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
	const unsigned char* oldData = _data;
	unsigned char* newData = new unsigned char[_length+length];

	memcpy(newData, oldData, _length);
	
	delRef();

	memcpy(&newData[_length], data, length);
	_length += length;
	
	_data = newData;
	
	addRef();
    }
    
    void ByteArray::append(unsigned char c) { append(&c, 1);}
    void ByteArray::append(const char* str) { append((const unsigned char*)str, strlen(str));}
    void ByteArray::append(const std::string& str) { append((const unsigned char*)str.c_str(), str.length()); }
}
