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

#ifndef _DEVICE_H_
#define _DEVICE_H_

namespace gourou
{
    class DRMProcessor;

    /**
     * @brief This class is a container for device.xml (device info) and devicesalt (device private key). It should not be used by user.
     */
    class Device
    {
    public:
	static const int DEVICE_KEY_SIZE   = 16;
	static const int DEVICE_SERIAL_LEN = 10;

	/**
	 * @brief Main Device constructor
	 *
	 * @param processor      Instance of DRMProcessor
	 * @param deviceFile     Path of device.xml
	 * @param deviceKeyFile  Path of devicesalt
	 */
	Device(DRMProcessor* processor, const std::string& deviceFile, const std::string& deviceKeyFile);

	/**
	 * @brief Return value of devicesalt file (DEVICE_KEY_SIZE len)
	 */
	const unsigned char* getDeviceKey();

	/**
	 * @brief Get one value of device.xml (deviceClass, deviceSerial, deviceName, deviceType, jobbes, clientOS, clientLocale)
	 */
	std::string getProperty(const std::string& property, const std::string& _default=std::string(""));
	std::string operator[](const std::string& property);

	/**
	 * @brief Create device.xml and devicesalt files when they did not exists
	 *
	 * @param processor      Instance of DRMProcessor
	 * @param dirName        Directory where to put files (.adept)
	 * @param hobbes         Hobbes (client version) to set
	 * @param randomSerial   Create a random serial (new device each time) or not (serial computed from machine specs)
	 */
	static Device* createDevice(DRMProcessor* processor, const std::string& dirName, const std::string& hobbes, bool randomSerial);
	
    private:
	DRMProcessor* processor;
        std::string deviceFile;
        std::string deviceKeyFile;
	unsigned char deviceKey[DEVICE_KEY_SIZE];
	std::map<std::string, std::string> properties;

	Device(DRMProcessor* processor);
	
	std::string makeFingerprint(const std::string& serial);
	std::string makeSerial(bool random);
	void parseDeviceFile();
	void parseDeviceKeyFile();
	void createDeviceFile(const std::string& hobbes, bool randomSerial);
	void createDeviceKeyFile();
    };
}

#endif
