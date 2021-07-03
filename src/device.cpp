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

#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <pwd.h>
#include <locale.h>

#include <libgourou.h>
#include <libgourou_common.h>
#include <libgourou_log.h>
#include <device.h>

// From https://stackoverflow.com/questions/1779715/how-to-get-mac-address-of-your-machine-using-a-c-program/35242525
#include <sys/ioctl.h>
#include <net/if.h> 
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>

int get_mac_address(unsigned char* mac_address)
{
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) { EXCEPTION(gourou::DEV_MAC_ERROR, "Unable to create socket"); };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { EXCEPTION(gourou::DEV_MAC_ERROR, "SIOCGIFCONF ioctl failed"); }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else { EXCEPTION(gourou::DEV_MAC_ERROR, "SIOCGIFFLAGS ioctl failed"); }
    }

    if (success)
    {
	memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);
	return 0;
    }

    return 1;
}


namespace gourou
{
    Device::Device(DRMProcessor* processor):
	processor(processor)
    {}
    
    Device::Device(DRMProcessor* processor, const std::string& deviceFile, const std::string& deviceKeyFile):
	processor(processor), deviceFile(deviceFile), deviceKeyFile(deviceKeyFile)
    {
	parseDeviceKeyFile();
	parseDeviceFile();
    }

    /* SHA1(uid ":" username ":" macaddress ":" */
    std::string Device::makeSerial(bool random)
    {
	unsigned char sha_out[SHA1_LEN];
	DRMProcessorClient* client = processor->getClient();
	
	if (!random)
	{
	    uid_t uid = getuid();
	    struct passwd * passwd = getpwuid(uid);
	    // Default mac address in case of failure
	    unsigned char mac_address[6] = {0x01, 0x02, 0x03, 0x04, 0x05};

	    get_mac_address(mac_address);

	    int dataToHashLen = 10 /* UID */ + strlen(passwd->pw_name) + sizeof(mac_address)*2 /*mac address*/ + 1 /* \0 */;
	    dataToHashLen += 8; /* Separators */
	    unsigned char* dataToHash = new unsigned char[dataToHashLen];
	    dataToHashLen = snprintf((char*)dataToHash, dataToHashLen, "%d:%s:%02x:%02x:%02x:%02x:%02x:%02x:",
				     uid, passwd->pw_name,
				     mac_address[0], mac_address[1], mac_address[2],
				     mac_address[3], mac_address[4], mac_address[5]);
	
	    client->digest("SHA1", dataToHash, dataToHashLen+1, sha_out);

	    delete[] dataToHash;
	}
	else
	{
	    client->randBytes(sha_out, sizeof(sha_out));
	}

	std::string res = ByteArray((const char*)sha_out, DEVICE_SERIAL_LEN).toHex();
	GOUROU_LOG(DEBUG, "Serial : " << res);
	return res;
    }

    /* base64(SHA1 (serial + privateKey)) */
    std::string Device::makeFingerprint(const std::string& serial)
    {
	DRMProcessorClient* client = processor->getClient();
	unsigned char sha_out[SHA1_LEN];

	void* handler = client->createDigest("SHA1");
	client->digestUpdate(handler, (unsigned char*) serial.c_str(), serial.length());
	client->digestUpdate(handler, deviceKey, sizeof(deviceKey));
	client->digestFinalize(handler, sha_out);

	std::string res = ByteArray(sha_out, sizeof(sha_out)).toBase64();
	GOUROU_LOG(DEBUG, "Fingerprint : " << res);
	return res;
    }
    
    void Device::createDeviceFile(const std::string& hobbes, bool randomSerial)
    {
	struct utsname sysname;
	uname(&sysname);

	std::string serial = makeSerial(randomSerial);
	std::string fingerprint = makeFingerprint(serial);
	
	pugi::xml_document deviceDoc;
	pugi::xml_node decl = deviceDoc.append_child(pugi::node_declaration);
	decl.append_attribute("version") = "1.0";
	
	pugi::xml_node root = deviceDoc.append_child("adept:deviceInfo");
	root.append_attribute("xmlns:adept") = ADOBE_ADEPT_NS;

	appendTextElem(root, "adept:deviceClass",  "Desktop");
	appendTextElem(root, "adept:deviceSerial", serial);
	appendTextElem(root, "adept:deviceName",   sysname.nodename);
	appendTextElem(root, "adept:deviceType",   "standalone");

	pugi::xml_node version = root.append_child("adept:version");
	version.append_attribute("name") = "hobbes";
	version.append_attribute("value") = hobbes.c_str();
	
	version = root.append_child("adept:version");
	version.append_attribute("name") = "clientOS";
	std::string os = std::string(sysname.sysname) + " " + std::string(sysname.release);
	version.append_attribute("value") = os.c_str();
	
	version = root.append_child("adept:version");
	version.append_attribute("name") = "clientLocale";
	version.append_attribute("value") = setlocale(LC_ALL, NULL);

	appendTextElem(root, "adept:fingerprint", fingerprint);

	StringXMLWriter xmlWriter;
	deviceDoc.save(xmlWriter, "  ");

	GOUROU_LOG(DEBUG, "Create device file " << deviceFile);

	writeFile(deviceFile, xmlWriter.getResult());
    }

    void Device::createDeviceKeyFile()
    {
	unsigned char key[DEVICE_KEY_SIZE];

	GOUROU_LOG(DEBUG, "Create device key file " << deviceKeyFile);

	processor->getClient()->randBytes(key, sizeof(key));

	writeFile(deviceKeyFile, key, sizeof(key));
    }
    
    Device* Device::createDevice(DRMProcessor* processor, const std::string& dirName, const std::string& hobbes, bool randomSerial)
    {
	struct stat _stat;

	if (stat(dirName.c_str(), &_stat) != 0)
	{
	    if (mkdir_p(dirName.c_str(), S_IRWXU))
		EXCEPTION(DEV_MKPATH, "Unable to create " << dirName)
	}

	Device* device = new Device(processor);

	device->deviceFile = dirName + "/device.xml";
	device->deviceKeyFile = dirName + "/devicesalt";

	try
	{
	    device->parseDeviceKeyFile();
	}
	catch (...)
	{
	    device->createDeviceKeyFile();
	    device->parseDeviceKeyFile();
	}

	try
	{
	    device->parseDeviceFile();
	}
	catch (...)
	{
	    device->createDeviceFile(hobbes, randomSerial);
	    device->parseDeviceFile();
	}
	
	return device;
    }
    
    const unsigned char* Device::getDeviceKey()
    {
	return deviceKey;
    }

    void Device::parseDeviceFile()
    {
	pugi::xml_document doc;

	if (!doc.load_file(deviceFile.c_str()))
	    EXCEPTION(DEV_INVALID_DEVICE_FILE, "Invalid device file");

	try
	{
	    properties["deviceClass"]  = gourou::extractTextElem(doc, "/adept:deviceInfo/adept:deviceClass");
	    properties["deviceSerial"] = gourou::extractTextElem(doc, "/adept:deviceInfo/adept:deviceSerial");
	    properties["deviceName"]   = gourou::extractTextElem(doc, "/adept:deviceInfo/adept:deviceName");
	    properties["deviceType"]   = gourou::extractTextElem(doc, "/adept:deviceInfo/adept:deviceType");   
	    properties["fingerprint"]  = gourou::extractTextElem(doc, "/adept:deviceInfo/adept:fingerprint");

	    pugi::xpath_node_set nodeSet = doc.select_nodes("/adept:deviceInfo/adept:version");

	    for (pugi::xpath_node_set::const_iterator it = nodeSet.begin();
		 it != nodeSet.end(); ++it)
	    {
		pugi::xml_node node = it->node();
		pugi::xml_attribute name = node.attribute("name");
		pugi::xml_attribute value = node.attribute("value");

		properties[name.value()] = value.value();
	    }
	}
	catch (gourou::Exception& e)
	{
	    EXCEPTION(DEV_INVALID_DEVICE_FILE, "Invalid device file");
	}
    }

    void Device::parseDeviceKeyFile()
    {
	struct stat _stat;

	if (stat(deviceKeyFile.c_str(), &_stat) == 0 &&
	    _stat.st_size == DEVICE_KEY_SIZE)
	{
	    readFile(deviceKeyFile, deviceKey, sizeof(deviceKey));
	}
	else
	    EXCEPTION(DEV_INVALID_DEVICE_KEY_FILE, "Invalid device key file");
    }

    std::string Device::getProperty(const std::string& property, const std::string& _default)
    {
	if (properties.find(property) == properties.end())
	{
	    if (_default == "")
		EXCEPTION(DEV_INVALID_DEV_PROPERTY, "Invalid property " << property);

	    return _default;
	}

	return properties[property];
    }

    std::string Device::operator[](const std::string& property)
    {
	return getProperty(property);
    }
}
