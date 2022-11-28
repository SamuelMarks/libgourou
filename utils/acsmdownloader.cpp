/*
  Copyright (c) 2021, Grégory Soutadé

  All rights reserved.
  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:
  
  * Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
  * Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
  * Neither the name of the copyright holder nor the
    names of its contributors may be used to endorse or promote products
    derived from this software without specific prior written permission.
  
  THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY
  EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE REGENTS AND CONTRIBUTORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <getopt.h>
#include <libgen.h>

#include <iostream>
#include <algorithm>

#include <libgourou.h>
#include <libgourou_common.h>

#include "drmprocessorclientimpl.h"
#include "utils_common.h"

static const char* deviceFile     = "device.xml";
static const char* activationFile = "activation.xml";
static const char* devicekeyFile  = "devicesalt";
static const char* acsmFile       = 0;
static       bool  exportPrivateKey = false;
static const char* outputFile     = 0;
static const char* outputDir      = 0;
static       bool  resume         = false;


class ACSMDownloader
{
public:
    
    int run()
    {
	int ret = 0;
	try
	{
	    gourou::DRMProcessor processor(&client, deviceFile, activationFile, devicekeyFile);
	    gourou::User* user = processor.getUser();
	    
	    if (exportPrivateKey)
	    {
		std::string filename;
            if (outputFile != nullptr)
                filename = outputFile;
            else
                filename = std::string("Adobe_PrivateLicenseKey--") + user->getUsername() + ".der";

            if (outputDir)
            {
                if (!fileExists(outputDir))
                    mkpath(outputDir);

                filename = std::string(outputDir) + "/" + filename;
            }

            processor.exportPrivateLicenseKey(filename);

            std::cout << "Private license key exported to " << filename << std::endl;
        }
	    else
	    {
		gourou::FulfillmentItem* item = processor.fulfill(acsmFile);

		std::string filename;
		if (!outputFile)
		{
		    filename = item->getMetadata("title");
		    if (filename == "")
			filename = "output";
		    else
		    {
			// Remove invalid characters
			std::replace(filename.begin(), filename.end(), '/', '_');
		    }
		}
		else
		    filename = outputFile;
	    
		if (outputDir)
		{
		    if (!fileExists(outputDir))
			mkpath(outputDir);

		    filename = std::string(outputDir) + "/" + filename;
		}
	    
		gourou::DRMProcessor::ITEM_TYPE type = processor.download(item, filename, resume);

		if (!outputFile)
		{
		    std::string finalName = filename;
		    if (type == gourou::DRMProcessor::ITEM_TYPE::PDF)
			finalName += ".pdf";
		    else
			finalName += ".epub";
		    rename(filename.c_str(), finalName.c_str());
		    filename = finalName;
		}
		std::cout << "Created " << filename << std::endl;

		serializeLoanToken(item);
	    }
	} catch(std::exception& e)
	{
	    std::cout << e.what() << std::endl;
	    ret = 1;
	}

	return ret;
    }

    void serializeLoanToken(gourou::FulfillmentItem* item)
    {
	gourou::LoanToken* token = item->getLoanToken();

	// No loan token available
	if (!token)
	    return;

	pugi::xml_document doc;

	pugi::xml_node decl = doc.append_child(pugi::node_declaration);
	decl.append_attribute("version") = "1.0";

	pugi::xml_node root = doc.append_child("loanToken");
	gourou::appendTextElem(root, "id",          (*token)["id"]);
	gourou::appendTextElem(root, "operatorURL", (*token)["operatorURL"]);
	gourou::appendTextElem(root, "validity",    (*token)["validity"]);
	gourou::appendTextElem(root, "name",        item->getMetadata("title"));

	char * activationDir = strdup(deviceFile);
	activationDir = dirname(activationDir);
		
	gourou::StringXMLWriter xmlWriter;
	doc.save(xmlWriter, "  ");
	std::string xmlStr = xmlWriter.getResult();

	// Use first bytes of SHA1(id) as filename
	unsigned char sha1[gourou::SHA1_LEN];
	client.digest("SHA1", (unsigned char*)(*token)["id"].c_str(), (*token)["id"].size(), sha1);
	gourou::ByteArray tmp(sha1, sizeof(sha1));
	std::string filenameHex = tmp.toHex();
	std::string filename(filenameHex.c_str(), ID_HASH_SIZE);
	std::string fullPath = std::string(activationDir);
	fullPath += std::string ("/") + std::string(LOANS_DIR);
	mkpath(fullPath.c_str());
	fullPath += filename + std::string(".xml");
	gourou::writeFile(fullPath, xmlStr);

	std::cout << "Loan token serialized into " << fullPath << std::endl;

	free(activationDir);
    }
    
private:
    DRMProcessorClientImpl client;
};	      


static void usage(const char* cmd)
{
    std::cout << "Download EPUB file from ACSM request file\n"
    
              << "Usage: " << basename((char*)cmd) << " [(-d|--device-file) device.xml] [(-a|--activation-file) activation.xml] [(-k|--device-key-file) devicesalt] [(-O|--output-dir) dir] [(-o|--output-file) output(.epub|.pdf|.der)] [(-r|--resume)] [(-v|--verbose)] [(-h|--help)] (-f|--acsm-file) file.acsm|(-e|--export-private-key)\n\n"

              << "  " << "-d|--device-file"     << "\t"   << "device.xml file from eReader\n"
              << "  " << "-a|--activation-file" << "\t"   << "activation.xml file from eReader\n"
              << "  " << "-k|--device-key-file" << "\t"   << "private device key file (eg devicesalt/devkey.bin) from eReader\n"
              << "  " << "-O|--output-dir"      << "\t"   << "Optional output directory were to put result (default ./)\n"
              << "  " << "-o|--output-file"     << "\t"   << "Optional output filename (default <title.(epub|pdf|der)>)\n"
              << "  " << "-f|--acsm-file"       << "\t"   << "ACSM request file for epub download\n"
              << "  " << "-e|--export-private-key"<< "\t" << "Export private key in DER format\n"
              << "  " << "-r|--resume"          << "\t\t" << "Try to resume download (in case of previous failure)\n"
              << "  " << "-v|--verbose"         << "\t\t" << "Increase verbosity, can be set multiple times\n"
              << "  " << "-V|--version"         << "\t\t" << "Display libgourou version\n"
              << "  " << "-h|--help"            << "\t\t" << "This help\n"

              << '\n'
              << "Device file, activation file and device key file are optionals. If not set, they are looked into :\n"
              << "  * Current directory\n"
              << "  * .adept\n"
              << "  * adobe-digital-editions directory\n"
              << "  * .adobe-digital-editions directory" << std::endl;
}

int main(int argc, char** argv)
{
    int c, ret = -1;

    const char** files[] = {&devicekeyFile, &deviceFile, &activationFile};
    int verbose = gourou::DRMProcessor::getLogLevel();

    while (true) {
	int option_index = 0;
	static struct option long_options[] = {
	    {"device-file",      required_argument, 0,  'd' },
	    {"activation-file",  required_argument, 0,  'a' },
	    {"device-key-file",  required_argument, 0,  'k' },
	    {"output-dir",       required_argument, 0,  'O' },
	    {"output-file",      required_argument, 0,  'o' },
	    {"acsm-file",        required_argument, 0,  'f' },
	    {"export-private-key",no_argument,      0,  'e' },
	    {"resume",           no_argument,       0,  'r' },
	    {"verbose",          no_argument,       0,  'v' },
	    {"version",          no_argument,       0,  'V' },
	    {"help",             no_argument,       0,  'h' },
	    {0,                  0,                 0,  0 }
	};

	c = getopt_long(argc, argv, "d:a:k:O:o:f:ervVh",
                        long_options, &option_index);
	if (c == -1)
	    break;

	switch (c) {
	case 'd':
	    deviceFile = optarg;
	    break;
	case 'a':
	    activationFile = optarg;
	    break;
	case 'k':
	    devicekeyFile = optarg;
	    break;
	case 'f':
	    acsmFile = optarg;
	    break;
	case 'O':
	    outputDir = optarg;
	    break;
	case 'o':
	    outputFile = optarg;
	    break;
	case 'e':
	    exportPrivateKey = true;
	    break;
	case 'r':
	    resume = true;
	    break;
	case 'v':
	    verbose++;
	    break;
	case 'V':
	    version();
	    return 0;
	case 'h':
	    usage(argv[0]);
	    return 0;
	default:
	    usage(argv[0]);
	    return -1;
	}
    }
   
    gourou::DRMProcessor::setLogLevel(verbose);

    if ((!acsmFile && !exportPrivateKey) || (outputDir && !outputDir[0]) ||
	(outputFile && !outputFile[0]))
    {
	usage(argv[0]);
	return -1;
    }

    ACSMDownloader downloader;

    int i;
    bool hasErrors = false;
    const char* orig;
    for (i=0; i<(int)ARRAY_SIZE(files); i++)
    {
	orig = *files[i];
	*files[i] = findFile(*files[i]);
	if (!*files[i])
	{
	    std::cout << "Error : " << orig << " doesn't exists, did you activate your device ?" << std::endl;
	    ret = -1;
	    hasErrors = true;
	}
    }

    if (hasErrors)
	goto end;
    
    if (exportPrivateKey)
    {
	if (acsmFile)
	{
	    usage(argv[0]);
	    return -1;
	}
    }
    else
    {
	if (!fileExists(acsmFile))
	{
	    std::cout << "Error : " << acsmFile << " doesn't exists" << std::endl;
	    ret = -1;
	    goto end;
	}
    }
    
    ret = downloader.run();

end:
    for (i=0; i<(int)ARRAY_SIZE(files); i++)
    {
	if (*files[i])
	    free((void*)*files[i]);
    }

    return ret;
}
