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

#include <unistd.h>
#include <getopt.h>

#include <iostream>

#include <QFile>
#include <QDir>
#include <QCoreApplication>
#include <QRunnable>
#include <QThreadPool>

#include <libgourou.h>
#include "drmprocessorclientimpl.h"

#define ARRAY_SIZE(arr) (sizeof(arr)/sizeof(arr[0]))

static const char* deviceFile     = "device.xml";
static const char* activationFile = "activation.xml";
static const char* devicekeyFile  = "devicesalt";
static const char* acsmFile       = 0;
static const char* outputFile     = 0;
static const char* outputDir      = 0;
static const char* defaultDirs[]  = {
    ".adept/",
    "./adobe-digital-editions/",
    "./.adobe-digital-editions/"
};


class ACSMDownloader: public QRunnable
{
public:
    ACSMDownloader(QCoreApplication* app):
	app(app)
    {
	setAutoDelete(false);
    }
   
    void run()
    {
	int ret = 0;
	try
	{
	    DRMProcessorClientImpl client;
	    gourou::DRMProcessor processor(&client, deviceFile, activationFile, devicekeyFile);

	    gourou::FulfillmentItem* item = processor.fulfill(acsmFile);

	    std::string filename;
	    if (!outputFile)
	    {
		filename = item->getMetadata("title");
		if (filename == "")
		    filename = "output.epub";
		else
		    filename += ".epub";
	    }
	    else
		filename = outputFile;
	    
	    if (outputDir)
	    {
		QDir dir(outputDir);
		if (!dir.exists(outputDir))
		    dir.mkpath(outputDir);

		filename = std::string(outputDir) + "/" + filename;
	    }
	    
	    processor.download(item, filename);
	    std::cout << "Created " << filename << std::endl;
	} catch(std::exception& e)
	{
	    std::cout << e.what() << std::endl;
	    ret = 1;
	}

	this->app->exit(ret);
    }

private:
    QCoreApplication* app;
};	      

static const char* findFile(const char* filename, bool inDefaultDirs=true)
{
    QFile file(filename);

    if (file.exists())
	return strdup(filename);

    if (!inDefaultDirs) return 0;
    
    for (int i=0; i<(int)ARRAY_SIZE(defaultDirs); i++)
    {
	QString path = QString(defaultDirs[i]) + QString(filename);
	file.setFileName(path);
	if (file.exists())
	    return strdup(path.toStdString().c_str());
    }
    
    return 0;
}

static void version(void)
{
    std::cout << "Current libgourou version : " << gourou::DRMProcessor::VERSION << std::endl ;
}

static void usage(const char* cmd)
{
    std::cout << "Download EPUB file from ACSM request file" << std::endl;
    
    std::cout << "Usage: " << cmd << " [(-d|--device-file) device.xml] [(-a|--activation-file) activation.xml] [(-s|--device-key-file) devicesalt] [(-O|--output-dir) dir] [(-o|--output-file) output.epub] [(-v|--verbose)] [(-h|--help)] (-f|--acsm-file) file.acsm" << std::endl << std::endl;
    
    std::cout << "  " << "-d|--device-file"     << "\t"   << "device.xml file from eReader" << std::endl;
    std::cout << "  " << "-a|--activation-file" << "\t"   << "activation.xml file from eReader" << std::endl;
    std::cout << "  " << "-k|--device-key-file" << "\t"   << "private device key file (eg devicesalt/devkey.bin) from eReader" << std::endl;
    std::cout << "  " << "-O|--output-dir"      << "\t"   << "Optional output directory were to put result (default ./)" << std::endl;
    std::cout << "  " << "-o|--output-file"     << "\t"   << "Optional output epub filename (default <title.epub>)" << std::endl;
    std::cout << "  " << "-f|--acsm-file"       << "\t"   << "ACSM request file for epub download" << std::endl;
    std::cout << "  " << "-v|--verbose"         << "\t\t" << "Increase verbosity, can be set multiple times" << std::endl;
    std::cout << "  " << "-V|--version"         << "\t\t" << "Display libgourou version" << std::endl;
    std::cout << "  " << "-h|--help"            << "\t\t" << "This help" << std::endl;

    std::cout << std::endl;
    std::cout << "Device file, activation file and device key file are optionals. If not set, they are looked into :" << std::endl;
    std::cout << "  * Current directory" << std::endl;
    std::cout << "  * .adept" << std::endl;
    std::cout << "  * adobe-digital-editions directory" << std::endl;
    std::cout << "  * .adobe-digital-editions directory" << std::endl;
}

int main(int argc, char** argv)
{
    int c, ret = -1;

    const char** files[] = {&devicekeyFile, &deviceFile, &activationFile};
    int verbose = gourou::DRMProcessor::getLogLevel();

    while (1) {
	int option_index = 0;
	static struct option long_options[] = {
	    {"device-file",      required_argument, 0,  'd' },
	    {"activation-file",  required_argument, 0,  'a' },
	    {"device-key-file",  required_argument, 0,  'k' },
	    {"output-dir",       required_argument, 0,  'O' },
	    {"output-file",      required_argument, 0,  'o' },
	    {"acsm-file",        required_argument, 0,  'f' },
	    {"verbose",          no_argument,       0,  'v' },
	    {"version",          no_argument,       0,  'V' },
	    {"help",             no_argument,       0,  'h' },
	    {0,                  0,                 0,  0 }
	};

	c = getopt_long(argc, argv, "d:a:k:O:o:f:vVh",
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

    if (!acsmFile || (outputDir && !outputDir[0]) ||
	(outputFile && !outputFile[0]))
    {
	usage(argv[0]);
	return -1;
    }

    QCoreApplication app(argc, argv);
    ACSMDownloader downloader(&app);

    int i;
    for (i=0; i<(int)ARRAY_SIZE(files); i++)
    {
	*files[i] = findFile(*files[i]);
	if (!*files[i])
	{
	    std::cout << "Error : " << *files[i] << " doesn't exists" << std::endl;
	    ret = -1;
	    goto end;
	}
    }
    
    QFile file(acsmFile);
    if (!file.exists())
    {
	std::cout << "Error : " << acsmFile << " doesn't exists" << std::endl;
	ret = -1;
	goto end;
    }
    
    QThreadPool::globalInstance()->start(&downloader);

    ret = app.exec();

end:
    for (i=0; i<(int)ARRAY_SIZE(files); i++)
    {
	if (*files[i])
	    free((void*)*files[i]);
    }

    return ret;
}
