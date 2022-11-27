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
#include <termios.h>
#include <cstring>
#include <climits>

#include <iostream>
#include <ostream>

#include <libgourou.h>
#include <libgen.h>
#include "drmprocessorclientimpl.h"
#include "utils_common.h"

static const char* username      = 0;
static const char* password      = 0;
static const char* outputDir     = 0;
static const char* hobbesVersion = HOBBES_DEFAULT_VERSION;
static bool        randomSerial  = false;

// From http://www.cplusplus.com/articles/E6vU7k9E/
static int getch() {
    int ch;
    struct termios t_old, t_new;

    tcgetattr(STDIN_FILENO, &t_old);
    t_new = t_old;
    t_new.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &t_new);

    ch = getchar();

    tcsetattr(STDIN_FILENO, TCSANOW, &t_old);
    return ch;
}

static std::string getpass(const char *prompt, bool show_asterisk=false)
{
  const char BACKSPACE=127;
  const char RETURN=10;

  std::string password;
  unsigned char ch=0;

  std::cout <<prompt;

  while((ch=getch())!= RETURN)
    {
	if(ch==BACKSPACE)
         {
            if(password.length()!=0)
              {
                 if(show_asterisk)
                 std::cout <<"\b \b";
                 password.resize(password.length()-1);
              }
         }
       else
         {
             password+=ch;
             if(show_asterisk)
                 std::cout <<'*';
         }
    }
  std::cout <<std::endl;
  return password;
}


class ADEPTActivate
{
public:  

    int run()
    {
	int ret = 0;
	try
	{
	    DRMProcessorClientImpl client;
	    gourou::DRMProcessor* processor = gourou::DRMProcessor::createDRMProcessor(
		&client, randomSerial, outputDir, hobbesVersion);

	    processor->signIn(username, password);
	    processor->activateDevice();

	    std::cout << username << " fully signed and device activated in " << outputDir << std::endl;
	} catch(std::exception& e)
	{
	    std::cout << e.what() << std::endl;
	    ret = 1;
	}

	return ret;
    }
};	      


static void usage(const char* cmd)
{
    std::cout << "Create new device files used by ADEPT DRM" << std::endl;
    
    std::cout << "Usage: " << basename((char*)cmd) << " (-a|--anonymous) | ( (-u|--username) username [(-p|--password) password] ) [(-O|--output-dir) dir] [(-r|--random-serial)] [(-v|--verbose)] [(-h|--help)]" << std::endl << std::endl;
    
    std::cout << "  " << "-a|--anonymous"  << "\t"   << "Anonymous account, no need for username/password (Use it only with a DRM removal software)" << std::endl;
    std::cout << "  " << "-u|--username"   << "\t\t" << "AdobeID username (ie adobe.com email account)" << std::endl;
    std::cout << "  " << "-p|--password"   << "\t\t" << "AdobeID password (asked if not set via command line) " << std::endl;
    std::cout << "  " << "-O|--output-dir" << "\t"   << "Optional output directory were to put result (default ./.adept). This directory must not already exists" << std::endl;
    std::cout << "  " << "-H|--hobbes-version" << "\t"<< "Force RMSDK version to a specific value (default: version of current librmsdk)" << std::endl;
    std::cout << "  " << "-r|--random-serial" << "\t"<< "Generate a random device serial (if not set, it will be dependent of your current configuration)" << std::endl;
    std::cout << "  " << "-v|--verbose"    << "\t\t" << "Increase verbosity, can be set multiple times" << std::endl;
    std::cout << "  " << "-V|--version"    << "\t\t" << "Display libgourou version" << std::endl;
    std::cout << "  " << "-h|--help"       << "\t\t" << "This help" << std::endl;

    std::cout << std::endl;
}

static const char* abspath(const char* filename)
{
    const char* root = getcwd(0, PATH_MAX);
    std::string fullPath = std::string(root) + std::string("/") + filename;
    const char* res = strdup(fullPath.c_str());

    free((void*)root);

    return res;
}

int main(int argc, char** argv)
{
    int c, ret = -1;
    const char* _outputDir = outputDir;
    int verbose = gourou::DRMProcessor::getLogLevel();
    bool anonymous = false;
    
    while (1) {
	int option_index = 0;
	static struct option long_options[] = {
	    {"anonymous",     no_argument      , 0,  'a' },
	    {"username",      required_argument, 0,  'u' },
	    {"password",      required_argument, 0,  'p' },
	    {"output-dir",    required_argument, 0,  'O' },
	    {"hobbes-version",required_argument, 0,  'H' },
	    {"random-serial", no_argument,       0,  'r' },
	    {"verbose",       no_argument,       0,  'v' },
	    {"version",       no_argument,       0,  'V' },
	    {"help",          no_argument,       0,  'h' },
	    {0,               0,                 0,  0 }
	};

	c = getopt_long(argc, argv, "au:p:O:H:rvVh",
                        long_options, &option_index);
	if (c == -1)
	    break;

	switch (c) {
	case 'a':
	    anonymous = true;
	    break;
	case 'u':
	    username = optarg;
	    break;
	case 'p':
	    password = optarg;
	    break;
	case 'O':
	    _outputDir = optarg;
	    break;
	case 'H':
	    hobbesVersion = optarg;
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
	case 'r':
	    randomSerial = true;
	    break;
	default:
	    usage(argv[0]);
	    return -1;
	}
    }
   
    gourou::DRMProcessor::setLogLevel(verbose);

    if ((!username && !anonymous) ||
	(username && anonymous))
    {
	usage(argv[0]);
	return -1;
    }

    if (anonymous)
    {
	username = "anonymous";
	password = "";
    }
    
    if (!_outputDir || _outputDir[0] == 0)
    {
	outputDir = strdup(abspath(DEFAULT_ADEPT_DIR));
    }
    else
    {
	// Relative path
	if (_outputDir[0] == '.' || _outputDir[0] != '/')
	{
	    // realpath doesn't works if file/dir doesn't exists
	    if (fileExists(_outputDir))
		outputDir = strdup(realpath(_outputDir, 0));
	    else
		outputDir = strdup(abspath(_outputDir));
	}
	else
	    outputDir = strdup(_outputDir);
    }

    std::string pass;
    if (fileExists(outputDir))
    {
	int key;
	
	while (true)
	{
	    std::cout << "!! Warning !! : " << outputDir << " already exists." << std::endl;
	    std::cout << "All your data will be overwrite. Would you like to continue ? [y/N] " << std::flush ;
	    key = getchar();
	    if (key == 'n' || key == 'N' || key == '\n' || key == '\r')
		goto end;
	    if (key == 'y' || key == 'Y')
		break;
	}

	// Clean STDIN buf
	while ((key = getchar()) != '\n')
	    ;
    }

    if (!password)
    {
	char prompt[128];
	std::snprintf(prompt, sizeof(prompt), "Enter password for <%s> : ", username);
	pass = getpass((const char*)prompt, false);
	password = pass.c_str();
    }
        
    ADEPTActivate activate;

    ret = activate.run();

end:    
    free((void*)outputDir);
    return ret;
}
