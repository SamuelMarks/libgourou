#include <iostream>
#include <unistd.h>
#include <libgen.h>
#include <cstdlib>
#include <cstring>

#include "utils_common.h"

#ifndef DEFAULT_UTIL
#define DEFAULT_UTIL "acsmdownloader"
#endif

/* Inspired from https://discourse.appimage.org/t/call-alternative-binary-from-appimage/93/10*/

int main(int argc, char** argv)
{
    char* util, *argv0=getenv("ARGV0");
    char* mountPoint = getenv("APPDIR");
    std::string fullPath;

    /* Original command is in ARGV0 env variable*/
    if (argv0 == NULL)
        argv0 = argv[0];
    util = basename(argv0);

    fullPath = std::string(mountPoint) + util;

    if (std::string(util) == "launcher" || !fileExists(fullPath.c_str()))
	  fullPath = std::string(mountPoint) + DEFAULT_UTIL;

    if (execvp(fullPath.c_str(), argv))
	  std::cout << "Unable to launch '" << fullPath << "'" << std::endl;
    
    return EXIT_SUCCESS;
}
