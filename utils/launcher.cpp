#include <iostream>
#include <unistd.h>
#include <libgen.h>
#include <cstring>

#include "utils_common.h"

#ifndef DEFAULT_UTIL
#define DEFAULT_UTIL "acsmdownloader"
#endif

/* Inspired from https://discourse.appimage.org/t/call-alternative-binary-from-appimage/93/10*/

int main(int argc, char** argv)
{
    char* util, *argv0;
    char* mountPoint = getenv("APPDIR");
    std::string fullPath;

    /* Original command is in ARGV0 env variable*/
    argv0 = strdup(getenv("ARGV0"));
    util = basename(argv0);

    fullPath = std::string(mountPoint) + util;

    if (std::string(util) == "launcher" || !fileExists(fullPath.c_str()))
	fullPath = std::string(mountPoint) + DEFAULT_UTIL;

    free(argv0);
    
    argv[0] = strdup(fullPath.c_str());

    if (execvp(argv[0], argv))
	std::cout << "Unable to launch '" << argv[0] << "'" << std::endl;

    /* Should not happens */
    free(argv[0]);
    
    return 0;
}
