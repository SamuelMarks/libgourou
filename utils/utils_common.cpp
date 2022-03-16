/*
  Copyright (c) 2022, Grégory Soutadé

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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <limits.h>

#include <iostream>

#include <libgourou.h>
#include <libgourou_common.h>
#include "utils_common.h"

static const char* defaultDirs[]  = {
    ".adept/",
    "./adobe-digital-editions/",
    "./.adobe-digital-editions/"
};

void version(void)
{
    std::cout << "Current libgourou version : " << gourou::DRMProcessor::VERSION << std::endl ;
}

bool fileExists(const char* filename)
{
    struct stat _stat;
    int ret = stat(filename, &_stat);

    return (ret == 0);
}

const char* findFile(const char* filename, bool inDefaultDirs)
{
    if (fileExists(filename))
	return strdup(filename);

    if (!inDefaultDirs) return 0;
    
    for (int i=0; i<(int)ARRAY_SIZE(defaultDirs); i++)
    {
	std::string path = std::string(defaultDirs[i]) + filename;
	if (fileExists(path.c_str()))
	    return strdup(path.c_str());
    }
    
    return 0;
}

// https://stackoverflow.com/questions/2336242/recursive-mkdir-system-call-on-unix
void mkpath(const char *dir)
{
    char tmp[PATH_MAX];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp),"%s",dir);
    len = strlen(tmp);
    if (tmp[len - 1] == '/')
        tmp[len - 1] = 0;
    for (p = tmp + 1; *p; p++)
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, S_IRWXU);
            *p = '/';
        }
    mkdir(tmp, S_IRWXU);
}

void fileCopy(const char* in, const char* out)
{
    char buffer[4096];
    int ret, fdIn, fdOut;

    fdIn = open(in, O_RDONLY);

    if (!fdIn)
	EXCEPTION(gourou::CLIENT_FILE_ERROR, "Unable to open " << in);
    
    fdOut = open(out, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH);
    
    if (!fdOut)
    {
	close (fdIn);
	EXCEPTION(gourou::CLIENT_FILE_ERROR, "Unable to open " << out);
    }

    while (true)
    {
	ret = ::read(fdIn, buffer, sizeof(buffer));
	if (ret <= 0)
	    break;
	::write(fdOut, buffer, ret);
    }

    close (fdIn);
    close (fdOut);
}
