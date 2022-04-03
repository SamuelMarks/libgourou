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

#ifndef _UTILS_COMMON_H_
#define _UTILS_COMMON_H_

#define LOANS_DIR            "loans/"
#define ID_HASH_SIZE         16

#define ARRAY_SIZE(arr) (sizeof(arr)/sizeof(arr[0]))

/**
 * @brief Display libgourou version
 */
void version(void);

/**
 * @brief Find a given filename in current directory and/or in default directories
 *
 * @param filename        Filename to search
 * @param inDefaultDirs   Search is default directories or not
 *
 * @return A copy of full path
 */
const char* findFile(const char* filename, bool inDefaultDirs=true);

/**
 * @brief Does the file (or directory exists)
 */
bool fileExists(const char* filename);

/**
 * @brief Recursively created dir
 */
void mkpath(const char *dir);

/**
 * @brief Copy file in into file out
 */
void fileCopy(const char* in, const char* out);

#endif
