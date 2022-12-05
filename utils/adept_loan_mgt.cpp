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

#include <getopt.h>

#include <iostream>
#include <algorithm>
#include <map>

#define _XOPEN_SOURCE 700
#include <cstdio>
#include <sys/types.h>
#include <dirent.h>
#include <libgen.h>
#include <ctime>

#include <libgourou.h>
#include <libgourou_common.h>
#include "drmprocessorclientimpl.h"
#include "utils_common.h"

#define MAX_SIZE_BOOK_NAME   30

static       char* activationDir  = nullptr;
static const char* deviceFile     = "device.xml";
static const char* activationFile = "activation.xml";
static const char* devicekeyFile  = "devicesalt";
static       bool  list           = false;
static const char* returnID       = nullptr;
static const char* deleteID       = nullptr;

struct Loan
{
    std::string id;
    std::string operatorURL;
    std::string validity;
    std::string bookName;
    
    std::string path;
};
    
class LoanMGT
{
public:
    ~LoanMGT()
    {
	for (const auto& kv : loanedBooks)
	    delete kv.second;
    }
    
    int run()
    {
	int ret = 0;
	try
	{
	    DRMProcessorClientImpl client;
	    gourou::DRMProcessor processor(&client, deviceFile, activationFile, devicekeyFile);

	    loadLoanedBooks();

	    if (list)
		displayLoanList();
	    else if (returnID)
		returnBook(processor);
	    else if (deleteID)
		deleteLoan();
	} catch(std::exception& e)
	{
	    std::cout << e.what() << std::endl;
	    ret = 1;
	}

	return ret;
    }

private:
    void loadLoanedBooks()
    {
	DIR *dp;
	struct dirent *ep;
	int entryLen;
	struct Loan* loan;
	char * res;
	
	std::string loanDir = std::string(activationDir) + std::string("/") + LOANS_DIR;

	if (!fileExists(loanDir.c_str()))
	    return;
	
	dp = opendir (loanDir.c_str());

	if(!dp)
	    EXCEPTION(gourou::USER_INVALID_INPUT, "Cannot read directory " << loanDir);

	while ((ep = readdir (dp)))
	{
	    if (ep->d_type != DT_LNK &&
		ep->d_type != DT_REG)
		continue;

	    entryLen = strlen(ep->d_name);

	    if (entryLen <= 4 ||
		ep->d_name[entryLen-4] != '.' ||
		ep->d_name[entryLen-3] != 'x' ||
		ep->d_name[entryLen-2] != 'm' ||
		ep->d_name[entryLen-1] != 'l')
		continue;

	    std::string id = std::string(ep->d_name, entryLen-4);
	    
	    loan = new Loan;
	    loan->path = loanDir + std::string("/") + ep->d_name;

	    pugi::xml_document xmlDoc;
	    pugi::xml_node node;

	    if (!xmlDoc.load_file(loan->path.c_str(), pugi::parse_ws_pcdata_single|pugi::parse_escapes, pugi::encoding_utf8))
	    {
		std::cout << "Invalid loan entry " << loan->path << std::endl;
		goto error;
	    }

	    // id
	    node = xmlDoc.select_node("//id").node();
	    if (!node)
	    {
		std::cout << "Invalid loan entry " << ep->d_name << ", no id element" << std::endl;
		goto error;
	    }
	    loan->id = node.first_child().value();

	    // operatorURL
	    node = xmlDoc.select_node("//operatorURL").node();
	    if (!node)
	    {
		std::cout << "Invalid loan entry " << ep->d_name << ", no operatorURL element" << std::endl;
		goto error;
	    }
	    loan->operatorURL = node.first_child().value();

	    // validity
	    node = xmlDoc.select_node("//validity").node();
	    if (!node)
	    {
		std::cout << "Invalid loan entry " << ep->d_name << ", no validity element" << std::endl;
		goto error;
	    }
	    loan->validity = node.first_child().value();

	    // bookName
	    node = xmlDoc.select_node("//name").node();
	    if (!node)
	    {
		std::cout << "Invalid loan entry " << ep->d_name << ", no name element" << std::endl;
		goto error;
	    }
	    loan->bookName = node.first_child().value();

	    struct tm tm;
	    res = strptime(loan->validity.c_str(), "%Y-%m-%dT%H:%M:%S%Z", &tm);
	    if (*res == 0)
	    {
		if (mktime(&tm) <= time(NULL))
		    loan->validity = "     (Expired)";
	    }
	    else
	    {
		std::cout << "Unable to parse validity timestamp :" << loan->validity << std::endl;
		loan->validity = "     (Unknown)";
	    }
	    
	    loanedBooks[id] = loan;
	    continue;

	error:
	    if (loan)
		delete loan;
	}

	closedir (dp);
    }

    void displayLoanList()
    {
	if (loanedBooks.empty())
	{
	    std::cout << "No books are loaned" << std::endl;
	    return;
	}

	struct Loan* loan;
	std::string::size_type maxSizeBookName=0;
	// Compute max size
	for (const auto& kv : loanedBooks)
	{
	    loan = kv.second;
	    if (loan->bookName.size() > maxSizeBookName)
		maxSizeBookName = loan->bookName.size();
	}

	if (maxSizeBookName > MAX_SIZE_BOOK_NAME)
	    maxSizeBookName = MAX_SIZE_BOOK_NAME;
	else if ((maxSizeBookName % 2))
	    maxSizeBookName++;

	// std::cout << "  ID      Book      Expiration" << std::endl;
	// std::cout << "------------------------------" << std::endl;

	int fillID, fillExpiration=(20 - 10)/2;
    std::string::size_type fillBookName;
	
	fillID = (ID_HASH_SIZE - 2) / 2;
	fillBookName = (maxSizeBookName - 4) / 2;

	std::cout.width (fillID);
	std::cout << ""
	          << "ID" ;
	std::cout.width (fillID);
	std::cout << ""
	          << "    " ;
	
	std::cout.width ((long)fillBookName);
	std::cout << ""
	          << "Book" ;
	std::cout.width ((long)fillBookName);
	std::cout << ""
	          << "    " ;

	std::cout.width (fillExpiration);
	std::cout << ""
	          << "Expiration";
	std::cout.width (fillExpiration);
	std::cout << "" << std::endl;

	std::cout.fill ('-');
	std::cout.width (ID_HASH_SIZE + 4 + maxSizeBookName + 4 + 20);
	std::cout << "" << std::endl;
	std::cout.fill (' ');

	std::string bookName;

	for (const auto& kv : loanedBooks)
	{
	    loan = kv.second;

	    std::cout << kv.first
	              << "    ";

	    if (loan->bookName.size() > MAX_SIZE_BOOK_NAME)
		bookName = std::string(loan->bookName.c_str(), MAX_SIZE_BOOK_NAME);
	    else
		bookName = loan->bookName;

	    std::cout << bookName;
	    std::cout.width ((long)(maxSizeBookName - bookName.size()));
	    std::cout << ""
	              << "    "
	    
	              << loan->validity << std::endl;
	}

	std::cout << std::endl;
    }

    void returnBook(gourou::DRMProcessor& processor)
    {
	struct Loan* loan = loanedBooks[std::string(returnID)];

	if (!loan)
	{
	    std::cout << "Error : Loan " << returnID << " doesn't exists" << std::endl;
	    return;
	}

	processor.returnLoan(loan->id, loan->operatorURL);
	
	deleteID = returnID;
	if (deleteLoan(false))
	{
	    std::cout << "Loan " << returnID << " successfully returned" << std::endl;
	}
    }
    
    bool deleteLoan(bool displayResult=true)
    {
	struct Loan* loan = loanedBooks[std::string(deleteID)];

	if (!loan)
	{
	    std::cout << "Error : Loan " << deleteID << " doesn't exists" << std::endl;
	    return false;
	}

	if (unlink(loan->path.c_str()))
	{
	    std::cout << "Error : Cannot delete " << loan->path << std::endl;
	    return false;
	}
	else if (displayResult)
	{
	    std::cout << "Loan " << deleteID << " deleted" << std::endl;
	}
	
	return true;
    }

    std::map<std::string, struct Loan*> loanedBooks;
};	      


static void usage(const char* cmd)
{
    std::cout << "Manage loaned books\n"
    
              << "Usage: " << basename((char*)cmd) << " [(-d|--activation-dir) dir] (-l|--list)|(-D|--delete loanID)|(-R|--delete loanID) [(-v|--verbose)] [(-h|--help)]\n\n"
    
              << "  " << "-d|--activation-dir"  << "\t"   << "Directory of device.xml/activation.xml and device key\n"
              << "  " << "-l|--list"            << "\t\t" << "List all loaned books\n"
              << "  " << "-r|--return"          << "\t\t" << "Return a loaned book\n"
              << "  " << "-D|--delete"          << "\t\t" << "Delete a loan entry without returning it\n"
              << "  " << "-v|--verbose"         << "\t\t" << "Increase verbosity, can be set multiple times\n"
              << "  " << "-V|--version"         << "\t\t" << "Display libgourou version\n"
              << "  " << "-h|--help"            << "\t\t" << "This help\n"

              << '\n'
              << "Activation directory is optional. If not set, it's looked into :\n"
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
    int actions = 0;
    
    while (true) {
	int option_index = 0;
	static struct option long_options[] = {
	    {"activation-dir",   required_argument, 0,  'd' },
	    {"list",             no_argument,       0,  'l' },
	    {"return",           no_argument,       0,  'r' },
	    {"delete",           no_argument,       0,  'D' },
	    {"verbose",          no_argument,       0,  'v' },
	    {"version",          no_argument,       0,  'V' },
	    {"help",             no_argument,       0,  'h' },
	    {0,                  0,                 0,  0 }
	};

	c = getopt_long(argc, argv, "d:lr:D:vVh",
                        long_options, &option_index);
	if (c == -1)
	    break;

	switch (c) {
	case 'd':
	    activationDir = optarg;
	    break;
	case 'l':
	    list = true;
	    actions++;
	    break;
	case 'r':
	    returnID = optarg;
	    actions++;
	    break;
	case 'D':
	    deleteID = optarg;
	    actions++;
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

    // By default, simply list books loaned
    if (actions == 0)
	list = true;
    else if (actions != 1)
    {
	usage(argv[0]);
	return -1;
    }

    LoanMGT loanMGT;

    unsigned i;
    bool hasErrors = false;
    const char* orig;
    char *filename;
    for (i=0; i<(unsigned)ARRAY_SIZE(files); i++)
    {
	orig = *files[i];
	
	if (activationDir)
	{
	    const std::string path = std::string(activationDir) + std::string("/") + orig;
	    filename = strdup(path.c_str());
	}
	else
	    filename = strdup(orig);
	*files[i] = findFile(filename);
	free(filename);
	if (!*files[i])
	{
	    std::cout << "Error : " << orig << " doesn't exists, did you activate your device ?" << std::endl;
	    hasErrors = true;
	}
    }

    if (hasErrors)
    {
	// In case of activation dir was provided by user
	activationDir = nullptr;
	goto end;
    }

    if (activationDir)
	activationDir = strdup(activationDir); // For below free
    else
    {
	activationDir = strdup(deviceFile);
	activationDir = dirname(activationDir);
    }

    ret = loanMGT.run();
    
end:
    for (i=0; i<(unsigned)ARRAY_SIZE(files); i++)
    {
	if (*files[i])
	    free((void*)*files[i]);
    }

    if (activationDir)
	free(activationDir);
    
    return ret;
}
