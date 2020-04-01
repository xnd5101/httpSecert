
#ifndef _BASE64_H
#define _BASE64_H

//C
#include <dirent.h>  
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h> 
#include <sys/stat.h>

//C++
#include <algorithm>
#include <iostream> 
#include <string> 
#include <vector>  
#include <iconv.h>
#include <uuid/uuid.h>

using namespace std;

string base64Encode(unsigned char* data, unsigned int len);

string base64Decode(std::string & encoded_string);

#endif