#include <fstream>  
#include <sstream>  
#include <string>
#include <getopt.h>
#include <set>
#include <ctime>

#include <ts/ts.h>
#include <ts/remap.h>
#include "configs.h"
#include "common.h"


set<string>
commaSeparateString(const string &input) {
  istringstream istr(input);
  string token;
  set<string> set;

  while (getline(istr, token, ',')) {
    set.insert(token);
  }

  return set;
}

string 
filterParam(set<string> includeParams, const char* query, int queryLength) {
    istringstream istr(string(query, queryLength));
    string param;
    string filteredParam;

    while (getline(istr, param, '&')) {
        size_t pos = param.find("=");
        if (pos != string::npos) {
            string key = param.substr(0, pos);
            string value = param.substr(pos, param.size());
            if (includeParams.find(key) != includeParams.end()) {
                filteredParam = filteredParam + param;
                filteredParam = filteredParam + "&";
            }
        } 
    }
    if (filteredParam.length() > 0 && filteredParam.back() == '&') {
        filteredParam.pop_back();
    }

    return filteredParam;
}

string 
getValueOfParam(string paramKey, string queryString) {
    istringstream istr(queryString);
    string param;
    string result;

    while (getline(istr, param, '&')) {
        size_t pos = param.find("=");
        if (pos != string::npos) {
            string key = param.substr(0, pos);
            if (paramKey.compare(key) == 0) {
                string value = param.substr(pos + 1, param.size());
                return value;
            }
        } 
    }

    return "";
}

bool 
filterUrlByRegex(pcre* regex, pcre_extra* regex_extra, char* url, int urlLength) {
    if (regex) {
        if (pcre_exec(regex, regex_extra, url, urlLength,0, PCRE_NOTEMPTY, nullptr, 0) >= 0) {
            return true;
        }
} else {
        return true;
    }
    return false;
}

time_t currentTimeInSeconds() {
    return (long)std::time(0);
}