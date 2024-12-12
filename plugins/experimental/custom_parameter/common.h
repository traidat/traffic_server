#define PLUGIN_NAME "custom_parameter"
#define EMPTY_STRING ""
using namespace std;

set<string>
commaSeparateString(const string &input);

string 
filterIncludeParam(string queryString, set<string> includeParams);

string 
filterExcludeParam(string queryString, set<string> includeParams);

string
getValueOfParam(string param, string queryString);

bool 
filterUrlByRegex(pcre* regex, pcre_extra* regex_extra, char* url, int urlLength);

time_t currentTimeInSeconds();

