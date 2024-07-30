#define PLUGIN_NAME "custom_parameter"
using namespace std;

set<string>
commaSeparateString(const string &input);

string 
filterParam(set<string> includeParams, const char* query, int queryLength);

string
getValueOfParam(string param, string queryString);

bool 
filterUrlByRegex(pcre* regex, pcre_extra* regex_extra, char* url, int urlLength);

time_t currentTimeInSeconds();

