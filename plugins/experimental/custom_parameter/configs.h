#include <string>
#include <set>
#include <map>

#ifdef HAVE_PCRE_PCRE_H
#include <pcre/pcre.h>
#else
#include <pcre.h>
#endif

using namespace std;

class ParameterConfig
{
public: 
    ParameterConfig() {}
    set<string> getParams();
    pcre* getUrlRegex();
    pcre_extra* getUrlRegexExtra();

    void setParams(set<string> params);
    void setUrlRegex(pcre* regex);
    void setUrlRegexExtra(pcre_extra* regexExtra);
    void freeRegex();

protected:
    set<string> params;
    pcre* urlRegex = nullptr;
    pcre_extra* urlRegexExtra = nullptr;
};

class WMParameterConfig : public ParameterConfig
{
public: 
    WMParameterConfig() {}
    set<string> getTimeshiftParams();

    void setTimeshiftParams(set<string> params);

private:
    set<string> timeshiftParams;
};


class Configs
{
public:
    Configs() {}
    bool init(int argc, const char *argv[]);

    bool shouldIncludeParams();
    bool shouldAddParams();
    void freeRegex();
    ParameterConfig* getIncludeParamConfig();
    WMParameterConfig* getAddParamConfig();

protected:
    bool _shouldIncludeParams = false;
    bool _shouldAddParams = false;

    ParameterConfig* includeParamConfig = nullptr;
    WMParameterConfig* addParamConfig = nullptr;
};

