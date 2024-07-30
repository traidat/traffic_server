#include <string>
#include <set>
#include <map>
#include <vector>
#include <list>

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
    pcre* getUrlIncludeRegex();
    pcre_extra* getUrlIncludeRegexExtra();
    pcre* getUrlExcludeRegex();
    pcre_extra* getUrlExcludeRegexExtra();
    bool isPristineUrl();

    void setParams(set<string> params);
    void setUrlIncludeRegex(pcre* regex);
    void setUrlIncludeRegexExtra(pcre_extra* regexExtra);
    void setUrlExcludeRegex(pcre* regex);
    void setUrlExcludeRegexExtra(pcre_extra* regexExtra);
    void setIsPristineUrl(bool isPristineUrl);
    void freeRegex();
    void freeIncludeRegex();
    void freeExcludeRegex();

protected:
    set<string> params;
    pcre* urlIncludeRegex = nullptr;
    pcre_extra* urlIncludeRegexExtra = nullptr;
    pcre* urlExcludeRegex = nullptr;
    pcre_extra* urlExcludeRegexExtra = nullptr;
    bool _isPristineUrl = true;
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
    ParameterConfig* getIncludeParamConfig();
    WMParameterConfig* getAddParamConfig();

    void freeRegex();
    void free();

protected:
    bool _shouldIncludeParams = false;
    bool _shouldAddParams = false;

    ParameterConfig* includeParamConfig = nullptr;
    WMParameterConfig* addParamConfig = nullptr;
};

