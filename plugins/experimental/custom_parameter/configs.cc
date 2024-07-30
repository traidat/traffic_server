#include <fstream>  
#include <sstream>  
#include <string>
#include <getopt.h>
#include <set>

#include <ts/ts.h>
#include <ts/remap.h>
#include "configs.h"
#include "common.h"


// Config

bool
Configs::init(int argc, const char *argv[]) {
    static const struct option longopt[] = {
    {const_cast<char *>("file-config"), optional_argument, nullptr, 'a'},
    {const_cast<char *>("include-param"), optional_argument, nullptr, 'b'},
    {const_cast<char *>("url-include-param-regex"), optional_argument, nullptr, 'c'},
    {const_cast<char *>("url-not-include-param-regex"), optional_argument, nullptr, 'd'},
    {const_cast<char *>("url-include-param-pristine"), optional_argument, nullptr, 'e'},
    {const_cast<char *>("add-param"), optional_argument, nullptr, 'f'},
    {const_cast<char *>("url-add-param-regex"), optional_argument, nullptr, 'g'},
    {const_cast<char *>("url-not-add-param-regex"), optional_argument, nullptr, 'h'},
    {const_cast<char *>("url-add-param-pristine"), optional_argument, nullptr, 'j'},
    {const_cast<char *>("timeshift-param"), optional_argument, nullptr, 'k'},
    {nullptr, 0, nullptr, 0},
  };

  argc--;
  argv++;

  for (;;) {
    int opt;
    opt = getopt_long(argc, const_cast<char *const *>(argv), "", longopt, nullptr);

    if (opt == -1) {
      break;
    }
    TSDebug(PLUGIN_NAME, "processing %s", argv[optind - 1]);

    switch (opt) {
    case 'a': /* file config */
      TSDebug(PLUGIN_NAME, "File config param: %s", optarg);
      break;
    case 'b': /* include-params */ 
    {
        TSDebug(PLUGIN_NAME, "Include param: %s", optarg);
        _shouldIncludeParams = true;
        if (!includeParamConfig) {
            includeParamConfig = new ParameterConfig();
        }
        includeParamConfig->setParams(commaSeparateString(string(optarg)));
    } break;
    case 'c': /* url include params regex */ 
    {
        TSDebug(PLUGIN_NAME, "Url include param regex param: %s", optarg);
        const char *errptr;
        int erroffset, options = 0;
        if (!includeParamConfig) {
            includeParamConfig = new ParameterConfig();
        }
        if (includeParamConfig->getUrlIncludeRegex()) {
            includeParamConfig->freeIncludeRegex();
        } 
        includeParamConfig->setUrlIncludeRegex(pcre_compile(optarg, options, &errptr, &erroffset, NULL));
        if (includeParamConfig->getUrlIncludeRegex() == NULL) {
            TSDebug(PLUGIN_NAME, "Regex compilation failed with error (%s) at character %d", errptr, erroffset);
        } else {
        //TODO: How to remove ifdef in code (it can be in declare but i don't want it in code) ???
        #ifdef PCRE_STUDY_JIT_COMPILE
            options = PCRE_STUDY_JIT_COMPILE;
        #endif
            includeParamConfig->setUrlIncludeRegexExtra(pcre_study(includeParamConfig->getUrlIncludeRegex(), options, &errptr)); // We do not need to check the error here because we can still run without the studying?
        }
    } break;
    case 'd': /* url not include param regex */ 
    {
        TSDebug(PLUGIN_NAME, "Url not include param regex param: %s", optarg);
        const char *errptr;
        int erroffset, options = 0;
        if (!includeParamConfig) {
            includeParamConfig = new ParameterConfig();
        }
        if (includeParamConfig->getUrlExcludeRegex()) {
            includeParamConfig->freeExcludeRegex();
        } 
        includeParamConfig->setUrlExcludeRegex(pcre_compile(optarg, options, &errptr, &erroffset, NULL));
        if (includeParamConfig->getUrlExcludeRegex() == NULL) {
            TSDebug(PLUGIN_NAME, "Regex compilation failed with error (%s) at character %d", errptr, erroffset);
        } else {
        //TODO: How to remove ifdef in code (it can be in declare but i don't want it in code) ???
        #ifdef PCRE_STUDY_JIT_COMPILE
            options = PCRE_STUDY_JIT_COMPILE;
        #endif
            includeParamConfig->setUrlExcludeRegexExtra(pcre_study(includeParamConfig->getUrlExcludeRegex(), options, &errptr)); // We do not need to check the error here because we can still run without the studying?
        }
    } break;
    case 'e': /* url include param pristine */
    {
        TSDebug(PLUGIN_NAME, "Url include param pristine: %s", optarg);
        if (!includeParamConfig) {
            includeParamConfig = new ParameterConfig();
        }
        includeParamConfig->setIsPristineUrl(string(optarg).compare("1") == 0);
    } break;
    case 'f': /* add params */
    {
        TSDebug(PLUGIN_NAME, "Add param: %s", optarg);
        _shouldAddParams = true;
        if (!addParamConfig) {
            addParamConfig = new WMParameterConfig();
        }
        addParamConfig->setParams(commaSeparateString(string(optarg)));
    } break;
    case 'g': /* url add params regex */ 
    {
        TSDebug(PLUGIN_NAME, "Url add regex param: %s", optarg);
        const char *errptr;
        int erroffset, options = 0;
        if (!addParamConfig) {
            addParamConfig = new WMParameterConfig();
        }
        if (addParamConfig->getUrlIncludeRegex()) {
            addParamConfig->freeIncludeRegex();
        } 
        addParamConfig->setUrlIncludeRegex(pcre_compile(optarg, options, &errptr, &erroffset, NULL));
        if (addParamConfig->getUrlIncludeRegex() == NULL) {
            TSDebug(PLUGIN_NAME, "Regex compilation failed with error (%s) at character %d", errptr, erroffset);
        } else {
        //TODO: How to remove ifdef in code (it can be in declare but i don't want it in code) ???
        #ifdef PCRE_STUDY_JIT_COMPILE
            options = PCRE_STUDY_JIT_COMPILE;
        #endif
            addParamConfig->setUrlIncludeRegexExtra(pcre_study(addParamConfig->getUrlIncludeRegex(), options, &errptr)); // We do not need to check the error here because we can still run without the studying?
        }
    } break;
    case 'h': /* url not add params regex */ 
    {
        TSDebug(PLUGIN_NAME, "Url not add regex param: %s", optarg);
        const char *errptr;
        int erroffset, options = 0;
        if (!addParamConfig) {
            addParamConfig = new WMParameterConfig();
        }
        if (addParamConfig->getUrlExcludeRegex()) {
            addParamConfig->freeExcludeRegex();
        } 
        addParamConfig->setUrlExcludeRegex(pcre_compile(optarg, options, &errptr, &erroffset, NULL));
        if (addParamConfig->getUrlExcludeRegex() == NULL) {
            TSDebug(PLUGIN_NAME, "Regex compilation failed with error (%s) at character %d", errptr, erroffset);
        } else {
        //TODO: How to remove ifdef in code (it can be in declare but i don't want it in code) ???
        #ifdef PCRE_STUDY_JIT_COMPILE
            options = PCRE_STUDY_JIT_COMPILE;
        #endif
            addParamConfig->setUrlExcludeRegexExtra(pcre_study(addParamConfig->getUrlExcludeRegex(), options, &errptr)); // We do not need to check the error here because we can still run without the studying?
        }
    } break;
    case 'j': /* url add param pristine */
    {
        TSDebug(PLUGIN_NAME, "Url add param pristine: %s", optarg);
        if (!addParamConfig) {
            addParamConfig = new WMParameterConfig();
        }
        addParamConfig->setIsPristineUrl(string(optarg).compare("1") == true);
    } break;
     case 'k': /* timeshift params */ 
    {
        TSDebug(PLUGIN_NAME, "Timeshift param: %s", optarg);
        if (!addParamConfig) {
            addParamConfig = new WMParameterConfig();
        }
        addParamConfig->setTimeshiftParams(commaSeparateString(string(optarg)));
    } break;
    default:
      break;
    }
  }

  return true;
}

bool
Configs::shouldIncludeParams() {
    return _shouldIncludeParams;
}

bool
Configs::shouldAddParams() {
    return _shouldAddParams;
}

WMParameterConfig*
Configs::getAddParamConfig() {
    return addParamConfig;
}

ParameterConfig*
Configs::getIncludeParamConfig() {
    return includeParamConfig;
}

void
Configs::freeRegex() {
    includeParamConfig->freeRegex();
    addParamConfig->freeRegex();
}

void 
Configs::free() {
    if (includeParamConfig) {
        includeParamConfig->freeRegex();
        delete includeParamConfig;
    }
    if (addParamConfig) {
        addParamConfig->freeRegex();
        delete addParamConfig;
    }
}


// ParameterConfig


void 
ParameterConfig::setUrlIncludeRegex(pcre* regex) {
    urlIncludeRegex = regex;
}

void 
ParameterConfig::setUrlIncludeRegexExtra(pcre_extra* regexExtra) {
    urlIncludeRegexExtra = regexExtra;
}

void 
ParameterConfig::setUrlExcludeRegex(pcre* regex) {
    urlExcludeRegex = regex;
}

void 
ParameterConfig::setUrlExcludeRegexExtra(pcre_extra* regexExtra) {
    urlExcludeRegexExtra = regexExtra;
}

void 
ParameterConfig::setParams(set<string> set) {
    params = set;
}

void 
ParameterConfig::setIsPristineUrl(bool isPristineUrl) {
    _isPristineUrl = isPristineUrl;
}

void 
ParameterConfig::freeRegex() {
    freeExcludeRegex();
    freeIncludeRegex();
}

void 
ParameterConfig::freeIncludeRegex() {
    if (urlIncludeRegex) {
    #ifndef PCRE_STUDY_JIT_COMPILE
        pcre_free(urlIncludeRegex);
    #else
        pcre_free_study(urlIncludeRegexExtra);
    #endif
        pcre_free(urlIncludeRegex);
    }
}

void 
ParameterConfig::freeExcludeRegex() {
    if (urlExcludeRegex) {
    #ifndef PCRE_STUDY_JIT_COMPILE
        pcre_free(urlExcludeRegex);
    #else
        pcre_free_study(urlExcludeRegexExtra);
    #endif
        pcre_free(urlExcludeRegex);
    }
}

set<string>
ParameterConfig::getParams() {
    return params;
}

pcre*
ParameterConfig::getUrlIncludeRegex() {
    return urlIncludeRegex;
}

pcre_extra*
ParameterConfig::getUrlIncludeRegexExtra() {
    return urlIncludeRegexExtra;
}

pcre*
ParameterConfig::getUrlExcludeRegex() {
    return urlExcludeRegex;
}

pcre_extra*
ParameterConfig::getUrlExcludeRegexExtra() {
    return urlExcludeRegexExtra;
}

bool
ParameterConfig::isPristineUrl() {
    return _isPristineUrl;
}

// WMParameterConfig

set<string>
WMParameterConfig::getTimeshiftParams() {
    return timeshiftParams;
}

void 
WMParameterConfig::setTimeshiftParams(set<string> params) {
    timeshiftParams = params;
}