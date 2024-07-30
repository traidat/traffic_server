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
    {const_cast<char *>("add-param"), optional_argument, nullptr, 'd'},
    {const_cast<char *>("url-add-param-regex"), optional_argument, nullptr, 'e'},
    {const_cast<char *>("timeshift-param"), optional_argument, nullptr, 'f'},
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
        if (includeParamConfig) {
            includeParamConfig->freeRegex();
        } else {
            includeParamConfig = new ParameterConfig();
        }
        includeParamConfig->setUrlRegex(pcre_compile(optarg, options, &errptr, &erroffset, NULL));
        if (includeParamConfig->getUrlRegex() == NULL) {
            TSDebug(PLUGIN_NAME, "Regex compilation failed with error (%s) at character %d", errptr, erroffset);
        } else {
        //TODO: How to remove ifdef in code (it can be in declare but i don't want it in code) ???
        #ifdef PCRE_STUDY_JIT_COMPILE
            options = PCRE_STUDY_JIT_COMPILE;
        #endif
            includeParamConfig->setUrlRegexExtra(pcre_study(includeParamConfig->getUrlRegex(), options, &errptr)); // We do not need to check the error here because we can still run without the studying?
        }
    } break;
    case 'd': /* add params */
    {
        TSDebug(PLUGIN_NAME, "Add param: %s", optarg);
        _shouldAddParams = true;
        if (!addParamConfig) {
            addParamConfig = new WMParameterConfig();
        }
        addParamConfig->setParams(commaSeparateString(string(optarg)));
    } break;
    case 'e': /* url add params regex */ 
    {
        TSDebug(PLUGIN_NAME, "Url add regex param: %s", optarg);
        const char *errptr;
        int erroffset, options = 0;
        if (addParamConfig) {
            addParamConfig->freeRegex();
        } else {
            addParamConfig = new WMParameterConfig();
        }
        addParamConfig->setUrlRegex(pcre_compile(optarg, options, &errptr, &erroffset, NULL));
        if (addParamConfig->getUrlRegex() == NULL) {
            TSDebug(PLUGIN_NAME, "Regex compilation failed with error (%s) at character %d", errptr, erroffset);
        } else {
        //TODO: How to remove ifdef in code (it can be in declare but i don't want it in code) ???
        #ifdef PCRE_STUDY_JIT_COMPILE
            options = PCRE_STUDY_JIT_COMPILE;
        #endif
            addParamConfig->setUrlRegexExtra(pcre_study(addParamConfig->getUrlRegex(), options, &errptr)); // We do not need to check the error here because we can still run without the studying?
        }
    } break;
     case 'f': /* timeshift params */ 
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
    includeParamConfig-> freeRegex();
    addParamConfig->freeRegex();
}


// ParameterConfig


void 
ParameterConfig::setUrlRegex(pcre* regex) {
    urlRegex = regex;
}

void 
ParameterConfig::setUrlRegexExtra(pcre_extra* regexExtra) {
    urlRegexExtra = regexExtra;
}

void 
ParameterConfig::setParams(set<string> set) {
    params = set;
}

void 
ParameterConfig::freeRegex() {
    if (urlRegex) {
    #ifndef PCRE_STUDY_JIT_COMPILE
        pcre_free(cfg->regex_extra);
    #else
        pcre_free_study(urlRegexExtra);
    #endif
        pcre_free(urlRegex);
    }
}

set<string>
ParameterConfig::getParams() {
    return params;
}

pcre*
ParameterConfig::getUrlRegex() {
    return urlRegex;
}

pcre_extra*
ParameterConfig::getUrlRegexExtra() {
    return urlRegexExtra;
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