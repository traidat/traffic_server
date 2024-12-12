/** @file

  A brief file description

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <zlib.h>
#include <ts/ts.h>
#include <ts/remap.h>
#include <fstream>
#include <cctype>
#include <vector>
#include <iostream>
#include <sstream>
#include <regex>
#include <string>
#include <set>
#include <chrono>

#include "ts/ts.h"
#include "tscore/ink_defs.h"
#include "configs.h"
#include "common.h"

#define ASSERT_SUCCESS(_x) TSAssert((_x) == TS_SUCCESS)
#define MAX_KEY_NUM 16
using namespace std;

void 
remapParam(TSMBuffer buf, TSMLoc url_loc, string param) 
{
  if (param.length() == 0) {
    if (TS_SUCCESS != TSUrlHttpQuerySet(buf, url_loc, NULL, 0)) {
      TSError("[custom_parameter] Cannot set empty request parameter");
    }
  } else if (param.size() > 0 &&
             TS_SUCCESS != TSUrlHttpQuerySet(buf, url_loc, param.c_str(), param.size())) {
    TSDebug(PLUGIN_NAME, "Cannot set request parameter: %s", param.c_str());
  }
}

string
generateWMParam(string queryString, WMParameterConfig *addParamConfig)
{
  time_t currentTime = currentTimeInSeconds();
  for (string timeshift : addParamConfig->getTimeshiftParams()) {
    string timeshiftValue = getValueOfParam(timeshift, queryString);
    if (!timeshiftValue.empty()) {
      long value = stol(timeshiftValue);
      currentTime = currentTime - value;
      break;
    }
  }

  return "wm=" + to_string(currentTime);
}

void
remapAddParam(WMParameterConfig *addParamConfig, TSMBuffer remapBuf, TSMLoc remapLoc, TSMLoc remapUrlLoc, string queryString)
{
  string filteredParam = queryString;
  for (string param : addParamConfig->getParams()) {
    if (param.compare("wm") == 0) {
      string wmParam = generateWMParam(queryString, addParamConfig);
       filteredParam = filterExcludeParam(queryString, addParamConfig->getTimeshiftParams());
      if (wmParam.length() > 0) {
        filteredParam.length() > 0 ? filteredParam += ("&" + wmParam) : filteredParam = wmParam;
      }
    }
  }
  remapParam(remapBuf, remapUrlLoc, filteredParam);
}

void
addParams(Configs *config, TSMBuffer pristineUrlBuf, TSMLoc pristineUrlLoc, TSMBuffer remapBuf, TSMLoc remapLoc,
               char *pristineUrl, int pristineUrlLen, TSMLoc remapUrlLoc)
{
  WMParameterConfig *addParamConfig = config->getAddParamConfig();
  const char *query;
  int queryLength;
  if (addParamConfig->isPristineUrl()) {
    query = TSUrlHttpQueryGet(pristineUrlBuf, pristineUrlLoc, &queryLength);
  } else {
    query = TSUrlHttpQueryGet(remapBuf, remapLoc, &queryLength);
  }
  TSDebug(PLUGIN_NAME, "Query param of request: %s length %d", query, queryLength);
  string queryString(query, queryLength);
  if (addParamConfig->getUrlIncludeRegex() || addParamConfig->getUrlExcludeRegex()) { //  Verify the pristine url of the request that matches regex or not
    if ((addParamConfig->getUrlIncludeRegex() && filterUrlByRegex(addParamConfig->getUrlIncludeRegex(), addParamConfig->getUrlIncludeRegexExtra(), pristineUrl, pristineUrlLen)) || 
        (addParamConfig->getUrlExcludeRegex() && !filterUrlByRegex(addParamConfig->getUrlExcludeRegex(), addParamConfig->getUrlExcludeRegexExtra(), pristineUrl, pristineUrlLen))) {
      remapAddParam(addParamConfig, remapBuf, remapLoc, remapUrlLoc, queryString);
    }
  } else {
    remapAddParam(addParamConfig, remapBuf, remapLoc, remapUrlLoc, queryString);
  }
}

void
includeParams(Configs *config, TSMBuffer pristineUrlBuf, TSMLoc pristineUrlLoc, TSMBuffer remapBuf, TSMLoc remapLoc,
                   char *pristineUrl, int pristineUrlLen, TSMLoc remapUrlLoc)
{
  ParameterConfig *includeParamConfig = config->getIncludeParamConfig();
  const char *query;
  int queryLength;
  if (includeParamConfig->isPristineUrl()) {
    query = TSUrlHttpQueryGet(pristineUrlBuf, pristineUrlLoc, &queryLength);
  } else {
    query = TSUrlHttpQueryGet(remapBuf, remapLoc, &queryLength);
  }
  TSDebug(PLUGIN_NAME, "Query param of request: %s length %d", query, queryLength);
  string queryString(query, queryLength);
 if (includeParamConfig->getUrlIncludeRegex() || includeParamConfig->getUrlExcludeRegex()) { //  Verify the pristine url of the request that matches regex or not
    if ((includeParamConfig->getUrlIncludeRegex() && filterUrlByRegex(includeParamConfig->getUrlIncludeRegex(), includeParamConfig->getUrlIncludeRegexExtra(), pristineUrl, pristineUrlLen)) || 
        (includeParamConfig->getUrlExcludeRegex() && !filterUrlByRegex(includeParamConfig->getUrlExcludeRegex(), includeParamConfig->getUrlExcludeRegexExtra(), pristineUrl, pristineUrlLen))) {
      string filteredParam = filterIncludeParam(queryString, includeParamConfig->getParams());
      remapParam(remapBuf, remapUrlLoc, filteredParam);
    }
  } else {
    string filteredParam = filterIncludeParam(queryString, includeParamConfig->getParams());
    remapParam(remapBuf, remapUrlLoc, filteredParam);
  }
}

TSReturnCode
TSRemapInit(TSRemapInterface *api_info, char *errbuf, int errbuf_size)
{
  if (!api_info) {
    snprintf(errbuf, errbuf_size, "[tsremap_init] - Invalid TSRemapInterface argument");
    return TS_ERROR;
  }

  if (api_info->tsremap_version < TSREMAP_VERSION) {
    snprintf(errbuf, errbuf_size, "[TSRemapInit] - Incorrect API version %ld.%ld", api_info->tsremap_version >> 16,
             (api_info->tsremap_version & 0xffff));
    return TS_ERROR;
  }

  TSDebug(PLUGIN_NAME, "plugin is successfully initialized");
  return TS_SUCCESS;
}


TSReturnCode
TSRemapNewInstance(int argc, char *argv[], void **instance, char *errbuf, int errbuf_size)
{
  Configs *config = new Configs();
  if (config != nullptr) {
    config->init(argc, const_cast<const char **>(argv));
    *instance = config;
  } else {
    TSError("[%s] failed to initialize the remap plugin", PLUGIN_NAME);
    *instance = nullptr;
    delete config;
    return TS_ERROR;
  }

  TSDebug(PLUGIN_NAME, "remap plugin initialized");
  return TS_SUCCESS;
}

void
TSRemapDeleteInstance(void *instance)
{
  Configs *config = static_cast<Configs *>(instance);
  config->free();
  delete config;
}

TSRemapStatus
TSRemapDoRemap(void *instance, TSHttpTxn txnp, TSRemapRequestInfo *rri)
{
  Configs *config = static_cast<Configs *>(instance);
  TSMBuffer remapBuf;
  TSMLoc remapLoc;
  int pristineUrlLen = 0;
  char* pristineUrl;

  TSMBuffer pristineUrlBuf;
  TSMLoc pristineUrlLoc;
  if (TS_SUCCESS == TSHttpTxnPristineUrlGet(txnp, &pristineUrlBuf, &pristineUrlLoc)) {
    pristineUrl = TSUrlStringGet(pristineUrlBuf, pristineUrlLoc, &pristineUrlLen);
  } else {
    TSError("[%s] failed to get pristine url", PLUGIN_NAME);
    return TSREMAP_NO_REMAP;
  }

  if (TS_SUCCESS == TSHttpTxnClientReqGet(txnp, &remapBuf, &remapLoc) && config != nullptr) {
    TSMLoc remapUrlLoc;
    if (TS_SUCCESS == TSHttpHdrUrlGet(remapBuf, remapLoc, &remapUrlLoc)) {
      // should include param or not
      if (config->shouldIncludeParams()) {
        includeParams(config, pristineUrlBuf, pristineUrlLoc, remapBuf, remapLoc, pristineUrl, pristineUrlLen, remapUrlLoc);
      }
      // should add param or not
      if (config->shouldAddParams()) {
        addParams(config, pristineUrlBuf, pristineUrlLoc, remapBuf, remapLoc, pristineUrl, pristineUrlLen, remapUrlLoc);
      }
      ASSERT_SUCCESS(TSHandleMLocRelease(remapBuf, remapLoc, remapUrlLoc));
    }
    ASSERT_SUCCESS(TSHandleMLocRelease(remapBuf, TS_NULL_MLOC, remapLoc));
  }
  ASSERT_SUCCESS(TSHandleMLocRelease(pristineUrlBuf, TS_NULL_MLOC, pristineUrlLoc));

  return TSREMAP_NO_REMAP;
}
