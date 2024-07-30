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
remapParam(TSMBuffer buf, TSMLoc loc, TSMLoc url_loc, string param) 
{
  if (param.length() == 0) {
    if (TS_SUCCESS != TSUrlHttpQuerySet(buf, loc, NULL, 0)) {
      TSError("[custom_parameter] Cannot set empty request parameter");
    }
  } else if (param.size() > 0 &&
             TS_SUCCESS != TSUrlHttpQuerySet(buf, url_loc, param.c_str(), param.size())) {
    TSDebug(PLUGIN_NAME, "Cannot set request parameter: %s", param.c_str());
  }
}

string
generateWMParam(TSMBuffer remapBuf, TSMLoc remapLoc,
             TSMLoc remapUrlLoc, string queryString, WMParameterConfig *addParamConfig)
{
  time_t currentTime = currentTimeInSeconds();
  for (string timeshift : addParamConfig->getTimeshiftParams()) {
    string timeshiftValue = getValueOfParam(timeshift, queryString);
    if (!timeshiftValue.empty()) {
      long value = stol(timeshiftValue);
      currentTime = currentTime - value;
      return "wm=" + to_string(currentTime);
    }
  }
  return "";
}

void
remapAddParam(WMParameterConfig *addParamConfig, TSMBuffer remapBuf, TSMLoc remapLoc, TSMLoc remapUrlLoc, const char *query,
              int queryLength)
{
  string queryString(query, queryLength);
  for (string param : addParamConfig->getParams()) {
    if (param.compare("wm") == 0) {
      string wmParam = generateWMParam(remapBuf, remapLoc, remapUrlLoc, queryString, addParamConfig);
      if (queryString.length() > 0 && wmParam.length() > 0) {
        queryString = queryString + "&" + wmParam;
      }
    }
  }
  remapParam(remapBuf, remapLoc, remapUrlLoc, queryString);
}

void
remapIncludeParam(TSMBuffer buf, TSMLoc loc, TSMLoc url_loc, ParameterConfig *includeParamConfig, const char *query, int queryLength)
{
  string filteredParam = filterParam(includeParamConfig->getParams(), query, queryLength);
  remapParam(buf, loc, url_loc, filteredParam);
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
  if (config->shouldAddParams()) {
    delete config->getAddParamConfig();
  } 
  if (config->shouldIncludeParams()) {
    delete config->getIncludeParamConfig();
  }
  config->freeRegex();
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
  }
  

  if (TS_SUCCESS == TSHttpTxnClientReqGet(txnp, &remapBuf, &remapLoc) && config != nullptr) {
    const char *query;
    int queryLength;
    TSMLoc remapUrlLoc;
    if (TS_SUCCESS == TSHttpHdrUrlGet(remapBuf, remapLoc, &remapUrlLoc)) {
      query = TSUrlHttpQueryGet(remapBuf, remapUrlLoc, &queryLength);
      TSDebug(PLUGIN_NAME, "Query param of request: %s length %d", query, queryLength);
      
      if (query != nullptr && queryLength > 0) {
        
        if (config->shouldIncludeParams()) { // should include param or not
          ParameterConfig* includeParamConfig = config->getIncludeParamConfig();
          if (includeParamConfig->getUrlRegex()) { //  Verify the pristine url of the request that matches regex or not
            if (filterUrlByRegex(includeParamConfig->getUrlRegex(), includeParamConfig->getUrlRegexExtra(), pristineUrl, pristineUrlLen)) {
              remapIncludeParam(remapBuf, remapLoc, remapUrlLoc, includeParamConfig, query, queryLength);
            }
          } else {
            remapIncludeParam(remapBuf, remapLoc, remapUrlLoc, includeParamConfig, query, queryLength);
          }
        }
        if (config->shouldAddParams()) { // should add param or not
          WMParameterConfig* addParamConfig = config->getAddParamConfig();
          if (addParamConfig->getUrlRegex()) { //  Verify the pristine url of the request that matches regex or not
            if (filterUrlByRegex(addParamConfig->getUrlRegex(), addParamConfig->getUrlRegexExtra(), pristineUrl, pristineUrlLen)) { 
              remapAddParam(addParamConfig, remapBuf, remapLoc, remapUrlLoc, query, queryLength);
            }
          } else {
            remapAddParam(addParamConfig, remapBuf, remapLoc, remapUrlLoc, query, queryLength);
          }
        }
      }
      ASSERT_SUCCESS(TSHandleMLocRelease(remapBuf, remapLoc, remapUrlLoc));
    }
    ASSERT_SUCCESS(TSHandleMLocRelease(remapBuf, TS_NULL_MLOC, remapLoc));
  }
  ASSERT_SUCCESS(TSHandleMLocRelease(pristineUrlBuf, TS_NULL_MLOC, pristineUrlLoc));

  return TSREMAP_NO_REMAP;
}


