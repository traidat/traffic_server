/** @file
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

#define min(a, b)           \
  ({                        \
    __typeof__(a) _a = (a); \
    __typeof__(b) _b = (b); \
    _a < _b ? _a : _b;      \
  })

#include "url_sig.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>
#include <ctype.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef HAVE_PCRE_PCRE_H
#include <pcre/pcre.h>
#else
#include <pcre.h>
#endif

#include <ts/ts.h>
#include <ts/remap.h>

static const char PLUGIN_NAME[] = "url_sig";

struct config {
  TSHttpStatus err_status;
  char *err_url;
  char keys[MAX_KEY_NUM][MAX_KEY_LEN];
  pcre *regex;
  pcre_extra *regex_extra;
  int pristine_url_flag;
  char *sig_anchor;
  bool ignore_expiry;
  char hash_query_param[MAX_HASH_QUERY_PARAM_NUM][MAX_HASH_QUERY_LEN];
  int paramNum;
  char use_parts[MAX_USE_PARTS_LEN];
  int algorithm;
  int knumber;
  char bypass_method[10][10];
  int method_num;
  char timeshift_param[MAX_TIME_SHIFT_PARAM][MAX_HASH_QUERY_LEN];
  int timeshift_param_num;
  bool enable_watermark;
};

static void
free_cfg(struct config *cfg)
{
  TSDebug(PLUGIN_NAME, "Cleaning up");
  TSfree(cfg->err_url);
  TSfree(cfg->sig_anchor);

  if (cfg->regex_extra) {
#ifndef PCRE_STUDY_JIT_COMPILE
    pcre_free(cfg->regex_extra);
#else
    pcre_free_study(cfg->regex_extra);
#endif
  }

  if (cfg->regex) {
    pcre_free(cfg->regex);
  }

  TSfree(cfg);
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

// To force a config file reload touch remap.config and do a "traffic_ctl config reload"
TSReturnCode
TSRemapNewInstance(int argc, char *argv[], void **ih, char *errbuf, int errbuf_size)
{
  char config_filepath_buf[PATH_MAX], *config_file;
  struct config *cfg;

  if ((argc < 3) || (argc > 4)) {
    snprintf(errbuf, errbuf_size,
             "[TSRemapNewInstance] - Argument count wrong (%d)... config file path is required first pparam, \"pristineurl\" is"
             "optional second pparam.",
             argc);
    return TS_ERROR;
  }
  TSDebug(PLUGIN_NAME, "Initializing remap function of %s -> %s with config from %s", argv[0], argv[1], argv[2]);

  if (argv[2][0] == '/') {
    config_file = argv[2];
  } else {
    snprintf(config_filepath_buf, sizeof(config_filepath_buf), "%s/%s", TSConfigDirGet(), argv[2]);
    config_file = config_filepath_buf;
  }
  TSDebug(PLUGIN_NAME, "config file name: %s", config_file);
  FILE *file = fopen(config_file, "r");
  if (file == NULL) {
    snprintf(errbuf, errbuf_size, "[TSRemapNewInstance] - Error opening file %s", config_file);
    return TS_ERROR;
  }

  char line[300];
  int line_no = 0;
  int keynum;
  int paramNum = 0;
  int method_num = 0;
  bool eat_comment = false;
  int timeshift_param_num = 0;
  bool enable_watermark = false;

  cfg = TSmalloc(sizeof(struct config));
  memset(cfg, 0, sizeof(struct config));

  while (fgets(line, sizeof(line), file) != NULL) {
    TSDebug(PLUGIN_NAME, "LINE: %s (%d)", line, (int)strlen(line));
    line_no++;

    if (eat_comment) {
      // Check if final char is EOL, if so we are done eating
      if (line[strlen(line) - 1] == '\n') {
        eat_comment = false;
      }
      continue;
    }
    if (line[0] == '#' || strlen(line) <= 1) {
      // Check if we have a comment longer than the full buffer if no EOL
      if (line[strlen(line) - 1] != '\n') {
        eat_comment = true;
      }
      continue;
    }
    char *pos = strchr(line, '=');
    if (pos == NULL) {
      TSError("[url_sig] Error parsing line %d of file %s (%s)", line_no, config_file, line);
      continue;
    }
    *pos        = '\0';
    char *value = pos + 1;
    while (isspace(*value)) { // remove whitespace
      value++;
    }
    pos = strchr(value, '\n'); // remove the new line, terminate the string
    if (pos != NULL) {
      *pos = '\0';
    }
    if (pos == NULL || strlen(value) >= MAX_KEY_LEN) {
      snprintf(errbuf, errbuf_size, "[TSRemapNewInstance] - Maximum key length (%d) exceeded on line %d", MAX_KEY_LEN - 1, line_no);
      fclose(file);
      free_cfg(cfg);
      return TS_ERROR;
    }

    cfg->enable_watermark = enable_watermark;
    if (strncmp(line, "key", 3) == 0) {
      if (strncmp(line + 3, "0", 1) == 0) {
        keynum = 0;
      } else {
        TSDebug(PLUGIN_NAME, ">>> %s <<<", line + 3);
        keynum = atoi(line + 3);
        if (keynum == 0) {
          keynum = -1; // Not a Number
        }
      }
      TSDebug(PLUGIN_NAME, "key number %d == %s", keynum, value);
      if (keynum >= MAX_KEY_NUM || keynum < 0) {
        snprintf(errbuf, errbuf_size, "[TSRemapNewInstance] - Key number (%d) >= MAX_KEY_NUM (%d) or NaN", keynum, MAX_KEY_NUM);
        fclose(file);
        free_cfg(cfg);
        return TS_ERROR;
      }
      snprintf(&cfg->keys[keynum][0], MAX_KEY_LEN, "%s", value);
    } else if (strncmp(line, "error_url", 9) == 0) {
      if (atoi(value)) {
        cfg->err_status = atoi(value);
      }
      value += 3;
      while (isspace(*value)) {
        value++;
      }
      if (cfg->err_status == TS_HTTP_STATUS_MOVED_TEMPORARILY) {
        cfg->err_url = TSstrndup(value, strlen(value));
      } else {
        cfg->err_url = NULL;
      }
    } else if (strncmp(line, "sig_anchor", 10) == 0) {
      cfg->sig_anchor = TSstrndup(value, strlen(value));
    } else if (strncmp(line, "excl_regex", 10) == 0) {
      // compile and study regex
      const char *errptr;
      int erroffset, options = 0;

      if (cfg->regex) {
        TSDebug(PLUGIN_NAME, "Skipping duplicate excl_regex");
        continue;
      }

      cfg->regex = pcre_compile(value, options, &errptr, &erroffset, NULL);
      if (cfg->regex == NULL) {
        TSDebug(PLUGIN_NAME, "Regex compilation failed with error (%s) at character %d", errptr, erroffset);
      } else {
#ifdef PCRE_STUDY_JIT_COMPILE
        options = PCRE_STUDY_JIT_COMPILE;
#endif
        cfg->regex_extra = pcre_study(
          cfg->regex, options, &errptr); // We do not need to check the error here because we can still run without the studying?
      }
    } else if (strncmp(line, "ignore_expiry", 13) == 0) {
      if (strncmp(value, "true", 4) == 0) {
        cfg->ignore_expiry = true;
        TSError("[url_sig] Plugin IGNORES sig expiration");
      }
    } else if (strncmp(line, "url_type", 8) == 0) {
      if (strncmp(value, "pristine", 8) == 0) {
        cfg->pristine_url_flag = 1;
        TSDebug(PLUGIN_NAME, "Pristine URLs (from config) will be used");
      }
    } else if (strncmp(line, "hash_query_param", 16) == 0) {
      char* param;
      while ((param = strtok_r(value, ",", &param))) {
        TSDebug(PLUGIN_NAME, "Param number %d: %s", paramNum, param);
        snprintf(&cfg->hash_query_param[paramNum][0], MAX_HASH_QUERY_LEN, "%s", param);
        value = value + strlen(param) + 1;
        paramNum = paramNum + 1;
      }
      cfg->paramNum = paramNum;
    } else if (strncmp(line, "use_parts", 9) == 0) {
      snprintf(&cfg->use_parts[0], MAX_USE_PARTS_LEN, "%s", value);
      TSDebug(PLUGIN_NAME, "Use_part: %s", cfg->use_parts);
    } else if (strncmp(line, "algorithm", 9) == 0) {
      cfg->algorithm = atoi(value);
    } else if (strncmp(line, "knumber", 1) == 0) {
      cfg->knumber = atoi(value);
    } else if (strncmp(line, "bypass_method", 13) == 0) {
      char* method;
      while ((method = strtok_r(value, ",", &method))) {
        TSDebug(PLUGIN_NAME, "Bypass method number %d: %s", method_num, method);
        snprintf(&cfg->bypass_method[method_num][0], 10, "%s", method);
        value = value + strlen(method) + 1;
        method_num = method_num + 1;
      }
      cfg->method_num = method_num;
    } else if (strncmp(line, "timeshift_param", 15) == 0) {
      char* param;
      while ((param = strtok_r(value, ",", &param))) {
        TSDebug(PLUGIN_NAME, "Timeshift param number %d: %s", timeshift_param_num, param);
        snprintf(&cfg->timeshift_param[timeshift_param_num][0], MAX_HASH_QUERY_LEN, "%s", param);
        value = value + strlen(param) + 1;
        timeshift_param_num = timeshift_param_num + 1;
      }
      cfg->timeshift_param_num = timeshift_param_num;
    } else if (strncmp(line, "enable_watermark", 16) == 0) {
      int enable = atoi(value);
      if (enable == 1) {
        cfg->enable_watermark = true;
      }
    } else {
      TSError("[url_sig] Error parsing line %d of file %s (%s)", line_no, config_file, line);
    }
  }

  fclose(file);

  if (argc > 3) {
    if (strcasecmp(argv[3], "pristineurl") == 0) {
      cfg->pristine_url_flag = 1;
      TSDebug(PLUGIN_NAME, "Pristine URLs (from args) will be used");

    } else {
      snprintf(errbuf, errbuf_size, "[TSRemapNewInstance] - second pparam (if present) must be pristineurl");
      free_cfg(cfg);
      return TS_ERROR;
    }
  }

  switch (cfg->err_status) {
  case TS_HTTP_STATUS_MOVED_TEMPORARILY:
    if (cfg->err_url == NULL) {
      snprintf(errbuf, errbuf_size, "[TSRemapNewInstance] - Invalid config, err_status == 302, but err_url == NULL");
      free_cfg(cfg);
      return TS_ERROR;
    }
    break;
  case TS_HTTP_STATUS_FORBIDDEN:
    if (cfg->err_url != NULL) {
      snprintf(errbuf, errbuf_size, "[TSRemapNewInstance] - Invalid config, err_status == 403, but err_url != NULL");
      free_cfg(cfg);
      return TS_ERROR;
    }
    break;
  default:
    snprintf(errbuf, errbuf_size, "[TSRemapNewInstance] - Return code %d not supported", cfg->err_status);
    free_cfg(cfg);
    return TS_ERROR;
  }

  *ih = (void *)cfg;
  return TS_SUCCESS;
}

void
TSRemapDeleteInstance(void *ih)
{
  free_cfg((struct config *)ih);
}

static void
err_log(const char *url, const char *msg)
{
  if (msg && url) {
    TSDebug(PLUGIN_NAME, "[URL=%s]: %s", url, msg);
    TSError("[url_sig] [URL=%s]: %s", url, msg); // This goes to error.log
  } else {
    TSError("[url_sig] Invalid err_log request");
  }
}

// See the README.  All Signing parameters must be concatenated to the end
// of the url and any application query parameters.
static char *
getAppQueryString(const struct config* cfg, const char *query_string, int query_length, char *const current_url)
{
  int done = 0;
  char *p;
  char buf[MAX_QUERY_LEN + 1];

  if (query_length > MAX_QUERY_LEN) {
    TSDebug(PLUGIN_NAME, "Cannot process the query string as the length exceeds %d bytes", MAX_QUERY_LEN);
    return NULL;
  }
  memset(buf, 0, sizeof(buf));
  memcpy(buf, query_string, query_length);
  p = buf;

  TSDebug(PLUGIN_NAME, "query_string: %s, query_length: %d", query_string, query_length);
  char result[MAX_QUERY_LEN];
  memset(result, '\0', sizeof(result));
  TSDebug(PLUGIN_NAME, "Result %s", result);
  // Remove token query param
  do {
    char* token = strstr(p, SIG_QSTRING "=");
    if (token != NULL) {
      TSDebug(PLUGIN_NAME, "Token %s", token);
      done = 1;
      char* delimeter = strchr(token, '&');
      TSDebug(PLUGIN_NAME, "Delimeter %s", delimeter);
      TSDebug(PLUGIN_NAME, "P %s", p);


      // remove "&token={TOKEN}" and retain all other params
      if (token != p) {
        strncat(result, p, (token - p) - 1);
        if (delimeter != NULL) {
          strcat(result, delimeter);
        }
      } else {
        if (delimeter != NULL) {
          delimeter++;
          strcat(result, delimeter);
        }
      }
    } else {
      TSDebug(PLUGIN_NAME, "P %s", p);
      done = 1;
      strcpy(result, p);
    }
  } while (!done);

  // Add timewater mark for manifest file (hls or dash) exclude CUTV and master manifest (index.m3u8)
  if (cfg->enable_watermark && strstr(query_string, "begin=") == NULL && strstr(query_string, "end=") == NULL 
    && strstr(current_url, "/index.m3u8") == NULL && strstr(current_url, "/index.mpd") == NULL 
    && (strstr(current_url, ".m3u8") != NULL || (strstr(current_url, ".mpd") != NULL))) {
    
    int timeshift = extractTimeshift(cfg->timeshift_param, cfg->timeshift_param_num, p);

    long long watermark = time(NULL) - timeshift;

    // add watermark=%s;
    char* join = (result[0] == '\0') ? "" : "&";
    char* temp = result;
    sprintf(result, "%s%swm=%lld", temp, join, watermark);
  }
  

  TSDebug(PLUGIN_NAME, "Result %s", result);
  if (strlen(result) > 0) {
    p = TSstrdup(result);
    memset(result, '\0', sizeof(result));
    return p;
  } else {
    return NULL;
  }
}

/**
 *  params = [ "time_shift", "timeshift", "delay"]
 * 
 * 
 * query_string: 
 * uid=10&timeshift=1000&token=24234234324 => 1000
 * channel=100&token=1000&delay=2&x=34324&u=34324324 => 
 * time_shift=1234&a=342342&bb=343434343434&c=adfjaslfjsadk324l32j4l => 1234
 */
 
int extractTimeshift(char params[][MAX_HASH_QUERY_LEN], int param_num, char* query_string) {
	for (int i = 0; i < param_num; i++) {
		char* param = params[i];
		int result = 0;
		
		char* pos = strstr(query_string, param);
    
	    if (pos != NULL) {
	        // Move the pointer to the position after "timeshift="
	        pos += strlen(param);
	        sscanf(pos, "=%d", &result);

          // prevent NEGATIVE timeshift
          if (result >= 0) {
	          return result;
          }
	    }
	}
	
	return 0;
}

/** fixedBufferWrite safely writes no more than *dest_len bytes to *dest_end
 * from src. If copying src_len bytes to *dest_len would overflow, it returns
 * zero. *dest_end is advanced and *dest_len is decremented to account for the
 * written data. No null-terminators are written automatically (though they
 * could be copied with data).
 */
static int
fixedBufferWrite(char **dest_end, int *dest_len, const char *src, int src_len)
{
  if (src_len > *dest_len) {
    return 0;
  }
  memcpy(*dest_end, src, src_len);
  *dest_end += src_len;
  *dest_len -= src_len;
  return 1;
}

static char *
urlParse(char const *const url_in, char *anchor, char *new_path_seg, int new_path_seg_len, char *signed_seg,
         unsigned int signed_seg_len)
{
  char *segment[MAX_SEGMENTS];
  char url[8192]                     = {'\0'};
  unsigned char decoded_string[2048] = {'\0'};
  char new_url[8192]; /* new_url is not null_terminated */
  char *p = NULL, *sig_anchor = NULL, *saveptr = NULL;
  int i = 0, numtoks = 0, sig_anchor_seg = 0;
  size_t decoded_len = 0;

  strncat(url, url_in, sizeof(url) - strlen(url) - 1);

  char *new_url_end    = new_url;
  int new_url_len_left = sizeof(new_url);

  char *new_path_seg_end    = new_path_seg;
  int new_path_seg_len_left = new_path_seg_len;

  char *skip = strchr(url, ':');
  if (!skip || skip[1] != '/' || skip[2] != '/') {
    return NULL;
  }
  skip += 3;
  // preserve the scheme in the new_url.
  if (!fixedBufferWrite(&new_url_end, &new_url_len_left, url, skip - url)) {
    TSError("insufficient space to copy schema into new_path_seg buffer.");
    return NULL;
  }
  TSDebug(PLUGIN_NAME, "%s:%d - new_url: %.*s\n", __FILE__, __LINE__, (int)(new_url_end - new_url), new_url);

  // parse the url.
  if ((p = strtok_r(skip, "/", &saveptr)) != NULL) {
    segment[numtoks++] = p;
    do {
      p = strtok_r(NULL, "/", &saveptr);
      if (p != NULL) {
        segment[numtoks] = p;
        if (anchor != NULL && sig_anchor_seg == 0) {
          // look for the signed anchor string.
          if ((sig_anchor = strcasestr(segment[numtoks], anchor)) != NULL) {
            // null terminate this segment just before he signing anchor, this should be a ';'.
            *(sig_anchor - 1) = '\0';
            if ((sig_anchor = strstr(sig_anchor, "=")) != NULL) {
              *sig_anchor = '\0';
              sig_anchor++;
              sig_anchor_seg = numtoks;
            }
          }
        }
        numtoks++;
      }
    } while (p != NULL && numtoks < MAX_SEGMENTS);
  } else {
    return NULL;
  }
  if ((numtoks >= MAX_SEGMENTS) || (numtoks < 3)) {
    return NULL;
  }

  // create a new path string for later use when dealing with query parameters.
  // this string will not contain the signing parameters.  skips the fqdn by
  // starting with segment 1.
  for (i = 1; i < numtoks; i++) {
    // if no signing anchor is found, skip the signed parameters segment.
    if (sig_anchor == NULL && i == numtoks - 2) {
      // the signing parameters when no signature anchor is found, should be in the
      // last path segment so skip them.
      continue;
    }
    if (!fixedBufferWrite(&new_path_seg_end, &new_path_seg_len_left, segment[i], strlen(segment[i]))) {
      TSError("insufficient space to copy into new_path_seg buffer.");
      return NULL;
    }
    if (i != numtoks - 1) {
      if (!fixedBufferWrite(&new_path_seg_end, &new_path_seg_len_left, "/", 1)) {
        TSError("insufficient space to copy into new_path_seg buffer.");
        return NULL;
      }
    }
  }
  *new_path_seg_end = '\0';
  TSDebug(PLUGIN_NAME, "new_path_seg: %s", new_path_seg);

  // save the encoded signing parameter data
  if (sig_anchor != NULL) { // a signature anchor string was found.
    if (strlen(sig_anchor) < signed_seg_len) {
      memcpy(signed_seg, sig_anchor, strlen(sig_anchor));
    } else {
      TSError("insufficient space to copy into new_path_seg buffer.");
    }
  } else { // no signature anchor string was found, assume it is in the last path segment.
    if (strlen(segment[numtoks - 2]) < signed_seg_len) {
      memcpy(signed_seg, segment[numtoks - 2], strlen(segment[numtoks - 2]));
    } else {
      TSError("insufficient space to copy into new_path_seg buffer.");
      return NULL;
    }
  }
  TSDebug(PLUGIN_NAME, "signed_seg: %s", signed_seg);

  // no signature anchor was found so decode and save the signing parameters assumed
  // to be in the last path segment.
  if (sig_anchor == NULL) {
    if (TSBase64Decode(segment[numtoks - 2], strlen(segment[numtoks - 2]), decoded_string, sizeof(decoded_string), &decoded_len) !=
        TS_SUCCESS) {
      TSDebug(PLUGIN_NAME, "Unable to decode the  path parameter string.");
    }
  } else {
    if (TSBase64Decode(sig_anchor, strlen(sig_anchor), decoded_string, sizeof(decoded_string), &decoded_len) != TS_SUCCESS) {
      TSDebug(PLUGIN_NAME, "Unable to decode the  path parameter string.");
    }
  }
  TSDebug(PLUGIN_NAME, "decoded_string: %s", decoded_string);

  {
    int oob = 0; /* Out Of Buffer */

    for (i = 0; i < numtoks; i++) {
      // cp the base64 decoded string.
      if (i == sig_anchor_seg && sig_anchor != NULL) {
        if (!fixedBufferWrite(&new_url_end, &new_url_len_left, segment[i], strlen(segment[i]))) {
          oob = 1;
          break;
        }
        if (!fixedBufferWrite(&new_url_end, &new_url_len_left, (char *)decoded_string, strlen((char *)decoded_string))) {
          oob = 1;
          break;
        }
        if (!fixedBufferWrite(&new_url_end, &new_url_len_left, "/", 1)) {
          oob = 1;
          break;
        }

        continue;
      } else if (i == numtoks - 2 && sig_anchor == NULL) {
        if (!fixedBufferWrite(&new_url_end, &new_url_len_left, (char *)decoded_string, strlen((char *)decoded_string))) {
          oob = 1;
          break;
        }
        if (!fixedBufferWrite(&new_url_end, &new_url_len_left, "/", 1)) {
          oob = 1;
          break;
        }
        continue;
      }
      if (!fixedBufferWrite(&new_url_end, &new_url_len_left, segment[i], strlen(segment[i]))) {
        oob = 1;
        break;
      }
      if (i < numtoks - 1) {
        if (!fixedBufferWrite(&new_url_end, &new_url_len_left, "/", 1)) {
          oob = 1;
          break;
        }
      }
    }
    if (oob) {
      TSError("insufficient space to copy into new_url.");
    }
  }
  return TSstrndup(new_url, new_url_end - new_url);
}

TSRemapStatus
TSRemapDoRemap(void *ih, TSHttpTxn txnp, TSRemapRequestInfo *rri)
{
  const struct config *cfg = (const struct config *)ih;

  int url_len         = 0;
  int current_url_len = 0;
  uint64_t expiration = 0;
  int algorithm       = -1;
  int keyindex        = -1;
  int cmp_res;
  int rval;
  unsigned int i       = 0;
  int j                = 0;
  unsigned int sig_len = 0;
  bool has_path_params = false;

  /* all strings are locally allocated except url... about 25k per instance */
  char *const current_url = TSUrlStringGet(rri->requestBufp, rri->requestUrl, &current_url_len);
  char *url               = current_url;
  char path_params[8192] = {'\0'}, new_path[8192] = {'\0'};
  char signed_part[8192]           = {'\0'}; // this initializes the whole array and is needed
  char urltokstr[8192]             = {'\0'};
  char client_ip[INET6_ADDRSTRLEN] = {'\0'}; // chose the larger ipv6 size
  char ipstr[INET6_ADDRSTRLEN]     = {'\0'}; // chose the larger ipv6 size
  unsigned char sig[MAX_SIG_SIZE + 1];
  char sig_string[2 * MAX_SIG_SIZE + 1];


  int method_len = 0;
  const char* method = TSHttpHdrMethodGet(rri->requestBufp, rri->requestHdrp, &method_len);
  char* request_method = (char*) malloc(method_len * sizeof(char));
  strncpy(request_method, method, method_len);
  *(request_method + method_len) = '\0';

  for (int i = 0; i < cfg->method_num; i++) {
    if (strcmp(request_method, &(cfg->bypass_method[i])) == 0) {
      free(request_method);
      goto allow;
    }
  }

  if (current_url_len >= MAX_REQ_LEN - 1) {
    err_log(current_url, "Request Url string too long");
    goto deny;
  }

  if (cfg->pristine_url_flag) {
    TSMBuffer mbuf;
    TSMLoc ul;
    TSReturnCode rc = TSHttpTxnPristineUrlGet(txnp, &mbuf, &ul);
    if (rc != TS_SUCCESS) {
      TSError("[url_sig] Failed call to TSHttpTxnPristineUrlGet()");
      goto deny;
    }
    url = TSUrlStringGet(mbuf, ul, &url_len);
    if (url_len >= MAX_REQ_LEN - 1) {
      err_log(url, "Pristine URL string too long.");
      goto deny;
    }
  } else {
    url_len = current_url_len;
  }

  TSDebug(PLUGIN_NAME, "%s", url);

  if (cfg->regex) {
    const int offset = 0, options = 0;
    int ovector[30];

    /* Only search up to the first ? or # */
    const char *base_url_end = url;
    while (*base_url_end && !(*base_url_end == '?' || *base_url_end == '#')) {
      ++base_url_end;
    }
    const int len = base_url_end - url;

    if (pcre_exec(cfg->regex, cfg->regex_extra, url, len, offset, options, ovector, 30) >= 0) {
      goto allow;
    }
  }

  const char *query = strchr(url, '?');

  // check for path params.
  if (query == NULL || strstr(query, "timestamp=") == NULL) {
    char *const parsed = urlParse(url, cfg->sig_anchor, new_path, 8192, path_params, 8192);
    if (parsed == NULL) {
      err_log(url, "Unable to parse/decode new url path parameters");
      goto deny;
    }

    has_path_params = true;
    query           = strstr(parsed, ";");

    if (query == NULL) {
      err_log(url, "Has no signing query string or signing path parameters.");
      TSfree(parsed);
      goto deny;
    }

    if (url != current_url) {
      TSfree(url);
    }

    url = parsed;
  }

  /* first, parse the query string */
  if (!has_path_params) {
    query++; /* get rid of the ? */
  }
  TSDebug(PLUGIN_NAME, "Query string is:%s", query);

  // Client IP - this one is optional
  const char *cp = strstr(query, CIP_QSTRING "=");
  const char *pp = NULL;
  if (cp != NULL) {
    cp += (strlen(CIP_QSTRING) + 1);
    struct sockaddr const *ip = TSHttpTxnClientAddrGet(txnp);
    if (ip == NULL) {
      TSError("Can't get client ip address.");
      goto deny;
    } else {
      switch (ip->sa_family) {
      case AF_INET:
        TSDebug(PLUGIN_NAME, "ip->sa_family: AF_INET");
        has_path_params == false ? (pp = strstr(cp, "&")) : (pp = strstr(cp, ";"));
        if ((pp - cp) > INET_ADDRSTRLEN - 1 || (pp - cp) < 4) {
          err_log(url, "IP address string too long or short.");
          goto deny;
        }
        strncpy(client_ip, cp, (pp - cp));
        client_ip[pp - cp] = '\0';
        TSDebug(PLUGIN_NAME, "CIP: -%s-", client_ip);
        inet_ntop(AF_INET, &(((struct sockaddr_in *)ip)->sin_addr), ipstr, sizeof ipstr);
        TSDebug(PLUGIN_NAME, "Peer address: -%s-", ipstr);
        if (strcmp(ipstr, client_ip) != 0) {
          err_log(url, "Client IP doesn't match signature.");
          goto deny;
        }
        break;
      case AF_INET6:
        TSDebug(PLUGIN_NAME, "ip->sa_family: AF_INET6");
        has_path_params == false ? (pp = strstr(cp, "&")) : (pp = strstr(cp, ";"));
        if ((pp - cp) > INET6_ADDRSTRLEN - 1 || (pp - cp) < 4) {
          err_log(url, "IP address string too long or short.");
          goto deny;
        }
        strncpy(client_ip, cp, (pp - cp));
        client_ip[pp - cp] = '\0';
        TSDebug(PLUGIN_NAME, "CIP: -%s-", client_ip);
        inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)ip)->sin6_addr), ipstr, sizeof ipstr);
        TSDebug(PLUGIN_NAME, "Peer address: -%s-", ipstr);
        if (strcmp(ipstr, client_ip) != 0) {
          err_log(url, "Client IP doesn't match signature.");
          goto deny;
        }
        break;
      default:
        TSError("%s: Unknown address family %d", PLUGIN_NAME, ip->sa_family);
        goto deny;
        break;
      }
    }
  }

  // Expiration
  if (!cfg->ignore_expiry) {
    cp = strstr(query, EXP_QSTRING "=");
    if (cp != NULL) {
      cp += strlen(EXP_QSTRING) + 1;
      if (sscanf(cp, "%" SCNu64, &expiration) != 1 || (time_t)expiration < time(NULL)) {
        err_log(url, "Invalid expiration, or expired");
        goto deny;
      }
      TSDebug(PLUGIN_NAME, "Exp: %" PRIu64, expiration);
    } else {
      err_log(url, "Timestamp query string not found");
      goto deny;
    }
  }
  // Algorithm
  cp = strstr(query, ALG_QSTRING "=");
  if (cp != NULL) {
    cp += strlen(ALG_QSTRING) + 1;
    algorithm = atoi(cp);
    // The check for a valid algorithm is later.
    TSDebug(PLUGIN_NAME, "Algorithm: %d", algorithm);
  } else {
    if (cfg->algorithm != 0) {
      algorithm = cfg->algorithm;
    } else {
      algorithm = 2;
    }
    TSDebug(PLUGIN_NAME, "Algorithm default: %d", algorithm);
  }
  // Key index
  cp = strstr(query, KIN_QSTRING "=");
  if (cp != NULL) {
    cp += strlen(KIN_QSTRING) + 1;
    keyindex = atoi(cp);
    if (keyindex < 0 || keyindex >= MAX_KEY_NUM || 0 == cfg->keys[keyindex][0]) {
      err_log(url, "Invalid key index");
      goto deny;
    }
    TSDebug(PLUGIN_NAME, "Key Index: %d", keyindex);
  } else {
    keyindex = cfg->knumber;
    if (keyindex < 0 || keyindex >= MAX_KEY_NUM || 0 == cfg->keys[keyindex][0]) {
      err_log(url, "Invalid key index");
      goto deny;
    }
    TSDebug(PLUGIN_NAME, "Key Index default: %d", keyindex);
  }
  // Parts
  const char *parts = NULL;
  cp                = strstr(query, PAR_QSTRING "=");
  if (cp != NULL) {
    cp += strlen(PAR_QSTRING) + 1;
    parts = cp; // NOTE parts is not NULL terminated it is terminated by "&" of next param
    has_path_params == false ? (cp = strstr(parts, "&")) : (cp = strstr(parts, ";"));
    if (cp) {
      TSDebug(PLUGIN_NAME, "Parts: %.*s", (int)(cp - parts), parts);
    } else {
      TSDebug(PLUGIN_NAME, "Parts: %s", parts);
    }
  } else {
    if (cfg->use_parts != NULL) {
      TSDebug(PLUGIN_NAME, "Use parts: %s", cfg->use_parts);
      parts = cfg->use_parts;
    } else {
      parts = "0011";
    }
    has_path_params == false ? (cp = strstr(parts, "&")) : (cp = strstr(parts, ";"));
    if (cp) {
      TSDebug(PLUGIN_NAME, "Parts default: %.*s", (int)(cp - parts), parts);
    } else {
      TSDebug(PLUGIN_NAME, "Parts default: %s", parts);
    }
  }
  // And finally, the sig (has to be last)
  const char *signature = NULL;
  cp                    = strstr(query, SIG_QSTRING "=");
  if (cp != NULL) {
    cp += strlen(SIG_QSTRING) + 1;
    signature = cp;
    if ((algorithm == USIG_HMAC_SHA1 && strlen(signature) < SHA1_SIG_SIZE) ||
        (algorithm == USIG_HMAC_MD5 && strlen(signature) < MD5_SIG_SIZE)) {
      err_log(url, "Token query string too short (< 20)");
      goto deny;
    }
  } else {
    err_log(url, "Token query string not found");
    goto deny;
  }

  /* have the query string, and parameters passed initial checks */
  TSDebug(PLUGIN_NAME, "Found all needed parameters: C=%s E=%" PRIu64 " A=%d K=%d P=%s S=%s", client_ip, expiration, algorithm,
          keyindex, parts, signature);

  /* find the string that was signed - cycle through the parts letters, adding the part of the fqdn/path if it is 1 */
  has_path_params == false ? (cp = strchr(url, '?')) : (cp = strchr(url, ';'));
  // Skip scheme and initial forward slashes.
  const char *skip = strchr(url, ':');
  if (!skip || skip[1] != '/' || skip[2] != '/') {
    goto deny;
  }
  skip += 3;
  memcpy(urltokstr, skip, cp - skip);
  char *strtok_r_p;

  const char *part = strtok_r(urltokstr, "/", &strtok_r_p);
  while (part != NULL) {
    if (parts[j] == '1') {
      strncat(signed_part, part, sizeof(signed_part) - strlen(signed_part) - 1);
      strncat(signed_part, "/", sizeof(signed_part) - strlen(signed_part) - 1);
    }
    if (parts[j + 1] == '0' ||
        parts[j + 1] == '1') { // This remembers the last part, meaning, if there are no more valid letters in parts
      j++;                     // will keep repeating the value of the last one
    }
    part = strtok_r(NULL, "/", &strtok_r_p);
  }

  // chop off the last /, replace with '?' or ';' as appropriate.
  has_path_params == false ? (signed_part[strlen(signed_part) - 1] = '?') : (signed_part[strlen(signed_part) - 1] = '\0');
  char* query_params[sizeof(cfg->hash_query_param)];
  char* delimeterParam;
  for (int i = 0; i < cfg->paramNum; i++) {
    TSDebug(PLUGIN_NAME, "Hash parameter %d: %s", i, cfg->hash_query_param[i]);
    query_params[i] = strstr(query, cfg->hash_query_param[i]);
    if (query_params[i] == NULL) {
      err_log(url, "Missing hash parameter");
      goto deny;
    }
    delimeterParam = strstr(query_params[i], "&");
    TSDebug(PLUGIN_NAME, "Pointer query param: %s", query_params[i]);
    TSDebug(PLUGIN_NAME, "Delimeter: %s", delimeterParam);
    if (i == cfg-> paramNum - 1) {
      strncat(signed_part, query_params[i], (delimeterParam - query_params[i]));
    } else {
      strncat(signed_part, query_params[i], (delimeterParam - query_params[i]) + 1);
    }
    TSDebug(PLUGIN_NAME, "Signed string: %s", signed_part);
  }
  cp = strstr(query, SIG_QSTRING "=");
  TSDebug(PLUGIN_NAME, "cp: %s, query: %s, signed_part: %s", cp, query, signed_part);
  /* strncat(signed_part, query, (cp - query) + strlen(SIG_QSTRING) + 1); */
  TSDebug(PLUGIN_NAME, "Signed string=\"%s\"", signed_part);

  /* calculate the expected the signature with the right algorithm */
  switch (algorithm) {
  case USIG_HMAC_SHA1:
    HMAC(EVP_sha1(), (const unsigned char *)cfg->keys[keyindex], strlen(cfg->keys[keyindex]), (const unsigned char *)signed_part,
         strlen(signed_part), sig, &sig_len);
    if (sig_len != SHA1_SIG_SIZE) {
      TSDebug(PLUGIN_NAME, "sig_len: %d", sig_len);
      err_log(url, "Calculated sig len !=  SHA1_SIG_SIZE !");
      goto deny;
    }

    break;
  case USIG_HMAC_MD5:
    HMAC(EVP_md5(), (const unsigned char *)cfg->keys[keyindex], strlen(cfg->keys[keyindex]), (const unsigned char *)signed_part,
         strlen(signed_part), sig, &sig_len);
    if (sig_len != MD5_SIG_SIZE) {
      TSDebug(PLUGIN_NAME, "sig_len: %d", sig_len);
      err_log(url, "Calculated sig len !=  MD5_SIG_SIZE !");
      goto deny;
    }
    break;
  default:
    err_log(url, "Algorithm not supported");
    goto deny;
  }

  for (i = 0; i < sig_len; i++) {
    sprintf(&(sig_string[i * 2]), "%02x", sig[i]);
  }

  TSDebug(PLUGIN_NAME, "Expected signature: %s", sig_string);

  /* and compare to signature that was sent */
  cmp_res = strncmp(sig_string, signature, sig_len * 2);
  if (cmp_res != 0) {
    err_log(url, "Signature check failed");
    goto deny;
  } else {
    TSDebug(PLUGIN_NAME, "Signature check passed");
    goto allow;
  }

/* ********* Deny ********* */
deny:
  if (url != current_url) {
    TSfree((void *)url);
  }
  TSfree((void *)current_url);

  switch (cfg->err_status) {
  case TS_HTTP_STATUS_MOVED_TEMPORARILY:
    TSDebug(PLUGIN_NAME, "Redirecting to %s", cfg->err_url);
    char *start, *end;
    start = cfg->err_url;
    end   = start + strlen(cfg->err_url);
    if (TSUrlParse(rri->requestBufp, rri->requestUrl, (const char **)&start, end) != TS_PARSE_DONE) {
      err_log("url", "Error inn TSUrlParse!");
    }
    rri->redirect = 1;
    break;
  default:
    TSHttpTxnErrorBodySet(txnp, TSstrdup("Authorization Denied"), sizeof("Authorization Denied") - 1, TSstrdup("text/plain"));
    break;
  }
  /* Always set the return status */
  TSHttpTxnStatusSet(txnp, cfg->err_status);

  return TSREMAP_DID_REMAP;

/* ********* Allow ********* */
allow:
  if (url != current_url) {
    TSfree((void *)url);
  }
  TSDebug(PLUGIN_NAME, "Current URL %s", current_url);
  const char *current_query = strchr(current_url, '?');
  const char *app_qry       = NULL;
  if (current_query != NULL) {
    current_query++;
    app_qry = getAppQueryString(cfg, current_query, strlen(current_query), current_url);
    TSDebug(PLUGIN_NAME, "Current query: %s", app_qry);
  }
  TSDebug(PLUGIN_NAME, "has_path_params: %d", has_path_params);
  if (has_path_params) {
    if (*new_path) {
      TSUrlPathSet(rri->requestBufp, rri->requestUrl, new_path, strlen(new_path));
    }
    TSUrlHttpParamsSet(rri->requestBufp, rri->requestUrl, NULL, 0);
  }

  TSfree((void *)current_url);

  /* drop the query string so we can cache-hit */
  if (app_qry != NULL) {
    rval = TSUrlHttpQuerySet(rri->requestBufp, rri->requestUrl, app_qry, strlen(app_qry));
    TSfree((void *)app_qry);
  } else {
    rval = TSUrlHttpQuerySet(rri->requestBufp, rri->requestUrl, NULL, 0);
  }
  if (rval != TS_SUCCESS) {
    TSError("[url_sig] Error setting the query string: %d", rval);
  }

  return TSREMAP_NO_REMAP;
}
