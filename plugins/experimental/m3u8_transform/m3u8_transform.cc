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
#include <cstring>
#include <cctype>
#include <vector>
#include <iostream>
#include <sstream>
#include <regex>
#include <string>
#include <set>

#include "ink_autoconf.h"
#include "ts/ts.h"
#include "tscore/ink_defs.h"
#include "util.cc"
#include "url_operation.cc"

#define PLUGIN_NAME "m3u8_transform"
#define USIG_HMAC_SHA1 1
#define USIG_HMAC_MD5 2
#define SHA1_SIG_SIZE 20
#define MD5_SIG_SIZE 16
#define MAX_SIG_SIZE 20

#define ASSERT_SUCCESS(_x) TSAssert((_x) == TS_SUCCESS)
#define MAX_FILE_LENGTH 100000
#define MAX_URL_LEN 1024
#define MAX_REQ_LEN 8192
#define MAX_KEY_LEN 256
#define MAX_KEY_NUM 16
#define MAX_USE_PARTS_LEN 10
#define MAX_QUERY_LEN 4096
#define MAX_HASH_QUERY_PARAM_NUM 16
#define MAX_HASH_QUERY_LEN 256
#define GZIP_MAGIC_0    0x1F
#define GZIP_MAGIC_1    0x8B
#define GZIP_METHOD     0x08
using namespace std;

struct Config {
  vector<string> keys;
  vector<string> hash_query_param;
  int param_num;
  string use_parts;
  int algorithm;  
  int knumber;
  set<string> origin_param;
};

struct ContData {
  TSVIO output_vio;
  TSIOBuffer output_buffer;
  TSIOBufferReader output_reader;
  string prefix;
  int prefix_length;
  string query_string;
  int query_string_length;
  int file_data;
  Config* config;
};

ContData* my_data_alloc_with_url(string prefix, int prefix_length, string query_string, int query_string_length, Config* cfg) {
  ContData *data = new ContData();
  data->output_vio    = nullptr;
  data->output_buffer = nullptr;
  data->output_reader = nullptr;
  data->prefix = prefix;
  data->prefix_length = prefix_length;
  data->query_string = query_string;
  data->query_string_length = query_string_length;
  data->file_data = 0;
  data->config = cfg;
  return data;
}

void my_data_destroy(ContData* data) {
  if (data) {
    if (data->output_buffer) {
      TSIOBufferDestroy(data->output_buffer);
    }
    delete data;
  }
}

void free_cfg(Config* cfg) {
  TSDebug(PLUGIN_NAME, "Cleaning up config");
  delete cfg;
}

char* strnstr(const char* s, const char* find, size_t slen) {
  char c, sc;
  size_t len;
  if ((c = *find++) != '\0') {
    len = strlen(find);
    do {
      do {
        if (slen-- < 1 || (sc = *s++) == '\0')
          return (nullptr);
      } while (sc != c);
      if (len > slen)
        return (nullptr);
    } while (strncmp(s, find, len) != 0);
    s--;
  }
  return (char*)s;
}



// Verify request is m3u8 file and get prefix and query_string of request URL
// TODO: Verify host is IP or domain, port is 80, 443 or not
bool verify_request_url(TSHttpTxn txnp, string& prefix, int* prefix_length, string& query_string, int* query_string_length, set<string> origin_param) {
  TSMBuffer buf;
  TSMLoc loc;
  if (TS_SUCCESS == TSHttpTxnClientReqGet(txnp, &buf, &loc)) {
    TSMLoc url_loc;
    if (TS_SUCCESS == TSHttpHdrUrlGet(buf, loc, &url_loc)) {
      int path_length = 0;
      const char* path = TSUrlPathGet(buf, url_loc, &path_length);
      string path_str(path, path_length);
      // Transform only request file .m3u8
      if (path_str.find(".m3u8") == string::npos) {
        ASSERT_SUCCESS(TSHandleMLocRelease(buf, loc, url_loc));
        ASSERT_SUCCESS(TSHandleMLocRelease(buf, TS_NULL_MLOC, loc));
        TSDebug(PLUGIN_NAME, "Path %s will not transform", path_str.c_str());
        return false;
      }

      TSDebug(PLUGIN_NAME, "Path %s will transform", path_str.c_str());
      int scheme_length = 0;
      const char* scheme = TSUrlSchemeGet(buf, url_loc, &scheme_length);
      string scheme_str(scheme, scheme_length);
      int query_param_length = 0;
      const char* query_param = TSUrlHttpQueryGet(buf, url_loc, &query_param_length);
      string query_param_str(query_param, query_param_length);
      TSDebug(PLUGIN_NAME, "Query param: %s", query_param);
      TSMLoc remap_loc;
      prefix = prefix + scheme_str + "://";
      *(prefix_length) = *(prefix_length) + scheme_length + 3;

      // Get host from remap.config 
      if (TS_SUCCESS == TSRemapFromUrlGet(txnp, &remap_loc)) {
        int host_length = 0;
        const char* host = TSUrlHostGet(buf, remap_loc, &host_length);
        string host_str(host, host_length);
        int port = TSUrlRawPortGet(buf, remap_loc);
        prefix += host_str;
        *(prefix_length) = *(prefix_length) + host_length;
        if (port > 0) {
          string port_string = to_string(port);
          prefix += ":" + to_string(port);
          *(prefix_length) = *(prefix_length) + port_string.size() + 1;
        }
        ASSERT_SUCCESS(TSHandleMLocRelease(buf, TS_NULL_MLOC, remap_loc));
      } else {
        // Get host from request if not found corresponding remap config 
        int host_length = 0;
        const char* host = TSHttpHdrHostGet(buf, loc, &host_length);
        string host_str(host, host_length);
        size_t end_host_pos = host_str.find("\r");
        if (end_host_pos != string::npos) {
            host_str = host_str.substr(0, end_host_pos);
        }
        host_length = end_host_pos;
        prefix = prefix + host_str;
        *(prefix_length) = *(prefix_length) + host_length;
      }
  
      // Remove file name from prefix
      prefix = prefix + "/" + remove_filename_from_path(path_str, &path_length);
      *(prefix_length) = *(prefix_length) + 1 + path_length;

      // Remove parameter that not process in origin, append those parameter to every link in m3u8 file later
      query_string = optimize_query_param(query_param_str, query_string_length, origin_param, buf, url_loc);

      ASSERT_SUCCESS(TSHandleMLocRelease(buf, loc, url_loc));
      ASSERT_SUCCESS(TSHandleMLocRelease(buf, TS_NULL_MLOC, loc));
      TSDebug(PLUGIN_NAME, "Prefix URL: %s", prefix.c_str());
      TSDebug(PLUGIN_NAME, "Query param string: %s", query_string.c_str());
      return true;
    }
  }
  TSDebug(PLUGIN_NAME, "Cannot get request");
  ASSERT_SUCCESS(TSHandleMLocRelease(buf, TS_NULL_MLOC, loc));
  return false;
}


extern "C" {
  bool
  generate_token(const char* url, Config* cfg, unsigned char* token, unsigned int* token_length) {
    const char *query = strchr(url, '?');
    char signed_part[MAX_URL_LEN] = {'\0'};
    char urltokstr[MAX_URL_LEN] = {'\0'};
    const char* cp = strchr(url, '?');
    int j = 0;
    TSDebug(PLUGIN_NAME, "Url: %s", url);
    // Skip scheme and initial forward slashes.
    const char *skip = strchr(url, ':');
    if (!skip || skip[1] != '/' || skip[2] != '/' || cp == NULL) {
      return false;
    }
    skip += 3;
    memcpy(urltokstr, skip, cp - skip);
    char *strtok_r_p;
    const char *part = strtok_r(urltokstr, "/", &strtok_r_p);
    while (part != NULL) {
      if (cfg->use_parts[j] == '1') {
        strncat(signed_part, part, sizeof(signed_part) - strlen(signed_part) - 1);
        strncat(signed_part, "/", sizeof(signed_part) - strlen(signed_part) - 1);
      }
      if (cfg->use_parts[j + 1] == '0' ||
          cfg->use_parts[j + 1] == '1') { // This remembers the last part, meaning, if there are no more valid letters in parts
        j++;                     // will keep repeating the value of the last one
      }
      part = strtok_r(NULL, "/", &strtok_r_p);
    }


    // chop off the last /, replace with '?' or ';' as appropriate.
    signed_part[strlen(signed_part) - 1] = '?';
    const char* query_params[sizeof(cfg->hash_query_param)];
    const char* delimeterParam;
    for (int i = 0; i < cfg->param_num; i++) {
      query_params[i] = strstr(query, cfg->hash_query_param[i].c_str());
      if (query_params[i] == NULL) {
        TSError("Missing hash parameter of %s", url);
        return false;
      }
      delimeterParam = strstr(query_params[i], "&");
      if (i == cfg-> param_num - 1) {
        strncat(signed_part, query_params[i], (delimeterParam - query_params[i]));
      } else {
        strncat(signed_part, query_params[i], (delimeterParam - query_params[i]) + 1);
      }
    }
    // signed_part[strlen(signed_part)] = '\0';
    TSDebug(PLUGIN_NAME, "Signed string=\"%s\"", signed_part);
    switch (cfg->algorithm) {
    case USIG_HMAC_SHA1:
      HMAC(EVP_sha1(), (const unsigned char *)(cfg->keys[cfg->knumber]).c_str(), (cfg->keys[cfg->knumber]).size(), (const unsigned char *)signed_part,
          strlen(signed_part), token, token_length);
      if ((*token_length) != SHA1_SIG_SIZE) {
        TSError("Calculated sig len of %s !=  SHA1_SIG_SIZE !", url);
        return false;
      }
      return true;
    case USIG_HMAC_MD5:
      HMAC(EVP_md5(), (const unsigned char *)(cfg->keys[cfg->knumber]).c_str(), (cfg->keys[cfg->knumber]).size(), (const unsigned char *)signed_part,
          strlen(signed_part), token, token_length);
      // HMAC(EVP_md5(), (const unsigned char *)"px0KnwI_hxaS8uNzLOUZw6lVuBqVggJH", 32, (const unsigned char *) "10.61.129.17:8080/file/index.m3u8?timestamp=2526689025",
      //      54, token, token_length);
      if ((*token_length) != MD5_SIG_SIZE) {
        TSError("Calculated sig len of %s !=  MD5_SIG_SIZE !", url);
        return false;
      }
      return true;
    default:
      TSError("Algorithm not supported: %d", cfg->algorithm);
      return false;
    }
    signed_part[0] = '\0';
  }
}

string add_token_and_prefix(const string& file_data, Config* cfg, const string& prefix, const string& query_string, int* data_size) {
    string result;
    istringstream stream(file_data);
    string line;
    while (getline(stream, line)) {
      if (line.back() == '\n') {
        line.pop_back();
      }
      TSDebug("PLUGIN_NAME", "LINE: %s (%lu)", line.c_str(), line.length());
      if (line[0] != '#') {
        if (line.find(".ts") != string::npos || line.find(".m3u8") != string::npos || line.find(".m4s") != string::npos || line.find(".mp4") != string::npos) {
          string url = prefix + line;
          if (!query_string.empty()) {
            if (url.find('?') != string::npos) {
                url += "&";
            } else {
              url += "?";
            }
            url += query_string;
          }
          result += url;
          unsigned char token[MAX_SIG_SIZE + 1] = {'\0'};
          unsigned int token_length = 0;
          bool is_success = generate_token(url.c_str(), cfg, token, &token_length);
          if (is_success) {
            result += "&token=";
            for (unsigned int i = 0; i < token_length; i++) {
                char buffer[3];
                sprintf(buffer, "%02x", token[i]);
                result += buffer;
            }
          }
        } else {
          result += line;
        }
      } else {
        size_t uri_pos = line.find("URI=\"");
        if (uri_pos != string::npos) {
          size_t next_quote_pos = line.find("\"", uri_pos + 5);
          if (next_quote_pos != string::npos) {
            string url = prefix + line.substr(uri_pos + 5, next_quote_pos - uri_pos - 5);
            if (!query_string.empty()) {
              if (url.find('?') != string::npos) {
                  url += "&";
              } else {
                url += "?";
              }
              url += query_string;
            }
            result += line.substr(0, uri_pos + 5) + url;
            unsigned char token[MAX_SIG_SIZE + 1] = {'\0'};
            unsigned int token_length = 0;
            bool is_success = generate_token(url.c_str(), cfg, token, &token_length);
            if (is_success) {
              result += "&token=";
              for (unsigned int i = 0; i < token_length; i++) {
                char buffer[3];
                sprintf(buffer, "%02x", token[i]);
                result += buffer;
              }
            }
            result += line.substr(next_quote_pos);
          } else {
            result += line;
          }
        } else {
          result += line;
        }
      }
      if (!stream.eof()) {
        result += "\n";
      }
    }
    return result;
}


static void
handle_transform_m3u8(TSCont contp)
{
  TSVConn output_conn;
  TSVIO write_vio;
  ContData *data;
  int64_t towrite;

  /* Get the output connection where we'll write data to. */
  output_conn = TSTransformOutputVConnGet(contp);

  /* Get the write VIO for the write operation that was performed on
     ourself. This VIO contains the buffer that we are to read from
     as well as the continuation we are to call when the buffer is
     empty. */
  write_vio = TSVConnWriteVIOGet(contp);

  /* Get our data structure for this operation. The private data
     structure contains the output VIO and output buffer. If the
     private data structure pointer is NULL, then we'll create it
     and initialize its internals. */
  data = static_cast<ContData*> (TSContDataGet(contp));
  if (!data) {
    towrite = TSVIONBytesGet(write_vio);
    data                = my_data_alloc_with_url("", 0,"", 0, NULL);
    data->output_buffer = TSIOBufferCreate();
    data->output_reader = TSIOBufferReaderAlloc(data->output_buffer);
    data->output_vio    = TSVConnWrite(output_conn, contp, data->output_reader, towrite);
    TSContDataSet(contp, data);
  } else if (data->output_vio == NULL) {
    towrite = TSVIONBytesGet(write_vio);
    data->output_buffer = TSIOBufferCreate();
    data->output_reader = TSIOBufferReaderAlloc(data->output_buffer);
    data->output_vio    = TSVConnWrite(output_conn, contp, data->output_reader, towrite);
  }

  /* We also check to see if the write VIO's buffer is non-NULL. A
     NULL buffer indicates that the write operation has been
     shutdown and that the continuation does not want us to send any
     more WRITE_READY or WRITE_COMPLETE events. For this simplistic
     transformation that means we're done. In a more complex
     transformation we might have to finish writing the transformed
     data to our output connection. */
  if (!TSVIOBufferGet(write_vio)) {
    // TSVIONBytesSet(data->output_vio, TSVIONDoneGet(write_vio));
    // TSVIOReenable(data->output_vio);
    
    TSVIONBytesSet(data->output_vio, data->file_data);
    TSVIOReenable(data->output_vio);

    return;
  }

  /* Determine how much data we have left to read. For this append
     transform plugin this is also the amount of data we have left
     to write to the output connection. */
  towrite = TSVIONTodoGet(write_vio);
  // unsigned char* file_data = (unsigned char*) malloc(towrite + 1);
  char* file_data = (char*) malloc(towrite + 1);
  TSIOBufferReaderCopy(TSVIOReaderGet(write_vio), file_data, towrite);
  *(file_data + towrite) = '\0';
  TSDebug(PLUGIN_NAME, "Data length: %ld", towrite);
  TSDebug(PLUGIN_NAME, "Data file: %s and data length: %ld", file_data, strlen(file_data));
  // free(file_data);
  // if (towrite > 0) {
  //   /* The amount of data left to read needs to be truncated by
  //      the amount of data actually in the read buffer. */
  //   int64_t avail = TSIOBufferReaderAvail(TSVIOReaderGet(write_vio));
  //   TSDebug(PLUGIN_NAME, "Towrite: %ld", towrite);
  //   TSDebug(PLUGIN_NAME, "Avail: %ld", avail);
  //   if (towrite > avail) {
  //     towrite = avail;
  //   }
  //   if (towrite > 0) {
  //     /* Copy the data from the read buffer to the output buffer. */
  //     TSIOBufferCopy(data->output_buffer, TSVIOReaderGet(write_vio), towrite, 0);

      /* Tell the read buffer that we have read the data and are no
         longer interested in it. */
      TSIOBufferReaderConsume(TSVIOReaderGet(write_vio), towrite);

      /* Modify the write VIO to reflect how much data we've
         completed. */
      TSVIONDoneSet(write_vio, towrite);
  //   }
  // }

  /* Now we check the write VIO to see if there is data left to
     read. */
  // if (TSVIONTodoGet(write_vio) > 0) {
  //   if (towrite > 0) {
  //     /* If there is data left to read, then we reenable the output
  //        connection by reenabling the output VIO. This will wakeup
  //        the output connection and allow it to consume data from the
  //        output buffer. */
  //     TSVIOReenable(data->output_vio);

  //     /* Call back the write VIO continuation to let it know that we
  //        are ready for more data. */
  //     TSContCall(TSVIOContGet(write_vio), TS_EVENT_VCONN_WRITE_READY, write_vio);
  //   }
  // } else {
    /* If there is no data left to read, then we modify the output
       VIO to reflect how much data the output connection should
       expect. This allows the output connection to know when it
       is done reading. We then reenable the output connection so
       that it can consume the data we just gave it. */
    TSDebug(PLUGIN_NAME, "Request prefix: %s", data->prefix.c_str());
    TSDebug(PLUGIN_NAME, "Request query string: %s", data->query_string.c_str());
    TSDebug(PLUGIN_NAME, "Write length: %ld", TSVIONDoneGet(write_vio));
    TSDebug(PLUGIN_NAME, "Read length: %ld",TSIOBufferReaderAvail(data->output_reader));
    int data_size = TSVIONDoneGet(write_vio);
    
    /* Copy file data from buffer*/
    // TSIOBufferReaderCopy(data->output_reader, file_data, data_size);
    // TSDebug(PLUGIN_NAME, "File data: %s", file_data);
    // bool is_gzip = is_gzip_data(file_data, data_size);
    // if (is_gzip) {
    //   file_data = unzip_file_data(file_data, &data_size);
    //   TSDebug(PLUGIN_NAME, "Unzip data: %s", file_data);
    //   TSDebug(PLUGIN_NAME, "Data size after unzip: %d", data_size);
    // } 
        
    /* Add token and prefix to every link in file*/
    string result = add_token_and_prefix(file_data, data->config, data-> prefix,  data-> query_string, &data_size);
    data_size = result.size();
    TSDebug(PLUGIN_NAME, "Length of text: %d", data_size);
    TSDebug(PLUGIN_NAME, "File after transform: %s", result.c_str());
    // if (is_gzip) {
    //   result = gzip_data(result, &data_size);
    //   TSDebug(PLUGIN_NAME, "File after gzip: %s", result);
    //   TSDebug(PLUGIN_NAME, "File size after gzip: %d", data_size);
    // }

    /* Remove all data from reader and add content of file after tranform to reader*/
    TSIOBufferReaderConsume(data->output_reader, TSIOBufferReaderAvail(data->output_reader));
    TSIOBufferWrite(data->output_buffer, result.c_str(), data_size);
    free(file_data);
    TSVIONBytesSet(data->output_vio, data_size);
    data->file_data = data_size;
    // TSVIONBytesSet(data->output_vio, TSVIONDoneGet(write_vio));

    TSVIOReenable(data->output_vio);

    /* Call back the write VIO continuation to let it know that wek
       have completed the write operation. */
    TSContCall(TSVIOContGet(write_vio), TS_EVENT_VCONN_WRITE_COMPLETE, write_vio);
  // }
}

static bool
transformable(TSHttpTxn txnp)
{
  TSMBuffer bufp;
  TSMLoc hdr_loc;

  if (TS_SUCCESS == TSHttpTxnServerRespGet(txnp, &bufp, &hdr_loc)) {
    TSHttpStatus status = TSHttpHdrStatusGet(bufp, hdr_loc);
    TSDebug(PLUGIN_NAME, "Status code of request: %d", status);

    if (TS_HTTP_STATUS_OK == status || TS_HTTP_STATUS_PARTIAL_CONTENT == status) {
      ASSERT_SUCCESS(TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc));
      return true;
    } else {
      ASSERT_SUCCESS(TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc));
      return false;
    }
  }

  return false; /* not a 200 */
}

static int
transform_data(TSCont contp, TSEvent event, void *edata ATS_UNUSED)
{
  /* Check to see if the transformation has been closed by a call to
     TSVConnClose. */
  if (TSVConnClosedGet(contp)) {
    my_data_destroy(static_cast<ContData*> (TSContDataGet(contp)));
    TSContDestroy(contp);
    return 0;
  } else {
    switch (event) {
    // case TS_EVENT_HTTP_READ_RESPONSE_HDR: {
    //   TSHttpTxn txnp = (TSHttpTxn) edata;
    //   if (transformable(txnp)) {
    //     TSHttpTxnHookAdd(txnp, TS_HTTP_RESPONSE_TRANSFORM_HOOK, contp);
    //   }
    // } break;
    case TS_EVENT_ERROR: {
      TSVIO write_vio;

      /* Get the write VIO for the write operation that was
         performed on ourself. This VIO contains the continuation of
         our parent transformation. */
      write_vio = TSVConnWriteVIOGet(contp);

      /* Call back the write VIO continuation to let it know that we
         have completed the write operation. */
      TSContCall(TSVIOContGet(write_vio), TS_EVENT_ERROR, write_vio);
    } break;
    case TS_EVENT_VCONN_WRITE_COMPLETE:
      /* When our output connection says that it has finished
         reading all the data we've written to it then we should
         shutdown the write portion of its connection to
         indicate that we don't want to hear about it anymore. */
      TSVConnShutdown(TSTransformOutputVConnGet(contp), 0, 1);
      break;
    case TS_EVENT_VCONN_WRITE_READY:
    default:
      /* If we get a WRITE_READY event or any other type of
         event (sent, perhaps, because we were reenabled) then
         we'll attempt to transform more data. */
      handle_transform_m3u8(contp);
      break;
    }
  }

  return 0;
}

static int
transform_m3u8_if_needed(TSCont contp, TSEvent event, void *edata) {
  TSHttpTxn txnp = (TSHttpTxn) edata;
  switch (event) {
  case TS_EVENT_HTTP_CACHE_LOOKUP_COMPLETE: {
    int obj_status = -1;
    if (TS_ERROR != TSHttpTxnCacheLookupStatusGet(txnp, &obj_status) && (TS_CACHE_LOOKUP_HIT_FRESH == obj_status)) {
      TSHttpTxnUntransformedRespCache(txnp, 1);
      TSHttpTxnTransformedRespCache(txnp, 0);
      TSVConn connp;
      connp = TSTransformCreate(transform_data, txnp);
      ContData *data =static_cast<ContData*> (TSContDataGet(contp));
      TSContDataSet(connp, data);
      TSHttpTxnHookAdd(txnp, TS_HTTP_RESPONSE_TRANSFORM_HOOK, connp);
    } else {
      TSHttpTxnHookAdd(txnp, TS_HTTP_READ_RESPONSE_HDR_HOOK, contp);
    }
  }
    break;
  case TS_EVENT_HTTP_READ_RESPONSE_HDR:
    if (transformable(txnp)) {
      TSHttpTxnUntransformedRespCache(txnp, 1);
      TSHttpTxnTransformedRespCache(txnp, 0);
      TSVConn connp;
      connp = TSTransformCreate(transform_data, txnp);
      ContData *data =static_cast<ContData*> (TSContDataGet(contp));
      TSContDataSet(connp, data);
      TSHttpTxnHookAdd(txnp, TS_HTTP_RESPONSE_TRANSFORM_HOOK, connp);
    } 
    break;
  case TS_EVENT_HTTP_TXN_CLOSE:
    TSContDestroy(contp);
    break;
  default:
    break;
  }
  TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
  return 0;
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
  const char *config_file = nullptr;

  if (argc > 4) {
    TSError("The m3u8 transform plugin does not accept more than one plugin argument");
  } else {
    config_file = TSstrdup(3 == argc ? argv[2] : "");
  }
  TSDebug(PLUGIN_NAME, "config file name: %s", config_file);
  string pathstring(config_file);

  // If we have a path and it's not an absolute path, make it relative to the
  // configuration directory.
  if (!pathstring.empty() && pathstring[0] != '/') {
    pathstring.assign(TSConfigDirGet());
    pathstring.append("/");
    pathstring.append(config_file);
  }

  config_file = pathstring.c_str();
  ifstream file(config_file, std::ios::in);
  if (!file.is_open()) {
    TSError("File config %s not found", config_file);
    return TS_ERROR;
  }
  int line_no = 0;
  int keynum;
  int param_num = 0;
  bool eat_comment = false;
  Config *cfg = new Config();
  
  while (!file.eof()) {
    string line;
    getline(file, line);
    line_no++;
    TSDebug(PLUGIN_NAME, "Line number %d: %s with line length %ld", line_no, line.c_str(), line.length());
     if (line.empty()) {
      continue;
    }
    if (eat_comment) {
       // Check if final char is EOL, if so we are done eating
      if (line.back() == '\n') {
        eat_comment = false;
      }
      continue;
    }
    if (line[0] == '#' || line.length() <= 1) {
      if (line.back() != '\n') {
        eat_comment = true;
      }
      continue;
    }
    auto pos = line.find('=');
    if (pos == string::npos) {
      TSError("[m3u8_transform] Error parsing line %d of file %s (%s)", line_no, config_file, line.c_str());
      continue;
    }
    string key = line.substr(0, pos);
    string value = line.substr(pos + 1);
    trim_if(value, isspace);
    trim_if(key, isspace);
    if (value.back() == '\n') {
      value.pop_back();
    }
    if (key.substr(0, 3) == "key") {
      keynum = stoi(key.substr(3, 1));
      TSDebug(PLUGIN_NAME, "Key number %d: %s, value: %s", keynum, key.c_str(), value.c_str());
      if (keynum >= MAX_KEY_NUM || keynum < 0) {
        delete cfg;
        return TS_ERROR;
      }
      cfg->keys.push_back(value);
    } else if (key == "hash_query_param") {
      istringstream param_stream(value);
      string param;
      while (getline(param_stream, param, ',')) {
        TSDebug(PLUGIN_NAME, "Hash param number %d: %s", param_num, param.c_str());
        cfg->hash_query_param.push_back(param);
        param_num++;
      }
      cfg->param_num = param_num;
    } else if (key == "use_parts") {
      cfg->use_parts = value;
      TSDebug(PLUGIN_NAME, "Use parts: %s", value.c_str());
    } else if (key == "algorithm") {
      cfg->algorithm = stoi(value);
      TSDebug(PLUGIN_NAME, "Algorithm: %s", value.c_str());
    } else if (key == "knumber") {
      cfg->knumber = stoi(value);
      TSDebug(PLUGIN_NAME, "Knumber: %s", value.c_str());
    } else if (key == "origin_param") {
      istringstream param_stream(value.c_str());
      string param;
      while (getline(param_stream, param, ',')) {
        TSDebug(PLUGIN_NAME, "Origin param number %d: %s", param_num, param.c_str());
        cfg->origin_param.insert(param);
      }
    } else {
      TSError("[m3u8_transform] Error when parsing line %d: %s", line_no, line.c_str());
    }
  }

  file.close();
  *instance = cfg;
  // TSfree((void *)config_file);
  TSDebug(PLUGIN_NAME, "Configuration of m3u8 transform loaded");
  return TS_SUCCESS;
}

void
TSRemapDeleteInstance(void *instance)
{
  TSDebug(PLUGIN_NAME, "Delete config");
  auto c = static_cast<Config *>(instance);
  delete c;
}

TSRemapStatus
TSRemapDoRemap(void *instance, TSHttpTxn txnp, TSRemapRequestInfo *rri)
{
  if (NULL == instance) {
    TSDebug(PLUGIN_NAME, "No Rules configured, falling back to default");
  } else {
    TSDebug(PLUGIN_NAME, "Remap Rules configured for transform m3u8");
    TSDebug(PLUGIN_NAME, "Start get url");
    string prefix = "";
    string query_string = "";
    int prefix_length = 0;
    int query_string_length = 0;
    Config* cfg = static_cast<Config *> (instance); 
    bool is_m3u8 = verify_request_url(txnp, prefix, &prefix_length, query_string, &query_string_length, cfg->origin_param);
    
    // TODO: Filter url by regex. Now just transform every file with url contain .m3u8;
    if (is_m3u8) {
      TSVConn connp;
      connp = TSContCreate(transform_m3u8_if_needed, NULL);
      ContData *data = my_data_alloc_with_url(prefix, prefix_length, query_string, query_string_length, cfg);
      TSContDataSet(connp, data);
      TSHttpTxnHookAdd(txnp, TS_HTTP_CACHE_LOOKUP_COMPLETE_HOOK, connp);
      TSHttpTxnHookAdd(txnp, TS_HTTP_TXN_CLOSE_HOOK, connp);
    }
  }
  return TSREMAP_NO_REMAP;
}
