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

#include "ink_autoconf.h"
#include "ts/ts.h"
#include "tscore/ink_defs.h"
#include "string_util.cc"
#include "url_operation.cc"

#define PLUGIN_NAME "m3u8_transform"

#define ASSERT_SUCCESS(_x) TSAssert((_x) == TS_SUCCESS)
#define MAX_KEY_NUM 16
using namespace std;


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

string
add_token_and_prefix(const string &file_data, Config *cfg, const string &prefix, const string &query_string, int *data_size)
{
  string result;
  istringstream stream(file_data);
  string line;
  while (getline(stream, line)) {
    if (line.back() == '\n') {
      line.pop_back();
    }
    TSDebug("PLUGIN_NAME", "LINE: %s (%lu)", line.c_str(), line.length());
    if (line[0] != '#') {
      rewrite_line_without_tag(line, prefix, query_string, result, cfg);
    } else {
      rewrite_line_with_tag(line, prefix, query_string, result, cfg);
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
    // data->output_vio    = TSVConnWrite(output_conn, contp, data->output_reader, towrite);
    TSContDataSet(contp, data);
  } else if (data->output_buffer == NULL) {
    towrite = TSVIONBytesGet(write_vio);
    data->output_buffer = TSIOBufferCreate();
    data->output_reader = TSIOBufferReaderAlloc(data->output_buffer);
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
    
    TSVIONBytesSet(data->output_vio, data->file_size);
    TSVIOReenable(data->output_vio);

    return;
  }

  /* Determine how much data we have left to read. For this append
     transform plugin this is also the amount of data we have left
     to write to the output connection. */
  towrite = TSVIONTodoGet(write_vio);
  // unsigned char* file_data = (unsigned char*) malloc(towrite + 1);
  // char* file_data = (char*) malloc(towrite + 1);
  // TSIOBufferReaderCopy(TSVIOReaderGet(write_vio), file_data, towrite);
  // string file_content(file_data, towrite);
  // int64_t avail = TSIOBufferReaderAvail(TSVIOReaderGet(write_vio));
  // TSDebug(PLUGIN_NAME, "Data length: %ld", towrite);
  // TSDebug(PLUGIN_NAME, "Data file: %s and data length: %ld and avail: %ld", file_content.c_str(), towrite, avail);
  // if (file_content.find("http://") != std::string::npos) {
  //   TSDebug(PLUGIN_NAME, "Wrong file data");
  // }
  // free(file_data);
  
  if (towrite > 0) {
    /* The amount of data left to read needs to be truncated by
       the amount of data actually in the read buffer. */
    int64_t avail = TSIOBufferReaderAvail(TSVIOReaderGet(write_vio));
    TSDebug(PLUGIN_NAME, "Towrite: %ld", towrite);
    TSDebug(PLUGIN_NAME, "Avail: %ld", avail);
    if (towrite > avail) {
      towrite = avail;
    }
    if (towrite > 0) {
      /* Copy the data from the read buffer to the output buffer. */
      // TSIOBufferCopy(data->output_buffer, TSVIOReaderGet(write_vio), towrite, 0);
      char* file_data = (char*) malloc(towrite + 1);
      TSIOBufferReaderCopy(TSVIOReaderGet(write_vio), file_data, towrite);
      string content(file_data, towrite);
      free(file_data);
      update_file_content(data, content, towrite);

      /* Tell the read buffer that we have read the data and are no
         longer interested in it. */
      TSIOBufferReaderConsume(TSVIOReaderGet(write_vio), towrite);

      /* Modify the write VIO to reflect how much data we've
         completed. */
      TSVIONDoneSet(write_vio, data->file_size);
    }
  }

  /* Now we check the write VIO to see if there is data left to
     read. */
  if (TSVIONTodoGet(write_vio) > 0) {
    if (towrite > 0) {
      /* If there is data left to read, then we reenable the output
         connection by reenabling the output VIO. This will wakeup
         the output connection and allow it to consume data from the
         output buffer. */
      // TSVIOReenable(data->output_vio);

      /* Call back the write VIO continuation to let it know that we
         are ready for more data. */
      TSContCall(TSVIOContGet(write_vio), TS_EVENT_VCONN_WRITE_READY, write_vio);
    }
  } else {
    /* If there is no data left to read, then we modify the output
       VIO to reflect how much data the output connection should
       expect. This allows the output connection to know when it
       is done reading. We then reenable the output connection so
       that it can consume the data we just gave it. */
    data->output_vio    = TSVConnWrite(output_conn, contp, data->output_reader, towrite);
    TSDebug(PLUGIN_NAME, "Request prefix: %s", data->prefix.c_str());
    TSDebug(PLUGIN_NAME, "Request query string: %s", data->query_string.c_str());
    int data_size = data->file_size;
    
    /* Copy file data from buffer*/
    TSDebug(PLUGIN_NAME, "File data: %s with length %d", data->file_content.c_str(), data->file_size);
    // bool is_gzip = is_gzip_data(file_data, data_size);
    // if (is_gzip) {
    //   file_data = unzip_file_data(file_data, &data_size);
    //   TSDebug(PLUGIN_NAME, "Unzip data: %s", file_data);
    //   TSDebug(PLUGIN_NAME, "Data size after unzip: %d", data_size);
    // } 
        
    /* Add token and prefix to every link in file*/
    string result = add_token_and_prefix(data->file_content, data->config, data-> prefix,  data-> query_string, &data_size);
    data_size = result.size();
    TSDebug(PLUGIN_NAME, "Length of text: %d", data_size);
    TSDebug(PLUGIN_NAME, "File after transform: %s", result.c_str());
    // if (is_gzip) {
    //   result = gzip_data(result, &data_size);
    //   TSDebug(PLUGIN_NAME, "File after gzip: %s", result);
    //   TSDebug(PLUGIN_NAME, "File size after gzip: %d", data_size);
    // }

    /* Remove all data from reader and add content of file after tranform to reader*/
    // TSIOBufferReaderConsume(data->output_reader, TSIOBufferReaderAvail(data->output_reader));
    data->file_size = data_size;
    // int64_t avail;
    // for (;;) {
    //   TSIOBufferBlock blk = TSIOBufferStart(data->output_buffer);
    //   TSIOBufferBlock block = TSIOBufferReaderStart(data->output_reader);
    //   while (block) {
    //     int64_t block_size;
    //     const char *block_data = TSIOBufferBlockReadStart(block, data->output_reader, &block_size);

    //     // Process or print the block data
    //     TSDebug(PLUGIN_NAME, "out 3 %.*s", (int)block_size, block_data);
 
    //     block = TSIOBufferBlockNext(block); 
    //   }
    //   char *p             = TSIOBufferBlockWriteStart(blk, &avail);
    //   TSDebug(PLUGIN_NAME, "Avai in buffer: %d", avail);
    //   if (data_size > avail) {
    //     memcpy(p, result.c_str(), data_size);
    //     data_size = data_size - avail;
    //     TSIOBufferProduce(data->output_buffer, avail);
    //   } else {
    //     memcpy(p, result.c_str(), data_size);
    //     data_size = 0;
    //     TSIOBufferProduce(data->output_buffer, data_size);
    //   }
    //   if (data_size <= 0) {
    //     break;
    //   }
    // }
    // TSDebug(PLUGIN_NAME, "Reader available: %s", TSIOBufferReaderAvail(data->output_reader));

    TSIOBufferWrite(data->output_buffer, result.c_str(), data_size);
    TSVIONBytesSet(data->output_vio, data_size);
    
    // TSVIONBytesSet(data->output_vio, TSVIONDoneGet(write_vio));

    TSVIOReenable(data->output_vio);

    /* Call back the write VIO continuation to let it know that wek
       have completed the write operation. */
    TSContCall(TSVIOContGet(write_vio), TS_EVENT_VCONN_WRITE_COMPLETE, write_vio);
  }
}

static bool
transformable(TSHttpTxn txnp)
{
  TSMBuffer bufp;
  TSMLoc hdr_loc;

  if (TS_SUCCESS == TSHttpTxnServerRespGet(txnp, &bufp, &hdr_loc)) {
    TSHttpStatus status = TSHttpHdrStatusGet(bufp, hdr_loc);
    TSDebug(PLUGIN_NAME, "Status code of request: %d", status);

    if (TS_HTTP_STATUS_OK == status || TS_HTTP_STATUS_PARTIAL_CONTENT == status || TS_HTTP_STATUS_NOT_MODIFIED == status) {
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

void
add_transform_hook(TSHttpTxn txnp, TSCont contp)
{
  TSHttpTxnUntransformedRespCache(txnp, 1);
  TSHttpTxnTransformedRespCache(txnp, 0);
  TSVConn connp;
  connp          = TSTransformCreate(transform_data, txnp);
  ContData *data = static_cast<ContData *>(TSContDataGet(contp));
  TSContDataSet(connp, data);
  TSHttpTxnHookAdd(txnp, TS_HTTP_RESPONSE_TRANSFORM_HOOK, connp);
}

static int
transform_m3u8_if_needed(TSCont contp, TSEvent event, void *edata) {
  TSHttpTxn txnp = (TSHttpTxn) edata;
  switch (event) {
  case TS_EVENT_HTTP_CACHE_LOOKUP_COMPLETE: {
    int obj_status = -1;
    if (TS_ERROR != TSHttpTxnCacheLookupStatusGet(txnp, &obj_status) && (TS_CACHE_LOOKUP_HIT_FRESH == obj_status)) {
      add_transform_hook(txnp, contp);
    } else {
      TSHttpTxnHookAdd(txnp, TS_HTTP_READ_RESPONSE_HDR_HOOK, contp);
    }
  }
    break;
  case TS_EVENT_HTTP_READ_RESPONSE_HDR:
    if (transformable(txnp)) {
      add_transform_hook(txnp, contp);
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
    // int n = 10000;
    // string prefix_temp = "http://";
    // for(int i = 0; i < n; i++) {
    //   prefix_temp += "a";
    // }
    // prefix_temp += ".com/";
    
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