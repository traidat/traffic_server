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
bool
verify_request_url(TSHttpTxn txnp, string &prefix, int *prefix_length, string &query_string, int *query_string_length,
                   set<string> origin_param, string &time_shift)
{
  TSMBuffer buf;
  TSMLoc loc;
  TSMBuffer remap_url_buf;
  TSMLoc remap_url_loc;
  TSMLoc url_loc;
  bool is_master_manifest = false;
  if (TS_SUCCESS == TSHttpTxnPristineUrlGet(txnp, &buf, &loc) 
    && TS_SUCCESS == TSHttpTxnClientReqGet(txnp, &remap_url_buf, &remap_url_loc) 
    && TS_SUCCESS == TSHttpHdrUrlGet(remap_url_buf, remap_url_loc, &url_loc)) {
    // Get path of request
    int path_length  = 0;
    const char *path = TSUrlPathGet(buf, loc, &path_length);
    string path_str(path, path_length);
    // Transform only request file .m3u8
    if (path_str.find(".m3u8") == string::npos) {
      ASSERT_SUCCESS(TSHandleMLocRelease(buf, TS_NULL_MLOC, loc));
      TSDebug(PLUGIN_NAME, "Path %s will not transform", path_str.c_str());
      return false;
    }
    TSDebug(PLUGIN_NAME, "Path %s will transform", path_str.c_str());

    // Get scheme
    int scheme_length  = 0;
    const char *scheme = TSUrlSchemeGet(buf, loc, &scheme_length);
    string scheme_str(scheme, scheme_length);

    // Get query param
    int query_param_length  = 0;
    const char* query_param;
    TSDebug(PLUGIN_NAME, "Get query param of remap url");
    query_param = TSUrlHttpQueryGet(remap_url_buf, url_loc, &query_param_length);
    string query_param_str(query_param, query_param_length);
    
    TSDebug(PLUGIN_NAME, "Query param: %s", query_param);
    prefix           = prefix + scheme_str + "://";
    *(prefix_length) = *(prefix_length) + scheme_length + 3;

      int host_length  = 0;
      const char *host = TSUrlHostGet(buf, loc, &host_length);
      string host_str(host, host_length);
      int port = TSUrlRawPortGet(buf, loc);
      if (port > 0) {
        string port_str = to_string(port);
        host_length = host_length + 1 + port_str.size();
        prefix = prefix + host_str + ":" + port_str;
      } else {
        prefix = prefix + host_str;
      }
      
      *(prefix_length) = *(prefix_length) + host_length;

    if (path_str.find("/index.m3u8") != string::npos) {
      is_master_manifest = true;
    }

    // Remove file name from prefix
    prefix           = prefix + "/" + remove_filename_from_path(path_str, &path_length);
    *(prefix_length) = *(prefix_length) + 1 + path_length;

    // Remove parameter that not process in origin, append those parameter to every link in m3u8 file later
    query_string =
      optimize_query_param(query_param_str, query_string_length, origin_param, remap_url_buf, url_loc, is_master_manifest, time_shift);

    TSDebug(PLUGIN_NAME, "Prefix URL: %s", prefix.c_str());
    TSDebug(PLUGIN_NAME, "Query param string: %s", query_string.c_str());
    ASSERT_SUCCESS(TSHandleMLocRelease(buf, TS_NULL_MLOC, loc));
    ASSERT_SUCCESS(TSHandleMLocRelease(remap_url_buf, remap_url_loc, url_loc));
    ASSERT_SUCCESS(TSHandleMLocRelease(remap_url_buf, TS_NULL_MLOC, remap_url_loc));
    return true;
    
  }
  TSDebug(PLUGIN_NAME, "Cannot get request");
  ASSERT_SUCCESS(TSHandleMLocRelease(buf, TS_NULL_MLOC, loc));
  return false;
}

string
add_token_and_prefix(IOBufferData *buffer_data, bool is_full_file)
{
  string result;
  istringstream stream(buffer_data->file_content);
  string line;
  bool has_last_line = false;
  TxnData* txn_data = buffer_data->txn_data;
  while (getline(stream, line)) {
    TSDebug(PLUGIN_NAME, "LINE: %s (%lu)", line.c_str(), line.length());
    if (line.back() == '\r') {
      line.pop_back();
    }
    if (!stream.eof() || (stream.eof() && (is_full_file || buffer_data->file_content.back() == '\n'))) {
      if (line[0] != '#') {
        int is_write;
        if (txn_data->should_add_time_shift) {
          is_write = rewrite_line_without_tag_tstv(line, txn_data->prefix, txn_data->query_string, result, txn_data->time_shift, txn_data->config);
        } else {
          is_write = rewrite_line_without_tag(line, txn_data->prefix, txn_data->query_string, result, txn_data->config);
        }
        if (is_write == 1) {
          result += "\n";
        } else {
          // When we decide to not write a bypass line, we need to delete line with tag before
          deleteSecondLastLine(result);
        }
      } else {
        rewrite_line_with_tag(line, txn_data->prefix, txn_data->query_string, result, txn_data->config);
        result += "\n";
      }
    } else {
      update_file_content(buffer_data, line);
      has_last_line = true;
    }
  }

  if (!has_last_line) {
    string empty       = "";
    buffer_data->file_content = empty;
  }

  return result;
}

static void
handle_transform_m3u8(TSCont contp)
{
  TSVConn output_conn;
  TSVIO write_vio;
  IOBufferData *data;
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
  data = static_cast<IOBufferData *>(TSContDataGet(contp));
  if (!data) {
    TSError("(m3u8_transform) No IOBufferData in transform continuation");
    TxnData *txn_data = txn_data_alloc("", 0, "", 0, NULL, "");
    data              = iobuffer_data_alloc(txn_data, false);
    TSContDataSet(contp, data);
  }

  if (data && data->output_buffer == NULL) {
    data->output_buffer = TSIOBufferCreate();
    data->output_reader = TSIOBufferReaderAlloc(data->output_buffer);
    data->output_vio    = TSVConnWrite(output_conn, contp, data->output_reader, INT64_MAX);
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

      char *file_data = (char *)malloc(towrite + 1);
      TSIOBufferReaderCopy(TSVIOReaderGet(write_vio), file_data, towrite);
      string content(file_data, towrite);
      free(file_data);
      append_file_content(data, content);

      /* Tell the read buffer that we have read the data and are no
         longer interested in it. */
      TSIOBufferReaderConsume(TSVIOReaderGet(write_vio), towrite);

      /* Modify the write VIO to reflect how much data we've
         completed. */
      TSVIONDoneSet(write_vio, TSVIONDoneGet(write_vio) + towrite);
    }
  }

  /* Now we check the write VIO to see if there is data left to
     read. */
  if (TSVIONTodoGet(write_vio) > 0) {
    string result = add_token_and_prefix(data, false);
    update_file_size(data, result.size());
    TSIOBufferWrite(data->output_buffer, result.c_str(), result.size());
    if (towrite > 0) {
      /* If there is data left to read, then we reenable the output
         connection by reenabling the output VIO. This will wakeup
         the output connection and allow it to consume data from the
         output buffer. */
      TSVIOReenable(data->output_vio);

      /* Call back the write VIO continuation to let it know that we
         are ready for more data. */
      TSContCall(TSVIOContGet(write_vio), TS_EVENT_VCONN_WRITE_READY, write_vio);
    }
  } else {
    string result = add_token_and_prefix(data, true);
    update_file_size(data, result.size());
    TSIOBufferWrite(data->output_buffer, result.c_str(), result.size());
    /* If there is no data left to read, then we modify the output
       VIO to reflect how much data the output connection should
       expect. This allows the output connection to know when it
       is done reading. We then reenable the output connection so
       that it can consume the data we just gave it. */
    TSVIONBytesSet(data->output_vio, data->file_size);
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
transform_body_handler(TSCont contp, TSEvent event, void *edata ATS_UNUSED)
{
  /* Check to see if the transformation has been closed by a call to
     TSVConnClose. */
  if (TSVConnClosedGet(contp)) {
    TSDebug(PLUGIN_NAME, "Free contdata when TSVConnClose");
    iobuffer_data_destroy(static_cast<IOBufferData *>(TSContDataGet(contp)));
    TSContDestroy(contp);
    return 0;
  } else {
    TSDebug(PLUGIN_NAME, "Event %d", event);
    switch (event) {
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
add_transform_hook(TSHttpTxn txnp, TSCont contp, bool is_hit)
{
  // Cache original data from origin / upstream server and don't cache transformed data.
  TSHttpTxnUntransformedRespCache(txnp, 1);
  TSHttpTxnTransformedRespCache(txnp, 0);

  TSVConn transform_body_contp = TSTransformCreate(transform_body_handler, txnp);
  TxnData *txn_data            = static_cast<TxnData *>(TSContDataGet(contp));
  if (txn_data->time_shift.size() > 0 && is_hit) {
    txn_data->should_add_time_shift = true;
  }
  IOBufferData *iobuffer_data = iobuffer_data_alloc(txn_data);

  TSContDataSet(transform_body_contp, iobuffer_data);
  TSHttpTxnHookAdd(txnp, TS_HTTP_RESPONSE_TRANSFORM_HOOK, transform_body_contp);
}

static int
transform_m3u8_if_needed(TSCont contp, TSEvent event, void *edata)
{
  TSHttpTxn txnp = (TSHttpTxn)edata;
  TSDebug(PLUGIN_NAME, "Txn %p event %d", txnp, event);
  switch (event) {
  case TS_EVENT_HTTP_CACHE_LOOKUP_COMPLETE: {
    int obj_status = -1;
    if (TS_ERROR != TSHttpTxnCacheLookupStatusGet(txnp, &obj_status) && (TS_CACHE_LOOKUP_HIT_FRESH == obj_status)) {
      add_transform_hook(txnp, contp, true);
    } else {
      TSHttpTxnHookAdd(txnp, TS_HTTP_READ_RESPONSE_HDR_HOOK, contp);
    }
  } break;

  case TS_EVENT_HTTP_READ_RESPONSE_HDR:
    if (transformable(txnp)) {
      add_transform_hook(txnp, contp, false);
    }
    break;

  case TS_EVENT_HTTP_TXN_CLOSE: {
    TxnData *txn_data = static_cast<TxnData *>(TSContDataGet(contp));
    if (txn_data == NULL) {
      TSDebug(PLUGIN_NAME, "TSContDataGet fail in TS_EVENT_HTTP_TXN_CLOSE");
    } else {
      txn_data_destroy(txn_data);
      TSDebug(PLUGIN_NAME, "Free m3u8_transform data in TS_EVENT_HTTP_TXN_CLOSE");
    }
    TSContDestroy(contp);
    break;
  }

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
  int param_num    = 0;
  bool eat_comment = false;
  Config *cfg      = new Config();

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
    string key   = line.substr(0, pos);
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
    } else if (key == "removed_string") {
      istringstream removed_string_stream(value.c_str());
      string removed_string;
      while (getline(removed_string_stream, removed_string, ',')) {
        TSDebug(PLUGIN_NAME, "Remove line with string %s", removed_string.c_str());
        cfg->removed_string.push_back(removed_string);
      }
    } else if (key == "enable_remove_line") {
      cfg->enable_remove_line = stoi(value);
      TSDebug(PLUGIN_NAME, "Enable remove line: %s", value.c_str());
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

    string prefix           = "";
    string query_string     = "";
    int prefix_length       = 0;
    int query_string_length = 0;
    Config *cfg             = static_cast<Config *>(instance);
    string time_shift       = "";
    bool is_m3u8 =
      verify_request_url(txnp, prefix, &prefix_length, query_string, &query_string_length, cfg->origin_param, time_shift);
    if (is_m3u8) {
      TSVConn connp;
      connp             = TSContCreate(transform_m3u8_if_needed, NULL);
      TxnData *txn_data = txn_data_alloc(prefix, prefix_length, query_string, query_string_length, cfg, time_shift);
      TSContDataSet(connp, txn_data);
      TSHttpTxnHookAdd(txnp, TS_HTTP_CACHE_LOOKUP_COMPLETE_HOOK, connp);
      TSHttpTxnHookAdd(txnp, TS_HTTP_TXN_CLOSE_HOOK, connp);
    }
  }
  return TSREMAP_NO_REMAP;
}
