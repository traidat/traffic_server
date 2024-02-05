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
#include <string.h>
#include <stdlib.h>

#include "ts/ts.h"
#include "tscore/ink_defs.h"

#define PLUGIN_NAME "m3u8_transform"

#define ASSERT_SUCCESS(_x) TSAssert((_x) == TS_SUCCESS)
#define MAX_FILE_LENGTH 100000
#define MAX_URL_LEN 100
#define MAX_REQ_LEN 8192
#define MAX_KEY_LEN 256
#define MAX_KEY_NUM 16
#define MAX_QUERY_LEN 4096
#define MAX_HASH_QUERY_PARAM_NUM 16
#define MAX_HASH_QUERY_LEN 256

typedef struct {
  TSVIO output_vio;
  TSIOBuffer output_buffer;
  TSIOBufferReader output_reader;
  TSIOBuffer hash_buffer;
  TSIOBufferReader hash_reader;
  char* prefix;
  char* query_string;
  int prefix_length;
  int query_string_length;
  int file_size;
  int append_needed;
} MyData;

static MyData *
my_data_alloc_with_url(char* prefix, int prefix_length, char* query_string, int query_string_length)
{
  MyData *data;

  data = (MyData *)TSmalloc(sizeof(MyData));
  TSReleaseAssert(data);

  data->output_vio    = NULL;
  data->output_buffer = NULL;
  data->output_reader = NULL;
  data->hash_buffer = NULL;
  data->hash_reader = NULL;
  data->prefix = TSmalloc(sizeof(prefix));
  data->prefix_length = prefix_length;
  strcpy(data->prefix, prefix);
  data->query_string = TSmalloc(sizeof(query_string));
  data->query_string_length = query_string_length;
  data->file_size = 0;
  strcpy(data->query_string, query_string);
  data->append_needed = 1;

  return data;
}

static void
my_data_destroy(MyData *data)
{
  if (data) {
    if (data->output_buffer) {
      TSIOBufferDestroy(data->output_buffer);
    }
    if (data->hash_buffer) {
      TSIOBufferDestroy(data->hash_buffer);
    }
    if (data->prefix) {
      TSfree(data->prefix);
    }
    if (data->query_string) {
      TSfree(data->query_string);
    }
    TSfree(data);
  }
}


// Verify request is m3u8 file and get prefix and query_string of request URL
bool 
verify_request_url(TSHttpTxn txnp, char* prefix, int* prefix_length, char* query_string, int* query_string_length) {
  TSMBuffer buf;
  TSMLoc loc;

  if (TS_SUCCESS == TSHttpTxnClientReqGet(txnp, &buf, &loc)) {
    int host_length = 0;
    int scheme_length = 0;
    int path_length = 0;
    int query_param_length = 0;
    TSMLoc url_loc;
    if (TS_SUCCESS == TSHttpHdrUrlGet(buf, loc, &url_loc)) {
      const char* path = TSUrlPathGet(buf, url_loc, &path_length);
      // TODO: Use regex to verify request m3u8 file. Now just check contain .m3u8
      if (strstr(path, ".m3u8") == NULL) {
        ASSERT_SUCCESS(TSHandleMLocRelease(buf, loc, url_loc));
        ASSERT_SUCCESS(TSHandleMLocRelease(buf, TS_NULL_MLOC, loc));
        return false;
      }

      const char* scheme = TSUrlSchemeGet(buf, url_loc, &scheme_length);
      const char* query_param = TSUrlHttpQueryGet(buf, url_loc, &query_param_length);
      TSMLoc remap_loc;
      prefix = strncat(prefix, scheme, scheme_length);
      prefix = strncat(prefix, "://", 3);
      if (TS_SUCCESS == TSRemapFromUrlGet(txnp, &remap_loc)) {
        const char* host = TSUrlHostGet(buf, remap_loc, &host_length);
        prefix = strncat(prefix, host, host_length);
        ASSERT_SUCCESS(TSHandleMLocRelease(buf, TS_NULL_MLOC, remap_loc));
      } else {
        const char* host = TSUrlHostGet(buf, url_loc, &host_length);
        prefix = strncat(prefix, host, host_length);
      }
      prefix = strncat(prefix, "/", 1);
      prefix = strncat(prefix, path, path_length);
      (*prefix_length) = (*prefix_length) + scheme_length + 3 + host_length + 1;
      char* file_name = strrchr(prefix, '/');
      if (file_name != NULL) {
        *(file_name + 1) = '\0';
        (*prefix_length) = (file_name - prefix);
      } else {
        *(prefix + scheme_length + 3 + host_length) = '\0';
      }
      query_string = strncat(query_string, "?", 1);
      query_string = strncat(query_string, query_param, query_param_length);
      *(query_string + query_param_length) = '\0';
      (*query_string_length) = (*query_string_length) + query_param_length + 1;
      
      ASSERT_SUCCESS(TSHandleMLocRelease(buf, loc, url_loc));
      ASSERT_SUCCESS(TSHandleMLocRelease(buf, TS_NULL_MLOC, loc));
      
      TSDebug(PLUGIN_NAME, "Prefix URL: %s", prefix);
      TSDebug(PLUGIN_NAME, "Query param string: %s", query_string);
      return true;
    }
  }
 
  TSDebug(PLUGIN_NAME, "Cannot get request");
  ASSERT_SUCCESS(TSHandleMLocRelease(buf, TS_NULL_MLOC, loc));
  return false;
}


// Add prefix cache domain and token to every link inside m3u8 file
char* 
add_token_and_prefix(const char *file_data, char* prefix, int prefix_length, char* query_string, int query_string_length, int* data_size) {
    char buf[MAX_FILE_LENGTH + 1];
    char* result = buf;
    const char *delimiter = "\n";
    char *line;
    char* temp = strdup(file_data);
    
    line = strtok(temp, delimiter);
    while (line != NULL) {
      TSDebug(PLUGIN_NAME, "Line: %s", line);
      if (*(line) != '#') {
        if (strstr(line, ".ts") != NULL || (strstr(line, ".m3u8") != NULL)) {
          strcat(result, prefix);
          strcat(result, line);
          strcat(result, query_string);
          (*data_size) = (*data_size) + prefix_length + query_string_length;
        } else {
          strcat(result, line);
        }
      } else {
        strcat(result, line);
      }
      line = strtok(NULL, delimiter);
      if (line != NULL) {
        strncat(result, "\n", 1);
      }
    }

    free(temp);

    return result;
}

static void
handle_transform_m3u8(TSCont contp)
{
  TSVConn output_conn;
  TSVIO write_vio;
  MyData *data;
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
  data = TSContDataGet(contp);
  if (!data) {
    towrite = TSVIONBytesGet(write_vio);
    data                = my_data_alloc_with_url("", 0,"", 0);
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
    char debug_file[data->file_size + 1];
    TSIOBufferReaderCopy(data->output_reader, debug_file, data->file_size);
    TSDebug(PLUGIN_NAME, "Debug file output: %s", debug_file);
    TSDebug(PLUGIN_NAME, "Debug file size: %d", data->file_size);
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
    if (towrite > avail) {
      towrite = avail;
    }
    if (towrite > 0) {
      /* Copy the data from the read buffer to the output buffer. */
      TSIOBufferCopy(TSVIOBufferGet(data->output_vio), TSVIOReaderGet(write_vio), towrite, 0);

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
    /* If there is no data left to read, then we modify the output
       VIO to reflect how much data the output connection should
       expect. This allows the output connection to know when it
       is done reading. We then reenable the output connection so
       that it can consume the data we just gave it. */
    TSDebug(PLUGIN_NAME, "Request prefix: %s", data->prefix);
    TSDebug(PLUGIN_NAME, "Request query string: %s", data->query_string);
    TSDebug(PLUGIN_NAME, "Write length: %ld", TSVIONDoneGet(write_vio));
    int data_size = TSIOBufferReaderAvail(data->output_reader);
    char file_data[data_size + 1];
    TSIOBufferReaderCopy(data->output_reader, file_data, data_size);
    
    char* result = add_token_and_prefix(file_data, data-> prefix, data -> prefix_length, data-> query_string, data->query_string_length, &data_size);
    TSDebug(PLUGIN_NAME, "File size after transform: %d", data_size);
    TSDebug(PLUGIN_NAME, "File after transform: %s", result);
    data->file_size = data_size;
    TSIOBufferReaderConsume(data->output_reader, TSIOBufferReaderAvail(data->output_reader));
    TSIOBufferWrite(data->output_buffer, result, data_size);
    TSVIONBytesSet(data->output_vio, data_size);
    TSVIOReenable(data->output_vio);

    /* Call back the write VIO continuation to let it know that wek
       have completed the write operation. */
    TSContCall(TSVIOContGet(write_vio), TS_EVENT_VCONN_WRITE_COMPLETE, write_vio);
  }
}

static int
add_token_transform(TSCont contp, TSEvent event, void *edata ATS_UNUSED)
{
  /* Check to see if the transformation has been closed by a call to
     TSVConnClose. */
  if (TSVConnClosedGet(contp)) {
    my_data_destroy(TSContDataGet(contp));
    TSContDestroy(contp);
    return 0;
  } else {
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

static int
transformable(TSHttpTxn txnp)
{
  TSMBuffer bufp;
  TSMLoc hdr_loc;

  if (TS_SUCCESS == TSHttpTxnServerRespGet(txnp, &bufp, &hdr_loc)) {
    /*
     *    We are only interested in "200 OK" responses.
     */

    if (TS_HTTP_STATUS_OK == TSHttpHdrStatusGet(bufp, hdr_loc)) {
      ASSERT_SUCCESS(TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc));
      return 1;
    } else {
      ASSERT_SUCCESS(TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc));
      return 0;
    }
  }

  return 0; /* not a 200 */
}

const char* 
getUrlRequest(TSHttpTxn txnp) 
{
  TSMBuffer buf;
  TSMLoc loc;

  if (TS_SUCCESS == TSHttpTxnClientReqGet(txnp, &buf, &loc)) {
    int length;
    char *url = TSHttpTxnEffectiveUrlStringGet(txnp, &length);
    if (url) {
      TSDebug(PLUGIN_NAME, "URL: %s", url);
      
      ASSERT_SUCCESS(TSHandleMLocRelease(buf, TS_NULL_MLOC, loc));
      return url;
    }
  }
 
  TSDebug(PLUGIN_NAME, "Cannot get request ");
  ASSERT_SUCCESS(TSHandleMLocRelease(buf, TS_NULL_MLOC, loc));
  return NULL;
}

char* 
getUrlRequestV2(TSHttpTxn txnp) 
{
  TSMBuffer buf;
  TSMLoc loc;
  if (TS_SUCCESS == TSHttpTxnClientReqGet(txnp, &buf, &loc)) {
    TSMLoc url_loc;
    int length = 0;
    TSRemapFromUrlGet(txnp, &url_loc);
    const char* host = TSUrlHostGet(buf, url_loc, &length);
    TSDebug(PLUGIN_NAME, "Url: %s", host);
  }
 
  TSDebug(PLUGIN_NAME, "Cannot get request ");
  ASSERT_SUCCESS(TSHandleMLocRelease(buf, TS_NULL_MLOC, loc));
  return NULL;
}

static void 
transform_m3u8(TSHttpTxn txnp, char* prefix, int prefix_length, char* query_string, int query_string_length) {
  TSVConn connp;
  
  connp = TSTransformCreate(add_token_transform, txnp);
  MyData *data = my_data_alloc_with_url(prefix, prefix_length, query_string, query_string_length);
  TSContDataSet(connp, data);
  TSHttpTxnHookAdd(txnp, TS_HTTP_RESPONSE_TRANSFORM_HOOK, connp);
}

static int
transform_plugin(TSCont contp ATS_UNUSED, TSEvent event, void *edata)
{
  TSHttpTxn txnp = (TSHttpTxn)edata;
  TSDebug(PLUGIN_NAME, "Start transform");

  switch (event) {
  case TS_EVENT_HTTP_READ_RESPONSE_HDR:
    if (transformable(txnp)) {
      char prefix_store[MAX_URL_LEN];
      char* prefix = prefix_store;
      char query_string_store[MAX_URL_LEN];
      char* query_string = query_string_store;
      int prefix_length = 0;
      int query_string_length = 0;
      bool is_m3u8 = verify_request_url(txnp, prefix, &prefix_length, query_string, &query_string_length);

      // TODO: Filter url by regex. Now just transform every file with url contain .m3u8;
      if (is_m3u8) {
        transform_m3u8(txnp, prefix, prefix_length, query_string, query_string_length);
      }
    }
    TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
    return 0;
  default:
    break;
  }

  return 0;
}

static int
load(const char *filename)
{
  TSFile fp;
  int64_t avail;

  fp = TSfopen(filename, "r");
  if (!fp) {
    return 0;
  }

  TSfclose(fp);
  return 1;
}

void
TSPluginInit(int argc, const char *argv[])
{
  TSPluginRegistrationInfo info;

  info.plugin_name   = PLUGIN_NAME;
  info.vendor_name   = "Apache Software Foundation";
  info.support_email = "dev@trafficserver.apache.org";
  TSDebug(PLUGIN_NAME, "Start m3u8 transform plugin");

  if (TSPluginRegister(&info) != TS_SUCCESS) {
    TSError("[%s] Plugin registration failed", PLUGIN_NAME);
    goto Lerror;
  }

  if (argc != 2) {
    TSError("[%s] Usage: %s <filename>", PLUGIN_NAME, argv[0]);
    goto Lerror;
  }

  if (!load(argv[1])) {
    TSError("[%s] Could not load %s", PLUGIN_NAME, argv[1]);
    goto Lerror;
  }

  TSHttpHookAdd(TS_HTTP_READ_RESPONSE_HDR_HOOK, TSContCreate(transform_plugin, NULL));
  return;

Lerror:

  TSError("[%s] Unable to initialize plugin", PLUGIN_NAME);
}