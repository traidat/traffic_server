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
#include <ctype.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <zlib.h>
#include <ts/ts.h>
#include <ts/remap.h>

#include "ts/ts.h"
#include "tscore/ink_defs.h"

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

typedef struct {
  TSVIO output_vio;
  TSIOBuffer output_buffer;
  TSIOBufferReader output_reader;
  char* prefix;
  char* query_string;
  int prefix_length;
  int query_string_length;
  int file_data;
  struct config* config;
} MyData;

struct config {
  char keys[MAX_KEY_NUM][MAX_KEY_LEN];
  char hash_query_param[MAX_HASH_QUERY_PARAM_NUM][MAX_HASH_QUERY_LEN];
  int paramNum;
  char use_parts[MAX_USE_PARTS_LEN];
  int algorithm;  
  int knumber;
};

static MyData *
my_data_alloc_with_url(char* prefix, int prefix_length, char* query_string, int query_string_length, struct config* cfg)
{
  MyData *data;

  data = (MyData *)TSmalloc(sizeof(MyData));
  TSReleaseAssert(data);

  data->output_vio    = NULL;
  data->output_buffer = NULL;
  data->output_reader = NULL;
  data->prefix = malloc(prefix_length + 1);
  data->prefix_length = prefix_length;
  strcpy(data->prefix, prefix);
  data->query_string = malloc(query_string_length + 1);
  data->query_string_length = query_string_length;
  data->file_data = 0;
  strcpy(data->query_string, query_string);
  data->config = cfg;

  return data;
}

static void
my_data_destroy(MyData *data)
{
  if (data) {
    if (data->output_buffer) {
      TSIOBufferDestroy(data->output_buffer);
    }
    if (data->prefix) {
      free(data->prefix);
    }
    if (data->query_string) {
      free(data->query_string);
    }
    TSfree(data);
  }
}

static void
free_cfg(struct config *cfg)
{
  TSDebug(PLUGIN_NAME, "Cleaning up config");
  TSfree(cfg->use_parts);

  TSfree(cfg);
}


char *
strnstr(const char *s, const char *find, size_t slen)
{
  char c, sc;
  size_t len;

  if ((c = *find++) != '\0') {
      len = strlen(find);
      do {
          do {
              if (slen-- < 1 || (sc = *s++) == '\0')
                  return (NULL);
          } while (sc != c);
          if (len > slen)
              return (NULL);
      } while (strncmp(s, find, len) != 0);
      s--;
  }
  return ((char *)s);
}

// Verify request is m3u8 file and get prefix and query_string of request URL
// TODO: Verify host is IP or domain, port is 80, 443 or not
bool 
verify_request_url(TSHttpTxn txnp, char* prefix, int* prefix_length, char* query_string, int* query_string_length) {
  TSMBuffer buf;
  TSMLoc loc;

  if (TS_SUCCESS == TSHttpTxnClientReqGet(txnp, &buf, &loc)) {
    int host_length = 0;
    int scheme_length = 0;
    int path_length = 0;
    int query_param_length = 0;
    // int port_length = 0;
    TSMLoc url_loc;
    if (TS_SUCCESS == TSHttpHdrUrlGet(buf, loc, &url_loc)) {
      const char* path = TSUrlPathGet(buf, url_loc, &path_length);
      // TODO: Use regex to verify request m3u8 file. Now just check contain .m3u8
      if (path == NULL || strnstr(path, ".m3u8", path_length + 1) == NULL) {
        ASSERT_SUCCESS(TSHandleMLocRelease(buf, loc, url_loc));
        ASSERT_SUCCESS(TSHandleMLocRelease(buf, TS_NULL_MLOC, loc));
        TSDebug(PLUGIN_NAME, "Path %s will not transform", path);
        return false;
      }
      TSDebug(PLUGIN_NAME, "Path %s will transform", path);

      const char* scheme = TSUrlSchemeGet(buf, url_loc, &scheme_length);
      const char* query_param = TSUrlHttpQueryGet(buf, url_loc, &query_param_length);
      TSMLoc remap_loc;
      strncat(prefix, scheme, scheme_length);
      strncat(prefix, "://", 3);
      if (TS_SUCCESS == TSRemapFromUrlGet(txnp, &remap_loc)) {
        const char* host = TSUrlHostGet(buf, remap_loc, &host_length);
        int port = TSUrlRawPortGet(buf, remap_loc);
        prefix = strncat(prefix, host, host_length);
        if (port > 0) {
          prefix = strncat(prefix, ":", 1);
          char buf[sizeof(int)*3+2];
          snprintf(buf, sizeof buf, "%d", port);
          prefix = strcat(prefix, buf);
        }
        ASSERT_SUCCESS(TSHandleMLocRelease(buf, TS_NULL_MLOC, remap_loc));
      } else {
        const char* host = TSHttpHdrHostGet(buf, loc, &host_length);
        char* end_host = strstr(host, "\r");
        prefix = strncat(prefix, host, end_host - host);
      }
      strncat(prefix, "/", 1);
      strncat(prefix, path, path_length);
      (*prefix_length) = (*prefix_length) + scheme_length + 3 + host_length + 1;
      char* file_name = strrchr(prefix, '/');
      if (file_name != NULL) {
        *(file_name + 1) = '\0';
        (*prefix_length) = (file_name - prefix + 1);
      } else {
        *(prefix + scheme_length + 3 + host_length) = '\0';
      }

      strncat(query_string, "?", 1);
      strncat(query_string, query_param, query_param_length);
      (*query_string_length) = (query_param_length);

      // Just remove token from query param
      // TODO: Remove all param not used by origin
      // if (query_param != NULL) {
      //   char* token = strstr(query_param, "token=");
      //     if (token != NULL) {
      //     char* delimeter = strstr(token, "&");
      //     if (delimeter == NULL) {
      //       strncat(query_string, "?", 1);
      //       strncat(query_string, query_param, query_param_length - (token - query_param + 8));
      //       (*query_string_length) = (query_param_length) - (token - query_param + 8);
      //       *(query_string + *query_string_length + 1) = '\0';
      //     } else {
      //       strncat(query_string, "?", 1);
      //       strncat(query_string, query_param, (token - query_param));
      //       strncat(query_string, delimeter + 1, query_param_length - (delimeter - query_param) - 1);
      //       (*query_string_length) = (query_param_length) - (token - query_param + 8);
      //       *(query_string + *query_string_length + 1) = '\0';
      //     }
      //   }
      // }
      
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

bool
generate_token(char* url, struct config* cfg, unsigned char* token, unsigned int* token_length) {
  const char *query = strchr(url, '?');
  char signed_part[MAX_URL_LEN] = {'\0'};
  char urltokstr[MAX_URL_LEN] = {'\0'};
  char* cp = strchr(url, '?');
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
  char* query_params[sizeof(cfg->hash_query_param)];
  char* delimeterParam;
  for (int i = 0; i < cfg->paramNum; i++) {
    query_params[i] = strstr(query, cfg->hash_query_param[i]);
    if (query_params[i] == NULL) {
      TSError("Missing hash parameter of %s", url);
      return false;
    }
    delimeterParam = strstr(query_params[i], "&");
    if (i == cfg-> paramNum - 1) {
      strncat(signed_part, query_params[i], (delimeterParam - query_params[i]));
    } else {
      strncat(signed_part, query_params[i], (delimeterParam - query_params[i]) + 1);
    }
  }
  // signed_part[strlen(signed_part)] = '\0';
  TSDebug(PLUGIN_NAME, "Signed string=\"%s\"", signed_part);
  switch (cfg->algorithm) {
  case USIG_HMAC_SHA1:
    HMAC(EVP_sha1(), (const unsigned char *)cfg->keys[cfg->knumber], strlen(cfg->keys[cfg->knumber]), (const unsigned char *)signed_part,
         strlen(signed_part), token, token_length);
    if ((*token_length) != SHA1_SIG_SIZE) {
      TSError("Calculated sig len of %s !=  SHA1_SIG_SIZE !", url);
      return false;
    }
    return true;
  case USIG_HMAC_MD5:
    HMAC(EVP_md5(), (const unsigned char *)cfg->keys[cfg->knumber], strlen(cfg->keys[cfg->knumber]), (const unsigned char *)signed_part,
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


// Add prefix cache domain and token to every link inside m3u8 file
// TODO: Add token to subtag URL 
char* 
add_token_and_prefix(const char *file_data, struct config* cfg, char* prefix, int prefix_length, char* query_string, int query_string_length, int* data_size) {
    *data_size = 0;
    char buf[MAX_FILE_LENGTH + 1] = {'\0'};
    char* result = buf;
    const char *delimiter = "\n";
    char *line;
    char* temp = strdup(file_data);

    line = strtok(temp, delimiter);
    while (line != NULL) {
      TSDebug(PLUGIN_NAME, "LINE: %s (%d)", line, (int)strlen(line));
      // If line not start with # 
      data_size = data_size + 1;
      if (*(line) != '#') {
        if (strstr(line, ".ts") != NULL || (strstr(line, ".m3u8") != NULL) || (strstr(line, ".m4s") != NULL) || (strstr(line, ".mp4") != NULL)) {
          char url_store[MAX_URL_LEN] = {'\0'};
          char* url = url_store;
          unsigned char token_store[MAX_SIG_SIZE + 1] = {'\0'};
          unsigned char* token = token_store;
          unsigned int token_length = 0;

          // Generate url from line
          strncat(url, prefix, prefix_length);
          strcat(url, line);
          if (query_string_length > 0 && strstr(url, query_string) == NULL) {
            strncat(url, query_string, query_string_length);
          } else if (query_string_length > 0 && strstr(url, "?") == NULL) {
            *(query_string) = '&';
            strncat(url, query_string, query_string_length);
          }

          // Add line with token to result (adding prefix, query_string, token if needed)
          strcat(result, url);
          bool is_success = generate_token(url, cfg, token, &token_length);
          if (is_success) {
            strncat(result, "&token=", 7);
            char token_string[2 * MAX_SIG_SIZE + 1] = {'\0'};
            for (int i = 0; i < (int) token_length; i++) {
              sprintf(&(token_string[i * 2]), "%02x", token[i]);
            }
            TSDebug(PLUGIN_NAME, "Token of url %s: %s", url, token_string);
            strncat(result, token_string, token_length * 2);
          }
            
          url_store[0] = '\0';
          token_store[0] = '\0';
        } else {
          strcat(result, line);
        }
      // If line contain URI tag
      } else {
        char* uri = strstr(line, "URI=\"");
        if (uri != NULL) {
          char* next_quote = strstr(uri + 5, "\"");
          if (next_quote != NULL) {
            char url_store[MAX_URL_LEN] = {'\0'};
          char* url = url_store;
          unsigned char token_store[MAX_SIG_SIZE + 1] = {'\0'};
          unsigned char* token = token_store;
          unsigned int token_length = 0;

          // Generate url from uri
          strncat(url, prefix, prefix_length);
          strncat(url, uri + 5, next_quote - uri - 5);
          strncat(url, query_string, query_string_length);

          // Add line with token to result (adding prefix, query_string, token if needed)
          strncat(result, line, uri - line + 5);
          strcat(result, url);
          bool is_success = generate_token(url, cfg, token, &token_length);
          if (is_success) {
            strncat(result, "&token=", 7);
            char token_string[2 * MAX_SIG_SIZE + 1] = {'\0'};
            for (int i = 0; i < (int) token_length; i++) {
              sprintf(&(token_string[i * 2]), "%02x", token[i]);
            }
            TSDebug(PLUGIN_NAME, "Token of url %s: %s", url, token_string);
            strncat(result, token_string, token_length * 2);
          }
          strcat(result, next_quote);
          
          url_store[0] = '\0';
          token_store[0] = '\0';
          } else {
            strcat(result, line);
          }
        } else {
          strcat(result, line);
        }
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
  unsigned char* file_data = (unsigned char*) malloc(towrite + 1);
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
    TSDebug(PLUGIN_NAME, "Request prefix: %s", data->prefix);
    TSDebug(PLUGIN_NAME, "Request query string: %s", data->query_string);
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
    char* result = add_token_and_prefix((char *) file_data, data->config, data-> prefix, data -> prefix_length, data-> query_string, data->query_string_length, &data_size);
    data_size = data_size + strlen(result);
    TSDebug(PLUGIN_NAME, "Length of text: %d", data_size);
    TSDebug(PLUGIN_NAME, "File after transform: %s", result);
    // if (is_gzip) {
    //   result = gzip_data(result, &data_size);
    //   TSDebug(PLUGIN_NAME, "File after gzip: %s", result);
    //   TSDebug(PLUGIN_NAME, "File size after gzip: %d", data_size);
    // }

    /* Remove all data from reader and add content of file after tranform to reader*/
    TSIOBufferReaderConsume(data->output_reader, TSIOBufferReaderAvail(data->output_reader));
    TSIOBufferWrite(data->output_buffer, result, data_size);
    *(result) = '\0';
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
    my_data_destroy(TSContDataGet(contp));
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
      MyData *data = TSContDataGet(contp);
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
      MyData *data = TSContDataGet(contp);
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
  char config_filepath_buf[PATH_MAX], *config_file;

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
  
  TSFile file;

  file = TSfopen(config_file, "r");
  if (!file) {
    TSError("File config: %s not found", config_file);
    return TS_ERROR;
  }
  char line[300];
  int line_no = 0;
  int keynum;
  int paramNum = 0;
  bool eat_comment = false;

  struct config *cfg = TSmalloc(sizeof(struct config));
  memset(cfg, 0, sizeof(struct config));

  while (TSfgets(file, line, sizeof(line)) != NULL) {
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
      TSfclose(file);
      free_cfg(cfg);
      return TS_ERROR;
    }
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
        TSfclose(file);
        free_cfg(cfg);
        return TS_ERROR;
      }
      snprintf(&cfg->keys[keynum][0], MAX_KEY_LEN, "%s", value);
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
    } else {
      TSError("[url_sig] Error parsing line %d of file %s (%s)", line_no, config_file, line);
    }
  }

  TSfclose(file);
  *instance = (void *)cfg;
  return TS_SUCCESS;
}

void
TSRemapDeleteInstance(void *instance)
{
  free_cfg((struct config *)instance);
}

TSRemapStatus
TSRemapDoRemap(void *instance, TSHttpTxn txnp, TSRemapRequestInfo *rri)
{
  if (NULL == instance) {
    TSDebug(PLUGIN_NAME, "No Rules configured, falling back to default");
  } else {
    TSDebug(PLUGIN_NAME, "Remap Rules configured for transform m3u8");
    TSDebug(PLUGIN_NAME, "Start get url");
    char prefix_store[MAX_URL_LEN] = {'\0'};
    char* prefix = prefix_store;
    char query_string_store[MAX_URL_LEN] = {'\0'};
    char* query_string = query_string_store;
    int prefix_length = 0;
    int query_string_length = 0;
    bool is_m3u8 = verify_request_url(txnp, prefix, &prefix_length, query_string, &query_string_length);
    struct config* cfg = (struct config*) instance; 
    // TODO: Filter url by regex. Now just transform every file with url contain .m3u8;
    if (is_m3u8) {
      TSVConn connp;
      connp = TSContCreate(transform_m3u8_if_needed, NULL);
      MyData *data = my_data_alloc_with_url(prefix, prefix_length, query_string, query_string_length, cfg);
      TSContDataSet(connp, data);
      TSHttpTxnHookAdd(txnp, TS_HTTP_CACHE_LOOKUP_COMPLETE_HOOK, connp);
      TSHttpTxnHookAdd(txnp, TS_HTTP_TXN_CLOSE_HOOK, connp);
    }
  }
  return TSREMAP_NO_REMAP;
}