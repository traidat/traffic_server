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
#define MAX_URL_LEN 4096
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
  int file_size;
} MyData;

struct config {
  char keys[MAX_KEY_NUM][MAX_KEY_LEN];
  char hash_query_param[MAX_HASH_QUERY_PARAM_NUM][MAX_HASH_QUERY_LEN];
  int paramNum;
  char use_parts[MAX_USE_PARTS_LEN];
  int algorithm;  
  int knumber;
};

struct config *cfg;

static MyData *
my_data_alloc_with_url(char* prefix, int prefix_length, char* query_string, int query_string_length)
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
  data->file_size = 0;
  strcpy(data->query_string, query_string);

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
  TSDebug(PLUGIN_NAME, "Cleaning up");
  TSfree(cfg->use_parts);

  TSfree(cfg);
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
        (*prefix_length) = (file_name - prefix + 1);
      } else {
        *(prefix + scheme_length + 3 + host_length) = '\0';
      }
      query_string = strncat(query_string, "?", 1);
      query_string = strncat(query_string, query_param, query_param_length);
      (*query_string_length) = (*query_string_length) + query_param_length + 1;
      *(query_string + query_param_length + 1) = '\0';
      
      
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
generate_token(char* url, unsigned char* token, unsigned int* token_length) {
  const char *query = strchr(url, '?');
  char signed_part[MAX_URL_LEN] = {'\0'};
  char urltokstr[MAX_URL_LEN] = {'\0'};
  char* cp = strchr(url, '?');
  int j = 0;
  TSDebug(PLUGIN_NAME, "Url: %s", url);
  // Skip scheme and initial forward slashes.
  const char *skip = strchr(url, ':');
  if (!skip || skip[1] != '/' || skip[2] != '/') {
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
    TSDebug(PLUGIN_NAME, "Hash parameter %d: %s", i, cfg->hash_query_param[i]);
    query_params[i] = strstr(query, cfg->hash_query_param[i]);
    if (query_params[i] == NULL) {
      TSError("Missing hash parameter of %s", url);
      return false;
    }
    delimeterParam = strstr(query_params[i], "&");
    TSDebug(PLUGIN_NAME, "Pointer query param: %s", query_params[i]);
    TSDebug(PLUGIN_NAME, "Delimeter: %s", delimeterParam);
    if (i == cfg-> paramNum - 1) {
      strncat(signed_part, query_params[i], (delimeterParam - query_params[i]));
    } else {
      strncat(signed_part, query_params[i], (delimeterParam - query_params[i]) + 1);
    }
  }
  // signed_part[strlen(signed_part)] = '\0';
  TSDebug(PLUGIN_NAME, "cp: %s, query: %s, signed_part: %s", cp, query, signed_part);
  TSDebug(PLUGIN_NAME, "Signed string=\"%s\"", signed_part);
  switch (cfg->algorithm) {
  case USIG_HMAC_SHA1:
    HMAC(EVP_sha1(), (const unsigned char *)cfg->keys[cfg->knumber], strlen(cfg->keys[cfg->knumber]), (const unsigned char *)signed_part,
         strlen(signed_part), token, token_length);
    if ((*token_length) != SHA1_SIG_SIZE) {
      TSDebug(PLUGIN_NAME, "sig_len: %d", (*token_length));
      TSError("Calculated sig len of %s !=  SHA1_SIG_SIZE !", url);
      return false;
    }
    TSDebug(PLUGIN_NAME, "HmacSHA1 of signed_part %s: %s", signed_part, token);
    return true;
  case USIG_HMAC_MD5:
    HMAC(EVP_md5(), (const unsigned char *)cfg->keys[cfg->knumber], strlen(cfg->keys[cfg->knumber]), (const unsigned char *)signed_part,
         strlen(signed_part), token, token_length);
    // HMAC(EVP_md5(), (const unsigned char *)"px0KnwI_hxaS8uNzLOUZw6lVuBqVggJH", 32, (const unsigned char *) "10.61.129.17:8080/file/index.m3u8?timestamp=2526689025",
    //      54, token, token_length);
    if ((*token_length) != MD5_SIG_SIZE) {
      TSDebug(PLUGIN_NAME, "sig_len: %d", (*token_length));
      TSError("Calculated sig len of %s !=  MD5_SIG_SIZE !", url);
      return false;
    }
    TSDebug(PLUGIN_NAME, "HmacMD5 of signed_part %s: %s", signed_part, token);
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
add_token_and_prefix(const char *file_data, char* prefix, int prefix_length, char* query_string, int query_string_length, int* data_size) {
    char buf[MAX_FILE_LENGTH + 1];
    char* result = buf;
    const char *delimiter = "\n";
    char *line;
    char* temp = strdup(file_data);
    TSDebug(PLUGIN_NAME, "Prefix %s length %d", prefix, prefix_length);
    TSDebug(PLUGIN_NAME, "Query string %s length %d", query_string, query_string_length);

    line = strtok(temp, delimiter);
    while (line != NULL) {
      TSDebug(PLUGIN_NAME, "Line: %s", line);
      if (*(line) != '#') {
        if (strstr(line, ".ts") != NULL || (strstr(line, ".m3u8") != NULL)) {
          char url_store[MAX_URL_LEN];
          char* url = url_store;
          unsigned char token_store[MAX_SIG_SIZE + 1];
          unsigned char* token = token_store;
          unsigned int token_length = 0;

          // Generate token from url
          strncat(url, prefix, prefix_length);
          strcat(url, line);
          if (query_string_length > 0 && strstr(url, query_string) == NULL) {
            strncat(url, query_string, query_string_length);
          } else if (query_string_length > 0 && strstr(url, "?") == NULL) {
            *(query_string) = '&';
            strncat(url, query_string, query_string_length);
          }

          // Add line to result (adding prefix, query_string, token if needed)
          strncat(result, prefix, prefix_length);
          (*data_size) = (*data_size) + prefix_length;
          strcat(result, line);
          if (query_string_length > 0 && strstr(line, query_string) == NULL) {
            strncat(result, query_string, query_string_length);
            (*data_size) = (*data_size) + query_string_length;
          } else if (query_string_length > 0 && strstr(line, "?") == NULL) {
            *(query_string) = '&';
            strncat(result, query_string, query_string_length);
            (*data_size) = (*data_size) + query_string_length;
          }

          bool is_success = generate_token(url, token, &token_length);
          if (is_success) {
            strncat(result, "&token=", 7);
            char token_string[2 * MAX_SIG_SIZE + 1];
            for (int i = 0; i < (int) token_length; i++) {
              sprintf(&(token_string[i * 2]), "%02x", token[i]);
            }
            TSDebug(PLUGIN_NAME, "Token of url %s: %s", url, token_string);
            strncat(result, token_string, token_length * 2);
            (*data_size) = (*data_size) + MD5_SIG_SIZE * 2 + 7;
          }
          
          url_store[0] = '\0';
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

bool 
is_gzip_data(const unsigned char *buffer, size_t size) {
    if (size < 2) {
        return false; // Buffer is too small to contain gzip header
    }

    if (buffer[0] != GZIP_MAGIC_0 || buffer[1] != GZIP_MAGIC_1) {
        return false; // Magic number mismatch, not a gzip file
    }

    if (size < 3) {
        return true; // Buffer contains gzip magic number only
    }

    if (buffer[2] != GZIP_METHOD) {
        return false; // Compression method mismatch
    }

    return true; // Likely a gzip file
}

static char*
gzip_data(char* data, int* data_size) {
  // Allocate memory for compressed data
  size_t compressed_capacity = compressBound(*data_size);
  unsigned char *compressed_data = (unsigned char *)malloc(compressed_capacity);
  if (compressed_data == NULL) {
      fprintf(stderr, "Failed to allocate memory\n");
      return NULL;
  }

  // Compress data using zlib
  z_stream stream;
  memset(&stream, 0, sizeof(stream));
  stream.next_in = (Bytef *)data;
  stream.avail_in = *data_size;
  stream.next_out = compressed_data;
  stream.avail_out = compressed_capacity;

  if (deflateInit2(&stream, Z_BEST_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
      fprintf(stderr, "Failed to initialize zlib\n");
      free(compressed_data);
      return NULL;
  }

  if (deflate(&stream, Z_FINISH) != Z_STREAM_END) {
      fprintf(stderr, "Failed to compress data\n");
      deflateEnd(&stream);
      free(compressed_data);
      return NULL;
  }

  deflate(&stream, Z_FINISH);
  deflateEnd(&stream);

  TSDebug(PLUGIN_NAME, "Compress data: %s", compressed_data);
  TSDebug(PLUGIN_NAME, "Compress data size: %ld", stream.total_out);
  *data_size = stream.total_out;

  // Free compressed data buffer
  free(compressed_data);

  return (char *)compressed_data;
}

static unsigned char*
unzip_file_data (unsigned char* compressed_data, int* data_size) {
  // Allocate memory for decompressed data
  int decompressed_size = MAX_FILE_LENGTH; // Adjust as needed
  unsigned char *decompressed_data = (unsigned char *)malloc(decompressed_size);

  if (decompressed_data == NULL) {
      fprintf(stderr, "Failed to allocate memory\n");
      return NULL;
  }

  // Decompress data using zlib
  z_stream stream;
  memset(&stream, 0, sizeof(stream));
  stream.next_in = compressed_data;
  stream.avail_in = *data_size;
  stream.next_out = decompressed_data;
  stream.avail_out = decompressed_size;

  if (inflateInit2(&stream, 16 + MAX_WBITS) != Z_OK) {
      TSDebug(PLUGIN_NAME, "Failed to initialize zlib\n");
      free(decompressed_data);
      return NULL;
  }

  int ret = inflate(&stream, Z_FINISH);
  if (ret != Z_STREAM_END) {
      TSDebug(PLUGIN_NAME, "Failed to decompress data\n");
      inflateEnd(&stream);
      free(decompressed_data);
      return NULL;
  }

  inflateEnd(&stream);

  // Print decompressed data
  TSDebug(PLUGIN_NAME, "Decompressed data: %s", decompressed_data);
  *data_size = stream.total_out;
  TSDebug(PLUGIN_NAME, "Decompressed data size: %d", *data_size);

  return decompressed_data;
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
    int data_size = TSVIONDoneGet(write_vio);
    unsigned char* file_data = (unsigned char*) malloc(data_size);
    /* Copy file data from buffer*/
    TSIOBufferReaderCopy(data->output_reader, file_data, data_size);
    // bool is_gzip = is_gzip_data(file_data, data_size);
    // if (is_gzip) {
    //   file_data = unzip_file_data(file_data, &data_size);
    //   TSDebug(PLUGIN_NAME, "Unzip data: %s", file_data);
    //   TSDebug(PLUGIN_NAME, "Data size after unzip: %d", data_size);
    // } 
    
    TSDebug(PLUGIN_NAME, "File data: %s", file_data);
    
    /* Add token and prefix to every link in file*/
    char* result = add_token_and_prefix((char *) file_data, data-> prefix, data -> prefix_length, data-> query_string, data->query_string_length, &data_size);
    TSDebug(PLUGIN_NAME, "File size after transform: %d", data_size);
    data_size = strlen(result);
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
    data->file_size = data_size;
    // TSVIONBytesSet(data->output_vio, TSVIONDoneGet(write_vio));

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
      char prefix_store[MAX_URL_LEN] = {'\0'};
      char* prefix = prefix_store;
      char query_string_store[MAX_URL_LEN] = {'\0'};
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
  TSFile file;
  TSDebug(PLUGIN_NAME, "Config file name: %s", filename);

  file = TSfopen(filename, "r");
  if (!file) {
    return 0;
  }
  char line[300];
  int line_no = 0;
  int keynum;
  int paramNum = 0;
  bool eat_comment = false;

  cfg = TSmalloc(sizeof(struct config));
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
      TSError("[url_sig] Error parsing line %d of file %s (%s)", line_no, filename, line);
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
      TSError("[url_sig] Error parsing line %d of file %s (%s)", line_no, filename, line);
    }
  }

  TSfclose(file);
  return 1;
}

void
TSPluginInit(int argc, const char *argv[])
{
  TSPluginRegistrationInfo info;

  info.plugin_name   = PLUGIN_NAME;
  info.vendor_name   = "VTNET";
  TSDebug(PLUGIN_NAME, "Start m3u8 transform plugin v2");

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
