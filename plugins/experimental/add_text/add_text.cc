/**
 * @file
 *
 * A brief file description
 *
 * @section license License
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * add_text_transform.c: a plugin that adds a predefined comment to the beginning
 *                       of .m3u8 files and a comment with the number of lines
 *                       to the end of the file.
 */
#include <climits>
#include <cstdio>
#include <cstring>
#include <stdio.h>
#include <stdlib.h>
#include "ts/ts.h"
#include "tscore/ink_defs.h"

#define PLUGIN_NAME "add_text"
#define FOOTER_PRE "##Total lines:"
#define FOOTER_LINES_MAX_CHAR 10
static const char * filepath = nullptr;

#define ASSERT_SUCCESS(_x) TSAssert((_x) == TS_SUCCESS)

struct MyData
{
  TSVIO output_vio;
  TSIOBuffer output_buffer;
  TSIOBufferReader output_reader;
  bool header_added;
  bool footer_added;
  int line_count;
  int header_length;
  int footer_length;
  char *header;
  char *footer;
};

static char *
load_header_in_file(const char *filename, int &file_size)
{
  FILE *file;
  char *buffer;
  // Open the file in read mode
  file = fopen(filename, "r");
  if (file == NULL)
  {
    TSError("[%s]Error opening file\n[%s]", PLUGIN_NAME, filename);
    return nullptr;
  }

  // Get the size of the file
  fseek(file, 0, SEEK_END); // Move to the end of the file
  file_size = ftell(file);  // Get the current position (size of the file)
  rewind(file);             // Move back to the beginning of the file

  // Allocate memory for the buffer
  buffer = (char *)malloc((file_size + 1) * sizeof(char));
  if (buffer == NULL)
  {
    perror("Memory allocation failed");
    fclose(file);
    return nullptr;
  }

  // Read the file content into the buffer
  fread(buffer, sizeof(char), file_size, file);
  // Clean up
  fclose(file);

  return buffer;
}

static MyData *
my_data_alloc(const char *filename)
{
  MyData *data = static_cast<MyData *>(TSmalloc(sizeof(MyData)));
  TSReleaseAssert(data);

  data->output_buffer = TSIOBufferCreate();
  data->output_reader = TSIOBufferReaderAlloc(data->output_buffer);
  data->header_added = false;
  data->line_count = 0;
  data->footer_added = false;

  int file_size;
  char *buffer = load_header_in_file(filename, file_size);
  if (buffer == nullptr)
  {
    int n = strlen(filename);
    int len = n + 3;
    char header_tmp[len];
    memset(header_tmp, 0, len);
    snprintf(header_tmp, len, "##%s\n", filename);
    data->header = strdup(header_tmp);
  }
  else
  {
    char header_tmp[file_size + 3];
    memset(header_tmp, 0, file_size + 3);
    snprintf(header_tmp, file_size + 3, "##%s\n", buffer);
    data->header = strdup(header_tmp);
    free(buffer);
    buffer = nullptr;
  }
  data->header_length = strlen(data->header);
  data->footer_length = strlen(FOOTER_PRE);

  return data;
}

static void
my_data_destroy(MyData *data)
{
  printf("my_data_destroy\n");
  if (data->header) {
    free(data->header);
    data->header = NULL;
  } 
  if (data->footer) {
    free(data->footer);
    data->footer = NULL;
  }

  if (data)
  {
    if (data->output_buffer)
    {
      TSIOBufferDestroy(data->output_buffer);
    }
    TSfree(data);
  }
}

static void
handle_transform(TSCont contp)
{
  TSVConn output_conn;
  TSVIO write_vio;
  int64_t towrite;
  MyData *data;
  /* Get the output connection where we'll write data to. */
  output_conn = TSTransformOutputVConnGet(contp);

  /* Get the write VIO for the write operation that was performed on
     ourself. This VIO contains the buffer that we are to read from
     as well as the continuation we are to call when the buffer is
     empty. */
  write_vio = TSVConnWriteVIOGet(contp);

  /* Get our data structure for this operation. The private data
     structure contains the output VIO and output buffer. If the
     private data structure pointer is nullptr, then we'll create it
     and initialize its internals. */
  data = static_cast<decltype(data)>(TSContDataGet(contp));
  if (!data) {
    printf("my_data_alloc\n");
  
    data                = my_data_alloc(filepath);
    towrite = TSVIONBytesGet(write_vio);
    if (towrite != INT64_MAX) {
      towrite += data->header_length;
    }
    // data->output_vio    = TSVConnWrite(output_conn, contp, data->output_reader, towrite);
    TSContDataSet(contp, data);
  }

   if (!TSVIOBufferGet(write_vio)) {
    if (!data->footer_added) {
      data->footer_added = true;
      TSIOBufferWrite(data->output_buffer, data->footer, data->footer_length);
    }

    TSVIONBytesSet(data->output_vio, TSVIONDoneGet(write_vio) + data->footer_length + data->header_length);
    TSVIOReenable(data->output_vio);

    return;
  }                                                                                                              

  towrite = TSVIONTodoGet(write_vio);
  if (towrite > 0)
  {
    int64_t avail = TSIOBufferReaderAvail(TSVIOReaderGet(write_vio));
    if (towrite > avail)
    {
      towrite = avail;
    }

    if (towrite > 0)
    {
      // Count lines and copy the data

      if (!data->header_added)
      {
        TSIOBufferWrite(data->output_buffer, data->header, data->header_length);
        // TSIOBufferCopy(TSVIOBufferGet(data->output_vio), data->header, data->header_length, 0);
        data->header_added = true;
        data->line_count ++;
        // TSVIOReenable(data->output_vio);
      }
      TSIOBufferBlock blk = TSIOBufferReaderStart(TSVIOReaderGet(write_vio));
      while (blk)
      {
        int64_t block_avail;
        const char *block_start = TSIOBufferBlockReadStart(blk, TSVIOReaderGet(write_vio), &block_avail);
        for (int64_t i = 0; i < block_avail; i++)
        {
          if (block_start[i] == '\n')
          {
            data->line_count++;
          }
        }
        // printf("%s", block_start);
        TSIOBufferWrite(data->output_buffer, block_start, block_avail);
        
        blk = TSIOBufferBlockNext(blk);
      }
      // TSIOBufferCopy(TSVIOBufferGet(data->output_vio), TSVIOReaderGet(write_vio), towrite, 0);

      TSIOBufferReaderConsume(TSVIOReaderGet(write_vio), towrite);
      TSVIONDoneSet(write_vio, TSVIONDoneGet(write_vio) + towrite);
      // printf("data->lines:%d\n", data->line_count);

      if (TSVIONTodoGet(write_vio) > 0)
      {
        if (towrite > 0) {
            // TSVIOReenable(data->output_vio);
            TSContCall(TSVIOContGet(write_vio), TS_EVENT_VCONN_WRITE_READY, write_vio);
        }
        
      }else
      {
        if (!data->footer_added)
        {
          data->footer_added = true;
          data->line_count++;
          int n  = data->line_count;
          int count = 0;
          do {
            n /= 10;
            ++count;
          } while (n != 0);
          data->footer_length += count;
          char line_count_str[count +1];
          memset(line_count_str, 0, count + 1);
          line_count_str[count+1] = '\0';
          snprintf(line_count_str, count+1,"%d", data->line_count);
         
          char footer_full[data->footer_length+2];
          memset(footer_full, 0, data->footer_length+2);
          footer_full[data->footer_length+2] = '\0';
          snprintf(footer_full, data->footer_length+2, "%s%s", FOOTER_PRE, line_count_str);
          data->footer = strdup(footer_full);

          printf("data->footer:%s:%d\n", data->footer,data->line_count);
         
         TSIOBufferWrite(data->output_buffer, data->footer, data->footer_length);
          // TSVIONBytesSet(data->output_vio, TSVIONDoneGet(write_vio) + data->header_length + data->footer_length);
         // TSVIOReenable(data->output_vio);
          data->output_vio = TSVConnWrite(output_conn, contp, data->output_reader, TSVIONDoneGet(write_vio) + data->header_length + data->footer_length);
          TSContCall(TSVIOContGet(write_vio), TS_EVENT_VCONN_WRITE_COMPLETE, write_vio);

        }
      }
    }
  }
}


static int
add_text_transform(TSCont contp, TSEvent event, void *edata ATS_UNUSED)
{
  if (TSVConnClosedGet(contp))
  {
    my_data_destroy(static_cast<MyData *>(TSContDataGet(contp)));
    TSContDestroy(contp);
    return 0;
  }
  else
  {
    switch (event)
    {
    case TS_EVENT_ERROR:
    {
      TSVIO write_vio;
      write_vio = TSVConnWriteVIOGet(contp);
      TSContCall(TSVIOContGet(write_vio), TS_EVENT_ERROR, write_vio);
    }
    break;
    case TS_EVENT_VCONN_WRITE_COMPLETE:
      TSVConnShutdown(TSTransformOutputVConnGet(contp), 0, 1);
      break;
    case TS_EVENT_VCONN_WRITE_READY:
    default:
      handle_transform(contp);
      break;
    }
  }

  return 0;
}

// static int
// transformable(TSHttpTxn txnp)
// {
//   int url_len;
//   const char *url = TSHttpTxnEffectiveUrlStringGet(txnp, &url_len);
//   printf("url: %s\n", url);

//   if (url && (url_len >= 5) && (strncmp(url + url_len - 5, ".m3u8", 5) == 0))
//   {
//     return 1;
//   }
//   return 0;
// }

static int transformable(TSHttpTxn txnp) {
    int url_len;
    const char* url = TSHttpTxnEffectiveUrlStringGet(txnp, &url_len);
    if (url) {
        printf("append_text_plugin", "URL: %.*s", url_len, url);

        // Find position of "?" if it exists
        const char* query_start = std::strchr(url, '?');
        int len_to_check = query_start ? query_start - url : url_len;

        // Check if the URL segment before the query parameters ends with ".m3u8"
        if (len_to_check >= 5 && strncmp(url + len_to_check - 5, ".m3u8", 5) == 0) {
            TSfree((void*)url);  
            return 1;
        }
        TSfree((void*)url);  
    }
    return 0;
}

static void
transform_add(TSHttpTxn txnp)
{
  TSVConn connp = TSTransformCreate(add_text_transform, txnp);
  TSHttpTxnHookAdd(txnp, TS_HTTP_RESPONSE_TRANSFORM_HOOK, connp);
}

static int
transform_plugin(TSCont contp ATS_UNUSED, TSEvent event, void *edata)
{
  TSHttpTxn txnp = static_cast<TSHttpTxn>(edata);

  switch (event)
  {
  case TS_EVENT_HTTP_READ_RESPONSE_HDR:
    if (transformable(txnp))
    {
      transform_add(txnp);
    }
    TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
    return 0;
  default:
    break;
  }

  return 0;
}

void TSPluginInit(int argc, const char *argv[])
{
  TSPluginRegistrationInfo info;

  info.plugin_name = PLUGIN_NAME;
  info.vendor_name = "Your Name";
  info.support_email = "your_email@example.com";

  if (TSPluginRegister(&info) != TS_SUCCESS)
  {
    TSError("[%s] Plugin registration failed", PLUGIN_NAME);
    return;
  }

  if (argc != 2)
  {
    TSError("[%s] Usage: %s <prepend_text>", PLUGIN_NAME, argv[0]);
    return;
  }
  filepath = strdup(argv[1]);

  TSHttpHookAdd(TS_HTTP_READ_RESPONSE_HDR_HOOK, TSContCreate(transform_plugin, nullptr));
}