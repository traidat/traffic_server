#include <string>
#include <vector>

#include <ts/ts.h>
#include <ts/remap.h>
#include <set>

using namespace std;
#define PLUGIN_NAME "m3u8_transform"


struct Config {
  vector<string> keys;
  vector<string> hash_query_param;
  int param_num;
  string use_parts;
  int algorithm;  
  int knumber;
  set<string> origin_param;
  int enable_remove_line = 0;
  vector<string> removed_string;
};

struct ContData {
  TSVIO output_vio;
  TSIOBuffer output_buffer;
  TSIOBufferReader output_reader;
  string prefix;
  int prefix_length;
  string query_string;
  int query_string_length;
  int file_size;
  string file_content;
  Config* config;
  string time_shift;
  bool should_add_time_shift;
};

ContData* 
my_data_alloc_with_url(string prefix, int prefix_length, string query_string, int query_string_length, Config* cfg, string time_shift) {
  ContData *data = new ContData();
  data->output_vio    = nullptr;
  data->output_buffer = nullptr;
  data->output_reader = nullptr;
  data->prefix = prefix;
  data->prefix_length = prefix_length;
  data->query_string = query_string;
  data->query_string_length = query_string_length;
  data->file_size = 0;
  string empty("");
  data->file_content = empty;
  data->config = cfg;
  data->time_shift = time_shift;
  data->should_add_time_shift = false;
  return data;
}

void update_file_content(ContData* data, string file_content) {
  data->file_content = file_content;
}

void append_file_content(ContData* data, string file_content) {
  data->file_content = data->file_content + file_content;
}

void update_file_size(ContData* data, int file_size) {
  data->file_size = data->file_size + file_size;
}

void my_data_destroy(ContData* data) {
  if (data) {
    if (data->output_reader) {
      TSIOBufferReaderFree(data->output_reader);
    }
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