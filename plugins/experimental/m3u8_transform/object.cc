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

struct TxnData {
  string prefix;
  int prefix_length;
  string query_string;
  int query_string_length;
  Config* config;
  string time_shift;
  bool should_add_time_shift;
};

struct IOBufferData {
  TSVIO output_vio;
  TSIOBuffer output_buffer;
  TSIOBufferReader output_reader;
  int file_size;
  string file_content;
  TxnData *txn_data;
  bool is_external_txn_data;
};

TxnData* 
txn_data_alloc(string prefix, int prefix_length, string query_string, int query_string_length, Config* cfg, string time_shift) {
  TxnData *data = new TxnData();
  data->prefix = prefix;
  data->prefix_length = prefix_length;
  data->query_string = query_string;
  data->query_string_length = query_string_length;
  data->config = cfg;
  data->time_shift = time_shift;
  data->should_add_time_shift = false;
  return data;
}


IOBufferData* 
iobuffer_data_alloc(TxnData *txn_data, bool is_external_txn_data) {
  IOBufferData *data = new IOBufferData();
  data->output_vio    = nullptr;
  data->output_buffer = nullptr;
  data->output_reader = nullptr;
  data->file_size = 0;
  data->txn_data = txn_data;
  data->is_external_txn_data = is_external_txn_data;
  return data;
}

IOBufferData* 
iobuffer_data_alloc(TxnData *txn_data) {
  return iobuffer_data_alloc(txn_data, true);
}

void update_file_content(IOBufferData *data, string file_content) {
  data->file_content = file_content;
}

void append_file_content(IOBufferData *data, string file_content) {
  data->file_content = data->file_content + file_content;
}

void update_file_size(IOBufferData *data, int file_size) {
  data->file_size = data->file_size + file_size;
}

void iobuffer_data_destroy(IOBufferData *data) {
  if (data) {
    if (data->output_reader) {
      TSIOBufferReaderFree(data->output_reader);
    }
    if (data->output_buffer) {
      TSIOBufferDestroy(data->output_buffer);
    }

    if (!data->is_external_txn_data) {
      delete data->txn_data;
    }
    
    delete data;
  }
}

void txn_data_destroy(TxnData *data) {
  delete data;
}

void free_cfg(Config *cfg) {
  TSDebug(PLUGIN_NAME, "Cleaning up config");
  delete cfg;
}