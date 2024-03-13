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
  Config* config;
};