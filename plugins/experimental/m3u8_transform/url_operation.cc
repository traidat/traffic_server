#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <set>
#include <ts/ts.h>
#include <ts/remap.h>


#include "ink_autoconf.h"
#include "ts/ts.h"
#include "tscore/ink_defs.h"
#include "object.cc"

#define PLUGIN_NAME "m3u8_transform"
#define MAX_URL_LEN 100000
#define USIG_HMAC_SHA1 1
#define USIG_HMAC_MD5 2
#define SHA1_SIG_SIZE 20
#define MD5_SIG_SIZE 16
#define MAX_SIG_SIZE 20


using namespace std;


string get_schema(TSMBuffer buf, TSMLoc loc, int *length) {
    const char* scheme = TSUrlSchemeGet(buf, loc, length);
    string scheme_str(scheme, *length);
    return scheme_str;
}

string get_path(TSMBuffer buf, TSMLoc loc, int *length) {
    const char* path = TSUrlPathGet(buf, loc, length);
    string path_str(path, *length);
    return path;
}

string get_query_param(TSMBuffer buf, TSMLoc loc, int *length) {
    const char* query_param = TSUrlHttpQueryGet(buf, loc, length);
    string query_param_str(query_param, *length);
    return query_param_str;
}

string get_host(TSMBuffer buf, TSMLoc loc, int *length) {
    const char* host = TSUrlHostGet(buf, loc, length);
    string host_str(host, *length);
    return host_str;
}

string get_request_host(TSMBuffer buf, TSMLoc loc, int *length) {
    const char* host = TSHttpHdrHostGet(buf, loc, length);
    string host_str(host, *length);
    size_t end_host_pos = host_str.find("\r");
    if (end_host_pos != string::npos) {
        host_str = host_str.substr(0, end_host_pos);
    }
    *length = end_host_pos;

    return host_str;
}

extern "C" {
  bool
  generate_token(const char* url, Config* cfg, unsigned char* token, unsigned int* token_length) {
    const char *query = strchr(url, '?');
    char signed_part[MAX_URL_LEN] = {'\0'};
    char urltokstr[MAX_URL_LEN] = {'\0'};
    const char* cp = strchr(url, '?');
    int j = 0;
    // TSDebug(PLUGIN_NAME, "Url: %s", url);
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
    // TSDebug(PLUGIN_NAME, "Signed string=\"%s\"", signed_part);
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

// Remove parameter that not process in origin, append those parameter to every link in m3u8 file later
string optimize_query_param(string query_param, int* query_param_length, set<string> origin_param, TSMBuffer buf, TSMLoc loc) {
    istringstream paramstream(query_param);
    string param;

    string request_origin_param = ""; // They are parameter that we keep and send to origin
    string next_request_param = ""; // They are parameter that we do not send to origin, but we will add them to every link in file m3u8'
    while (getline(paramstream, param, '&')) {
      size_t pos = param.find("=");
      if (pos != string::npos) {
        string key = param.substr(0, pos);
        string value = param.substr(pos, param.size());
        if (origin_param.size() == 0 || key == "token" || origin_param.find(key) != origin_param.end()) {
            if (request_origin_param.size() == 0) {
                request_origin_param.append(param);
            } else {
                request_origin_param.append("&").append(param);
            }
        } else {
            if (next_request_param.size() == 0) {
                next_request_param.append(param);
            } else {
                next_request_param.append("&").append(param);
            }
        }
      } else {
        TSError("[m3u8_transform] Cannot get query param %s", param.c_str());
      }
    }

    TSDebug(PLUGIN_NAME, "Request origin param: %s", request_origin_param.c_str());
    TSDebug(PLUGIN_NAME, "Param not send to origin: %s", next_request_param.c_str());

    if (request_origin_param.size() == 0) {
        if (TS_SUCCESS != TSUrlHttpQuerySet(buf, loc, request_origin_param.c_str(), -1)) {
            TSError("[m3u8_transform] Cannot set empty request parameter");
        }
    } else if (request_origin_param.size() > 0 && TS_SUCCESS != TSUrlHttpQuerySet(buf, loc, request_origin_param.c_str(), request_origin_param.size())) {
        TSDebug(PLUGIN_NAME, "Cannot set request parameter: %s", request_origin_param.c_str());
    }

    *query_param_length = next_request_param.size();
    return next_request_param;
}

void deleteSecondLastLine(string& str) {
    size_t last_pos = str.find_last_of('\n');
    if (last_pos != string::npos) {
        size_t second_last_pos = str.find_last_of('\n', last_pos - 1);
        if (second_last_pos != string::npos) {
            str.erase(second_last_pos, last_pos - second_last_pos - 1);
        }
    }
}

int
rewrite_line_without_tag(std::string &line, const std::string &prefix, const std::string &query_string, std::string &result,
                         Config *cfg)
{
  if (cfg->enable_remove_line == 1) {
    for (int i = 0; i < (int) cfg->removed_string.size(); i++) {
      if (line.find(cfg->removed_string.at(i)) != string::npos) {
        return 0;
      }
    }
  }
  if (line.find(".ts") != string::npos || line.find(".m3u8") != string::npos || line.find(".m4s") != string::npos ||
      line.find(".mp4") != string::npos) {
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
    unsigned int token_length             = 0;
    bool is_success                       = generate_token(url.c_str(), cfg, token, &token_length);
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
  return 1;
}

void
rewrite_line_with_tag(std::string &line, const std::string &prefix, const std::string &query_string, std::string &result,
                      Config *cfg)
{
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
      unsigned int token_length             = 0;
      bool is_success                       = generate_token(url.c_str(), cfg, token, &token_length);
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
