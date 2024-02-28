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

#define PLUGIN_NAME "m3u8_transform"


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

string remove_filename_from_path(string path, int* path_length) {
    size_t last_slash_pos = path.rfind('/');
    if (last_slash_pos != string::npos) {
    path = path.substr(0, last_slash_pos + 1);
    *(path_length) = *(path_length) - (*path_length - last_slash_pos);
    }

    return path;
}

// Remove parameter that not process in origin, append those parameter to every link in m3u8 file later
string optimize_query_param(string query_param, int* query_param_length, set<string> origin_param, TSMBuffer buf, TSMLoc loc) {
    istringstream paramstream(query_param);
    string param;
    
    string request_origin_param = ""; // They are parameter that we keep and send to origin
    string next_request_param = ""; // They are parameter that we do not send to origin, but we will add them to every link in file m3u8'
    while (getline(paramstream, param, '&')) {
        int pos = param.find("=");
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
    }

    if (request_origin_param.size() == 0) {
        if (TS_SUCCESS != TSUrlHttpQuerySet(buf, loc, request_origin_param.c_str(), -1)) {
            TSDebug(PLUGIN_NAME, "Cannot set empty request parameter");
        }
    } else if (request_origin_param.size() > 0 && TS_SUCCESS != TSUrlHttpQuerySet(buf, loc, request_origin_param.c_str(), request_origin_param.size())) {
        TSDebug(PLUGIN_NAME, "Cannot set request parameter: %s", request_origin_param.c_str());
    }
    int length = 0;
    const char* query_param_test = TSUrlHttpQueryGet(buf, loc, &length);
    string query_param_str(query_param_test, length);
    TSDebug(PLUGIN_NAME, "Query param after: %s with length %d", query_param_test, length);

    *query_param_length = next_request_param.size();
    return next_request_param;
}

