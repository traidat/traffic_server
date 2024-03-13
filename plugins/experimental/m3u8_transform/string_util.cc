#include "ink_autoconf.h"
#include <fstream>
#include <algorithm>
#include <vector>
#include <fnmatch.h>

using namespace std;

void
ltrim_if(string &s, int (*fp)(int))
{
  for (size_t i = 0; i < s.size();) {
    if (fp(s[i])) {
      s.erase(i, 1);
    } else {
      break;
    }
  }
}

void
rtrim_if(string &s, int (*fp)(int))
{
  for (ssize_t i = static_cast<ssize_t>(s.size()) - 1; i >= 0; i--) {
    if (fp(s[i])) {
      s.erase(i, 1);
    } else {
      break;
    }
  }
}

void
trim_if(string &s, int (*fp)(int))
{
  ltrim_if(s, fp);
  rtrim_if(s, fp);
}


string remove_filename_from_path(string path, int* path_length) {
    size_t last_slash_pos = path.rfind('/');
    if (last_slash_pos != string::npos) {
    path = path.substr(0, last_slash_pos + 1);
    *(path_length) = *(path_length) - (*path_length - last_slash_pos);
    }

    return path;
}