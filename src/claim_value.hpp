#ifndef CJWT_CLAIM_VALUE_HPP
#define CJWT_CLAIM_VALUE_HPP

#include <lua.hpp>

namespace cjwt { namespace claim_value {

struct impl {
  int type;
  char* data;
  size_t size;
};

void declare(lua_State* L);
impl* check(lua_State* L, int index);
impl* create(lua_State* L, int type, const char* data, size_t size);

} }

#endif  // CJWT_CLAIM_VALUE_HPP
