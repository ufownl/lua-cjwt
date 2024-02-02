#include "null.hpp"

namespace cjwt {

int null(lua_State* L) {
  lua_pushlightuserdata(L, nullptr);
  return 1;
}

}
