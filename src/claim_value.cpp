#include "claim_value.hpp"
#include <cstring>

namespace {

constexpr const char* name = "cjwt.claim_value";

int tostring(lua_State* L) {
  auto v = cjwt::claim_value::check(L, 1);
  lua_pushlstring(L, v->data, v->size);
  return 1;
}

}

namespace cjwt { namespace claim_value {

void declare(lua_State* L) {
  constexpr const luaL_Reg metatable[] = {
    {"__tostring", tostring},
    {nullptr, nullptr}
  };
  constexpr const luaL_Reg methods[] = {
    {nullptr, nullptr}
  };
  luaL_newmetatable(L, name);
  luaL_register(L, nullptr, metatable);
  lua_pushstring(L, name);
  lua_setfield(L, -2, "_NAME");
  lua_newtable(L);
  luaL_register(L, nullptr, methods);
  lua_setfield(L, -2, "__index");
}

impl* check(lua_State* L, int index) {
  if (!lua_isuserdata(L, index) || !luaL_checkudata(L, index, name)) {
    luaL_error(L, "Bad argument #%d, %s expected", index, name);
  }
  return static_cast<impl*>(lua_touserdata(L, index));
}

impl* create(lua_State* L, int type, const char* data, size_t size) {
  auto ud = static_cast<impl*>(lua_newuserdata(L, sizeof(impl) + size));
  ud->type = type;
  ud->data = reinterpret_cast<char*>(ud + 1);
  std::memcpy(ud->data, data, size);
  ud->size = size;
  luaL_getmetatable(L, name);
  lua_setmetatable(L, -2);
  return ud;
}

} }
