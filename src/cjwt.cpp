#include "cjwt.hpp"
#include "algs.hpp"
#include "encode.hpp"
#include "decode.hpp"
#include "null.hpp"

int luaopen_cjwt(lua_State* L) {
  constexpr const luaL_Reg entries[] = {
    {"encode", cjwt::encode},
    {"decode", cjwt::decode},
    {"null", cjwt::null},
    {nullptr, nullptr}
  };
  lua_newtable(L);
  luaL_register(L, nullptr, entries);
  lua_pushliteral(L, "cjwt");
  lua_setfield(L, -2, "_NAME");
  lua_pushliteral(L, "1.0");
  lua_setfield(L, -2, "_VERSION");
  lua_newtable(L);
  for (auto& alg: cjwt::algs) {
    lua_pushinteger(L, &alg - cjwt::algs);
    lua_setfield(L, -2, alg);
  }
  lua_setfield(L, -2, "algs");
  return 1;
}
