#include "cjwt.hpp"
#include <l8w8jwt/encode.h>
#include <iostream>

namespace {

constexpr const char* algs[] = {"HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "ES256K", "ED25519"};

}

int luaopen_cjwt(lua_State* L) {
  constexpr const luaL_Reg entries[] = {
    {nullptr, nullptr}
  };
  lua_newtable(L);
  luaL_register(L, nullptr, entries);
  lua_pushliteral(L, "cjwt");
  lua_setfield(L, -2, "_NAME");
  lua_pushliteral(L, "1.0");
  lua_setfield(L, -2, "_VERSION");
  lua_newtable(L);
  for (auto& alg: algs) {
    lua_pushinteger(L, &alg - algs);
    lua_setfield(L, -2, alg);
  }
  lua_setfield(L, -2, "algs");
  return 1;
}
