#include "cjwt.hpp"
#include <l8w8jwt/encode.h>
#include <vector>
#include <cstdint>
#include <cstring>

namespace {

constexpr const char* algs[] = {"HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "ES256K", "ED25519"};

l8w8jwt_claim parse_additional_claim(lua_State* L, const char* key, size_t key_length) {
  l8w8jwt_claim claim;
  claim.key = const_cast<char*>(key);
  claim.key_length = key_length;
  switch (lua_type(L, -1)) {
    case LUA_TBOOLEAN:
      if (lua_toboolean(L, -1)) {
        claim.value = const_cast<char*>("true");
        claim.value_length = 4;
      } else {
        claim.value = const_cast<char*>("false");
        claim.value_length = 5;
      }
      claim.type = L8W8JWT_CLAIM_TYPE_BOOLEAN;
      break;
    case LUA_TNUMBER:
      claim.value = const_cast<char*>(lua_tolstring(L, -1, &claim.value_length));
      claim.type = std::strchr(claim.value, '.') ? L8W8JWT_CLAIM_TYPE_NUMBER : L8W8JWT_CLAIM_TYPE_INTEGER;
      break;
    case LUA_TSTRING:
      claim.value = const_cast<char*>(lua_tolstring(L, -1, &claim.value_length));
      claim.type = L8W8JWT_CLAIM_TYPE_STRING;
      break;
    default:
      luaL_error(L, "Unsupported value type");
  }
  return claim;
}

int cjwt_encode(lua_State* L) {
  auto nargs = lua_gettop(L);
  luaL_checktype(L, 1, LUA_TTABLE);
  luaL_checktype(L, 2, LUA_TTABLE);
  luaL_checktype(L, 3, LUA_TSTRING);
  if (nargs > 3) {
    luaL_checktype(L, 4, LUA_TSTRING);
  }
  l8w8jwt_encoding_params params;
  l8w8jwt_encoding_params_init(&params);
  std::vector<l8w8jwt_claim> header;
  lua_pushnil(L);
  while (lua_next(L, 1)) {
    if (lua_type(L, -2) != LUA_TSTRING) {
      luaL_error(L, "Invalid JWT header");
    }
    size_t key_length;
    auto key = lua_tolstring(L, -2, &key_length);
    if (std::strcmp(key, "alg") == 0) {
      if (lua_type(L, -1) != LUA_TSTRING) {
        luaL_error(L, "Invalid JWT header");
      }
      auto value = lua_tostring(L, -1);
      for (auto& alg: algs) {
        if (std::strcmp(value, alg) == 0) {
          params.alg = &alg - algs;
          break;
        }
      }
      if (params.alg < 0) {
        luaL_error(L, "Invalid JWT algorithm");
      }
    } else if (std::strcmp(key, "typ") != 0) {
      header.emplace_back(parse_additional_claim(L, key, key_length));
    }
    lua_pop(L, 1);
  }
  if (!header.empty()) {
    params.additional_header_claims = header.data();
    params.additional_header_claims_count = header.size();
  }
  std::vector<l8w8jwt_claim> payload;
  lua_pushnil(L);
  while (lua_next(L, 2)) {
    if (lua_type(L, -2) != LUA_TSTRING) {
      luaL_error(L, "Invalid JWT payload");
    }
    size_t key_length;
    auto key = lua_tolstring(L, -2, &key_length);
    if (std::strcmp(key, "iss") == 0) {
      params.iss = const_cast<char*>(lua_tolstring(L, -1, &params.iss_length));
    } else if (std::strcmp(key, "sub") == 0) {
      params.sub = const_cast<char*>(lua_tolstring(L, -1, &params.sub_length));
    } else if (std::strcmp(key, "aud") == 0) {
      params.aud = const_cast<char*>(lua_tolstring(L, -1, &params.aud_length));
    } else if (std::strcmp(key, "jti") == 0) {
      params.jti = const_cast<char*>(lua_tolstring(L, -1, &params.jti_length));
    } else if (std::strcmp(key, "exp") == 0) {
      params.exp = lua_tointeger(L, -1);
      if (params.exp == 0) {
        luaL_error(L, "Invalid JWT payload");
      }
    } else if (std::strcmp(key, "nbf") == 0) {
      params.nbf = lua_tointeger(L, -1);
      if (params.nbf == 0) {
        luaL_error(L, "Invalid JWT payload");
      }
    } else if (std::strcmp(key, "iat") == 0) {
      params.iat = lua_tointeger(L, -1);
      if (params.iat == 0) {
        luaL_error(L, "Invalid JWT payload");
      }
    } else {
      payload.emplace_back(parse_additional_claim(L, key, key_length));
    }
    lua_pop(L, 1);
  }
  if (!payload.empty()) {
    params.additional_payload_claims = payload.data();
    params.additional_payload_claims_count = payload.size();
  }
  params.secret_key = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(lua_tolstring(L, 3, &params.secret_key_length)));
  if (nargs > 3) {
    params.secret_key_pw = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(lua_tolstring(L, 3, &params.secret_key_pw_length)));
  }
  char* jwt = nullptr;
  size_t jwt_length;
  params.out = &jwt;
  params.out_length = &jwt_length;
  auto rc = l8w8jwt_encode(&params);
  lua_pushinteger(L, rc);
  if (rc == L8W8JWT_SUCCESS) {
    lua_pushlstring(L, jwt, jwt_length);
  } else {
    lua_pushnil(L);
  }
  if (jwt) {
    l8w8jwt_free(jwt);
  }
  return 2;
}

}

int luaopen_cjwt(lua_State* L) {
  constexpr const luaL_Reg entries[] = {
    {"encode", cjwt_encode},
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
