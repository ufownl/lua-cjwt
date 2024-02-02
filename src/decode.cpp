#include "decode.hpp"
#include <l8w8jwt/decode.h>
#define JSMN_STATIC
#include <jsmn.h>
#define CHECKNUM_STATIC
#include <checknum.h>
#include <vector>
#include <string>
#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>

namespace {

using jsmntok_v = std::vector<jsmntok_t>;
jsmntok_v::const_iterator obj2table(lua_State* L, const char* json, jsmntok_v::const_iterator l, jsmntok_v::const_iterator r);
jsmntok_v::const_iterator arr2table(lua_State* L, const char* json, jsmntok_v::const_iterator l, jsmntok_v::const_iterator r);

void json2table(lua_State* L, const char* json, size_t json_length) {
  jsmn_parser p;
  jsmn_init(&p);
  auto n = jsmn_parse(&p, json, json_length, nullptr, 0);
  if (n < 0) {
    luaL_error(L, "Invalid object/array claim: JSON parsing error");
  }
  if (n == 0) {
    lua_newtable(L);
    return;
  }
  jsmntok_v tokens(n);
  jsmn_init(&p);
  if (jsmn_parse(&p, json, json_length, tokens.data(), tokens.size()) < 0) {
    luaL_error(L, "Invalid object/array claim: JSON parsing error");
  }
  switch (tokens.front().type) {
    case JSMN_OBJECT:
      obj2table(L, json, tokens.begin() + 1, tokens.end());
      break;
    case JSMN_ARRAY:
      arr2table(L, json, tokens.begin() + 1, tokens.end());
      break;
    default:
      luaL_error(L, "Invalid object/array claim: unknown token type %d", tokens.front().type);
  }
}

std::string unescape_json_str(const char* in, size_t n) {
  std::string out;
  out.reserve(n);
  for (size_t i = 0; i < n; ++i) {
    auto c = in[i];
    if (c == '\\' && i + 1 < n) {
      switch (in[i + 1]) {
        case '"':
          c = '"';
          ++i;
          break;
        case '\\':
          c = '\\';
          ++i;
          break;
        case '/':
          c = '/';
          ++i;
          break;
        case 'b':
          c = '\b';
          ++i;
          break;
        case 'f':
          c = '\f';
          ++i;
          break;
        case 'n':
          c = '\n';
          ++i;
          break;
        case 'r':
          c = '\r';
          ++i;
          break;
        case 't':
          c = '\t';
          ++i;
          break;
      }
    }
    out.push_back(c);
  }
  return out;
}

void parse_primitive(lua_State* L, const char* in, size_t n) {
  switch (checknum(const_cast<char*>(in), n)) {
    case 1:
      lua_pushinteger(L, std::strtoll(in, nullptr, 0));
      return;
    case 2:
      lua_pushnumber(L, std::strtod(in, nullptr));
      return;
  }
  if (n == 5 && strncmp(in, "false", 5) == 0) {
    lua_pushboolean(L, false);
    return;
  }
  if (n == 4) {
    if (strncmp(in, "true", 4) == 0) {
      lua_pushboolean(L, true);
      return;
    }
    if (strncmp(in, "null", 4) == 0) {
      lua_pushnil(L);
      return;
    }
  }
  luaL_error(L, "Invalid primitive value");
}

jsmntok_v::const_iterator parse_value(lua_State* L, const char* json, jsmntok_v::const_iterator i, jsmntok_v::const_iterator r) {
  auto& v = *i;
  auto p = [&](const jsmntok_t& t) {
    return t.end > v.end;
  };
  switch (v.type) {
    case JSMN_OBJECT:
      return obj2table(L, json, i + 1, std::find_if(i + 1, r, p));
    case JSMN_ARRAY:
      return arr2table(L, json, i + 1, std::find_if(i + 1, r, p));
    case JSMN_STRING: {
      auto value = unescape_json_str(json + v.start, v.end - v.start);
      lua_pushlstring(L, value.data(), value.size());
      break;
    }
    case JSMN_PRIMITIVE:
      parse_primitive(L, json + v.start, v.end - v.start);
      break;
    default:
      luaL_error(L, "Invalid object token: undefined value type");
  }
  return i + 1;
}

jsmntok_v::const_iterator obj2table(lua_State* L, const char* json, jsmntok_v::const_iterator l, jsmntok_v::const_iterator r) {
  lua_newtable(L);
  for (auto i = l; i != r;) {
    auto& k = *i;
    if (k.type != JSMN_STRING) {
      luaL_error(L, "Invalid object token: key must be a string");
    }
    if (++i == r) {
      luaL_error(L, "Invalid object token: key has no corresponding value");
    }
    auto key = unescape_json_str(json + k.start, k.end - k.start);
    lua_pushlstring(L, key.data(), key.size());
    i = parse_value(L, json, i, r);
    lua_settable(L, -3);
  }
  return r;
}

jsmntok_v::const_iterator arr2table(lua_State* L, const char* json, jsmntok_v::const_iterator l, jsmntok_v::const_iterator r) {
  lua_newtable(L);
  size_t index = 0;
  for (auto i = l; i != r;) {
    lua_pushinteger(L, ++index);
    i = parse_value(L, json, i, r);
    lua_settable(L, -3);
  }
  return r;
}

}

namespace cjwt {

int decode(lua_State* L) {
  auto nargs = lua_gettop(L);
  luaL_checktype(L, 1, LUA_TSTRING);
  if (nargs > 1) {
    luaL_checktype(L, 2, LUA_TNUMBER);
    luaL_checktype(L, 3, LUA_TSTRING);
    if (nargs > 3) {
      luaL_checktype(L, 4, LUA_TTABLE);
    }
  }
  l8w8jwt_decoding_params params;
  l8w8jwt_decoding_params_init(&params);
  params.jwt = const_cast<char*>(lua_tolstring(L, 1, &params.jwt_length));
  if (nargs > 1) {
    params.alg = lua_tointeger(L, 2);
    params.verification_key = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(lua_tolstring(L, 3, &params.verification_key_length)));
    if (nargs > 3) {
      lua_getfield(L, 4, "iss");
      if (!lua_isnil(L, -1)) {
        params.validate_iss = const_cast<char*>(lua_tolstring(L, -1, &params.validate_iss_length));
        if (!params.validate_iss) {
          luaL_error(L, "Invalid JWT validation: iss must be a string");
        }
      }
      lua_pop(L, 1);
      lua_getfield(L, 4, "sub");
      if (!lua_isnil(L, -1)) {
        params.validate_sub = const_cast<char*>(lua_tolstring(L, -1, &params.validate_sub_length));
        if (!params.validate_sub) {
          luaL_error(L, "Invalid JWT validation: sub must be a string");
        }
      }
      lua_pop(L, 1);
      lua_getfield(L, 4, "aud");
      if (!lua_isnil(L, -1)) {
        params.validate_aud = const_cast<char*>(lua_tolstring(L, -1, &params.validate_aud_length));
        if (!params.validate_aud) {
          luaL_error(L, "Invalid JWT validation: aud must be a string");
        }
      }
      lua_pop(L, 1);
      lua_getfield(L, 4, "jti");
      if (!lua_isnil(L, -1)) {
        params.validate_jti = const_cast<char*>(lua_tolstring(L, -1, &params.validate_jti_length));
        if (!params.validate_jti) {
          luaL_error(L, "Invalid JWT validation: jti must be a string");
        }
      }
      lua_pop(L, 1);
      lua_getfield(L, 4, "exp");
      if (!lua_isnil(L, -1)) {
        if (!lua_isboolean(L, -1)) {
          luaL_error(L, "Invalid JWT validation: exp must be a boolean");
        }
        params.validate_exp = lua_toboolean(L, -1);
      }
      lua_pop(L, 1);
      lua_getfield(L, 4, "nbf");
      if (!lua_isnil(L, -1)) {
        if (!lua_isboolean(L, -1)) {
          luaL_error(L, "Invalid JWT validation: nbf must be a boolean");
        }
        params.validate_nbf = lua_toboolean(L, -1);
      }
      lua_pop(L, 1);
      lua_getfield(L, 4, "iat");
      if (!lua_isnil(L, -1)) {
        if (!lua_isboolean(L, -1)) {
          luaL_error(L, "Invalid JWT validation: iat must be a boolean");
        }
        params.validate_iat = lua_toboolean(L, -1);
      }
      lua_pop(L, 1);
      lua_getfield(L, 4, "exp_tolerance");
      if (!lua_isnil(L, -1)) {
        if (!lua_isnumber(L, -1)) {
          luaL_error(L, "Invalid JWT validation: exp_tolerance must be a uint8");
        }
        auto value = lua_tointeger(L, -1);
        if (value < 0 || value > 0xFF) {
          luaL_error(L, "Invalid JWT validation: exp_tolerance must be a uint8");
        }
        params.exp_tolerance_seconds = static_cast<uint8_t>(value);
      }
      lua_pop(L, 1);
      lua_getfield(L, 4, "nbf_tolerance");
      if (!lua_isnil(L, -1)) {
        if (!lua_isnumber(L, -1)) {
          luaL_error(L, "Invalid JWT validation: nbf_tolerance must be a uint8");
        }
        auto value = lua_tointeger(L, -1);
        if (value < 0 || value > 0xFF) {
          luaL_error(L, "Invalid JWT validation: nbf_tolerance must be a uint8");
        }
        params.nbf_tolerance_seconds = static_cast<uint8_t>(value);
      }
      lua_pop(L, 1);
      lua_getfield(L, 4, "iat_tolerance");
      if (!lua_isnil(L, -1)) {
        if (!lua_isnumber(L, -1)) {
          luaL_error(L, "Invalid JWT validation: iat_tolerance must be a uint8");
        }
        auto value = lua_tointeger(L, -1);
        if (value < 0 || value > 0xFF) {
          luaL_error(L, "Invalid JWT validation: iat_tolerance must be a uint8");
        }
        params.iat_tolerance_seconds = static_cast<uint8_t>(value);
      }
      lua_pop(L, 1);
      lua_getfield(L, 4, "typ");
      if (!lua_isnil(L, -1)) {
        params.validate_typ = const_cast<char*>(lua_tolstring(L, -1, &params.validate_typ_length));
        if (!params.validate_typ) {
          luaL_error(L, "Invalid JWT validation: typ must be a string");
        }
      }
      lua_pop(L, 1);
    }
  } else {
    params.alg = -1;
    params.verification_key = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>("lua-cjwt"));
    params.verification_key_length = 8;
  }
  l8w8jwt_validation_result vc;
  l8w8jwt_claim* claims = nullptr;
  size_t claims_count;
  auto rc = l8w8jwt_decode(&params, &vc, &claims, &claims_count);
  lua_pushinteger(L, rc);
  if (rc == L8W8JWT_SUCCESS) {
    lua_pushinteger(L, vc);
    lua_newtable(L);
    for (size_t i = 0; i < claims_count; ++i) {
      switch (claims[i].type) {
        case L8W8JWT_CLAIM_TYPE_STRING:
          lua_pushlstring(L, claims[i].value, claims[i].value_length);
          break;
        case L8W8JWT_CLAIM_TYPE_INTEGER:
          lua_pushinteger(L, std::strtoll(claims[i].value, nullptr, 0));
          break;
        case L8W8JWT_CLAIM_TYPE_NUMBER:
          lua_pushnumber(L, std::strtod(claims[i].value, nullptr));
          break;
        case L8W8JWT_CLAIM_TYPE_BOOLEAN:
          lua_pushboolean(L, claims[i].value_length < 5);
          break;
        case L8W8JWT_CLAIM_TYPE_NULL:
          lua_pushnil(L);
          break;
        case L8W8JWT_CLAIM_TYPE_ARRAY:
        case L8W8JWT_CLAIM_TYPE_OBJECT:
          json2table(L, claims[i].value, claims[i].value_length);
          break;
        default:
          lua_pushfstring(L, "Unsupported claim type: %d", claims[i].type);
      }
      lua_setfield(L, -2, claims[i].key);
    }
  } else {
    lua_pushnil(L);
    lua_pushnil(L);
  }
  if (claims) {
    l8w8jwt_free_claims(claims, claims_count);
  }
  return 3;
}

}
