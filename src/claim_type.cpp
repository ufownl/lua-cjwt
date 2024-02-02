#include "claim_type.hpp"
#include "claim_value.hpp"
#include <l8w8jwt/claim.h>
#include <string>

namespace {

std::string json_escape(const char* in, size_t n) {
  constexpr const char* escape_table[] = {
    "\\u0000", "\\u0001", "\\u0002", "\\u0003", "\\u0004", "\\u0005", "\\u0006", "\\u0007",
    "\\b", "\\t", "\\n", "\\u000b", "\\f", "\\r", "\\u000e", "\\u000f",
    "\\u0010", "\\u0011", "\\u0012", "\\u0013", "\\u0014", "\\u0015", "\\u0016", "\\u0017",
    "\\u0018", "\\u0019", "\\u001a", "\\u001b", "\\u001c", "\\u001d", "\\u001e", "\\u001f",
    nullptr, nullptr, "\\\"", nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, "\\/",
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, nullptr, "\\\\", nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, "\\u007f",
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr
  };
  std::string out;
  out.reserve(n * 2);
  for (size_t i = 0; i < n; ++i) {
    auto rc = in[i];
    auto ec = escape_table[static_cast<uint8_t>(rc)];
    if (ec) {
      out.append(ec);
    } else {
      out.push_back(rc);
    }
  }
  return out;
}

void encode_value(lua_State* L, std::string& out) {
  switch (lua_type(L, -1)) {
    case LUA_TBOOLEAN:
      if (lua_toboolean(L, -1)) {
        out.append("true,", 5);
      } else {
        out.append("false,", 6);
      }
      break;
    case LUA_TNUMBER: {
      size_t n;
      auto s = lua_tolstring(L, -1, &n);
      out.append(s, n);
      out.push_back(',');
      break;
    }
    case LUA_TSTRING: {
      size_t n;
      auto s = lua_tolstring(L, -1, &n);
      out.push_back('"');
      out.append(json_escape(s, n));
      out.append("\",", 2);
      break;
    }
    case LUA_TLIGHTUSERDATA:
      if (lua_touserdata(L, -1)) {
        luaL_error(L, "Unsupported value type");
      }
      out.append("null,", 5);
      break;
    case LUA_TUSERDATA: {
      auto ud = cjwt::claim_value::check(L, -1);
      out.append(ud->data, ud->size);
      out.push_back(',');
      break;
    }
    default:
      luaL_error(L, "Unsupported value type");
  }
}

}

namespace cjwt {

int null(lua_State* L) {
  lua_pushlightuserdata(L, nullptr);
  return 1;
}

int array(lua_State* L) {
  luaL_checktype(L, 1, LUA_TTABLE);
  std::string s;
  s.push_back('[');
  lua_pushnil(L);
  while (lua_next(L, 1)) {
    if (lua_type(L, -2) != LUA_TNUMBER) {
      luaL_error(L, "Invalid array table: index must be a number");
    }
    encode_value(L, s);
    lua_pop(L, 1);
  }
  if (s.back() == ',') {
    s.back() = ']';
  } else {
    s.push_back(']');
  }
  claim_value::create(L, L8W8JWT_CLAIM_TYPE_ARRAY, s.data(), s.size());
  return 1;
}

int object(lua_State* L) {
  luaL_checktype(L, 1, LUA_TTABLE);
  std::string s;
  s.push_back('{');
  lua_pushnil(L);
  while (lua_next(L, 1)) {
    if (lua_type(L, -2) != LUA_TSTRING) {
      luaL_error(L, "Invalid object table: key must be a string");
    }
    size_t n;
    auto k = lua_tolstring(L, -2, &n);
    s.push_back('"');
    s.append(json_escape(k, n));
    s.append("\":", 2);
    encode_value(L, s);
    lua_pop(L, 1);
  }
  if (s.back() == ',') {
    s.back() = '}';
  } else {
    s.push_back('}');
  }
  claim_value::create(L, L8W8JWT_CLAIM_TYPE_OBJECT, s.data(), s.size());
  return 1;
}

}
