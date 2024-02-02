#ifndef CJWT_CLAIM_TYPE_HPP
#define CJWT_CLAIM_TYPE_HPP

#include <lua.hpp>

namespace cjwt {

int null(lua_State* L);
int array(lua_State* L);
int object(lua_State* L);

}

#endif  // CJWT_CLAIM_TYPE_HPP
