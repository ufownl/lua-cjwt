find_package(LuaJIT REQUIRED)
include_directories(${LUA_INCLUDE_DIR})
get_filename_component(LUA_LIBRARY_DIR ${LUA_LIBRARY} PATH)
set(LUA_MODULE_DIR "${LUA_LIBRARY_DIR}/lua/5.1")

include_directories(${CJWT_SOURCE_DIR}/3rdparty/l8w8jwt/lib/jsmn)
include_directories(${CJWT_SOURCE_DIR}/3rdparty/l8w8jwt/lib/checknum/include)

aux_source_directory(. SOURCES)
add_library(cjwt MODULE ${SOURCES})
target_link_libraries(cjwt PRIVATE ${LUA_LIBRARIES} l8w8jwt)
set_target_properties(cjwt PROPERTIES PREFIX "" SUFFIX ".so")
install(TARGETS cjwt DESTINATION ${LUA_MODULE_DIR})
