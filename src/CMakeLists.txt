find_package(LuaJIT REQUIRED)

aux_source_directory(. SOURCES)
add_library(cjwt MODULE ${SOURCES})
target_include_directories(cjwt PRIVATE ${LUA_INCLUDE_DIR})
target_include_directories(cjwt PRIVATE ${CJWT_SOURCE_DIR}/3rdparty/l8w8jwt/lib/jsmn)
target_include_directories(cjwt PRIVATE ${CJWT_SOURCE_DIR}/3rdparty/l8w8jwt/lib/checknum/include)
target_link_libraries(cjwt PRIVATE ${LUA_LIBRARIES} l8w8jwt)
set_target_properties(cjwt PROPERTIES PREFIX "" SUFFIX ".so")

get_filename_component(LUA_LIBRARY_DIR ${LUA_LIBRARY} PATH)
set(LUA_MODULE_DIR "${LUA_LIBRARY_DIR}/lua/5.1")
install(TARGETS cjwt DESTINATION ${LUA_MODULE_DIR})
