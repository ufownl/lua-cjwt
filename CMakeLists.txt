cmake_minimum_required(VERSION 3.12)
project(CJWT)

set(CMAKE_MODULE_PATH ${CJWT_SOURCE_DIR}/cmake)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -fPIC")
# silence policy CMP0042 warning by enabling RPATH explicitly
if(APPLE AND NOT DEFINED CMAKE_MACOSX_RPATH)
  set(CMAKE_MACOSX_RPATH TRUE)
endif()

find_package(LuaJIT REQUIRED)
include_directories(${LUA_INCLUDE_DIR})
get_filename_component(LUA_LIBRARY_DIR ${LUA_LIBRARY} PATH)
set(LUA_MODULE_DIR "${LUA_LIBRARY_DIR}/lua/5.1")

add_subdirectory(src)
add_subdirectory(3rdparty/l8w8jwt)
