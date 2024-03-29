# Locate LuaJIT library
# This module defines
#  LUAJIT_FOUND, if false, do not try to link to Lua
#  LUA_LIBRARIES
#  LUA_INCLUDE_DIR, where to find lua.h
#  LUAJIT_VERSION_STRING, the version of Lua found (since CMake 2.8.8)

## Copied from default CMake FindLua51.cmake

find_path(LUA_INCLUDE_DIR luajit.h
  HINTS
    ENV LUA_DIR
  PATH_SUFFIXES include/luajit-2.0 include/luajit-2.1 include
  PATHS
  ~/Library/Frameworks
  /Library/Frameworks
  /sw # Fink
  /opt/local # DarwinPorts
  /opt/csw # Blastwave
  /opt
  /usr/local/openresty/luajit/ # openresty
)

find_library(LUA_LIBRARY
  NAMES luajit-5.1 luajit-5.2
  HINTS
    ENV LUA_DIR
  PATH_SUFFIXES lib
  PATHS
  ~/Library/Frameworks
  /Library/Frameworks
  /sw
  /opt/local
  /opt/csw
  /opt
  /usr/local/openresty/luajit/ # openresty
)

if(LUA_LIBRARY)
  set( LUA_LIBRARIES "${LUA_LIBRARY}" CACHE STRING "Lua Libraries")
endif()

if(LUA_INCLUDE_DIR AND EXISTS "${LUA_INCLUDE_DIR}/luajit.h")
  file(STRINGS "${LUA_INCLUDE_DIR}/luajit.h" luajit_version_str REGEX "^#define[ \t]+LUAJIT_VERSION[ \t]+\"LuaJIT .+\"")
  string(REGEX REPLACE "^#define[ \t]+LUAJIT_VERSION[ \t]+\"LuaJIT ([^\"]+)\".*" "\\1" LUAJIT_VERSION_STRING "${luajit_version_str}")
  unset(luajit_version_str)
endif()

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set LUA_FOUND to TRUE if
# all listed variables are TRUE
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LuaJIT
                                  REQUIRED_VARS LUA_LIBRARIES LUA_INCLUDE_DIR
                                  VERSION_VAR LUAJIT_VERSION_STRING)

mark_as_advanced(LUA_INCLUDE_DIR LUA_LIBRARIES LUA_LIBRARY LUA_MATH_LIBRARY)

