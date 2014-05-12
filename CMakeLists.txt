cmake_minimum_required(VERSION 2.8)

include(FindOpenSSL)

find_package(PythonLibs REQUIRED)
find_package(PythonInterp REQUIRED)
if(NOT PYTHONLIBS_FOUND OR NOT PYTHON_EXECUTABLE)
    message(FATAL "You need Python to build Python binding")
endif()

if(NOT OPENSSL_FOUND)
    message(FATAL "OpenSSL not found!")
endif()

include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${PYTHON_INCLUDE_DIRS})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

add_definitions(
    -Wall
    -pedantic
    -Werror
    -Wno-long-long
    -Wno-unknown-pragmas
    -std=gnu99
    -fno-strict-aliasing  # when Python authors write a line of code, kitten dies
    )

option(DEBUG_ECDSA "Display debug messages on stderr" FALSE)

if (DEBUG_ECDSA)
    add_definitions(-DDEBUG_ECDSA)
endif()

if (${CMAKE_SYSTEM_NAME} MATCHES Linux)
    set (RESOLVLIB resolv)
endif()

file(GLOB SOURCES "src/*.[ch]")
add_library(ecdsa SHARED ${SOURCES})
set_target_properties(ecdsa PROPERTIES PREFIX "")
target_link_libraries(ecdsa ${RESOLVLIB} ${PYTHON_LIBRARIES} ${OPENSSL_LIBRARIES})

