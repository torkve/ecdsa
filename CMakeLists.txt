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
    -std=gnu99
    -pedantic
    -fno-strict-aliasing  # when Python authors write a line of code, kitten dies
    -Wall
    -Werror
    -Wuninitialized
    -Wignored-qualifiers
    -Wshadow
    -Wno-long-long
    -Wno-unknown-pragmas
    )

option(DEBUG_ECDSA "Display debug messages on stderr" FALSE)

if (DEBUG_ECDSA)
    add_definitions(-DDEBUG_ECDSA)
endif()

if (${CMAKE_SYSTEM_NAME} MATCHES Linux)
    set (RESOLVLIB resolv)
endif()

file(GLOB SOURCES "src/*.[ch]")
python_add_module(ecdsa ${SOURCES})
set_target_properties(ecdsa PROPERTIES PREFIX "")  # older CMake versions don't remove prefix on their own
target_link_libraries(ecdsa ${RESOLVLIB} ${PYTHON_LIBRARIES} ${OPENSSL_LIBRARIES})

option(INSTALL_DIR "Relative to prefix directory where to install" "")
if (NOT INSTALL_DIR)
    execute_process(
        COMMAND ${PYTHON_EXECUTABLE} -c "import site, sys; sys.stdout.write(site.PREFIXES[-1])"
        OUTPUT_VARIABLE PYTHON_PREFIX
        )
    file(TO_CMAKE_PATH "${PYTHON_PREFIX}" PYTHON_PREFIX)
    execute_process(
        COMMAND ${PYTHON_EXECUTABLE} -c "import site, sys; sys.stdout.write(site.getsitepackages()[-1])"
        OUTPUT_VARIABLE PYTHON_SITE_DIR
        )
    file(TO_CMAKE_PATH "${PYTHON_SITE_DIR}" PYTHON_SITE_DIR)
    string(REGEX REPLACE "^${PYTHON_PREFIX}/" "" PYTHON_SITE_DIR "${PYTHON_SITE_DIR}")
    message(STATUS "Python prefix is: ${PYTHON_PREFIX}")
    message(STATUS "Python site dir is: ${PYTHON_SITE_DIR}")
else()
    set(PYTHON_SITE_DIR "${INSTALL_DIR}")
endif()

install(TARGETS ecdsa LIBRARY DESTINATION ${PYTHON_SITE_DIR} COMPONENT library)

enable_testing()
add_test(
    NAME key_test
    COMMAND ${PYTHON_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_key.py"
    WORKING_DIRECTORY ${CMAKE_BUILD_DIR}
    )
set_tests_properties(key_test PROPERTIES ENVIRONMENT PYTHONPATH=${CMAKE_BUILD_DIR})
