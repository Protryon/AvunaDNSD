cmake_minimum_required(VERSION 3.12)
project(avuna-dnsd C)

set(CMAKE_VERBOSE_MAKEFILE on)

set(CMAKE_C_STANDARD 11)

option(MYSQL "Builds MySQL support" ON)

set(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -Wno-discarded-qualifiers")

if (MYSQL)
    set(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -DSUPPORTS_MYSQL")
endif()

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG")


file(GLOB dnsd_src
    "src/*.h"
    "src/*.c"
)

add_executable(avuna-dnsd ${dnsd_src})
target_link_libraries(avuna-dnsd -lavuna-util -lpthread)
if (MYSQL)
    target_link_libraries(avuna-dnsd -lmysqlclient)
endif()