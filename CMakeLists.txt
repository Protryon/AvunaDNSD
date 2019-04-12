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

file(GLOB lib_src
    "lib/src/*.h"
    "lib/src/*.c"
)


add_executable(avuna-dnsd ${dnsd_src})
target_link_libraries(avuna-dnsd -lavuna-util -lpthread avuna-dns)
target_include_directories(avuna-dnsd PRIVATE lib/include/)
if (MYSQL)
    target_link_libraries(avuna-dnsd -lmysqlclient)
endif()

add_library(avuna-dns SHARED ${lib_src})
target_link_libraries(avuna-dns -lavuna-util)
target_include_directories(avuna-dns PUBLIC lib/include/)


install(TARGETS avuna-dns
        LIBRARY DESTINATION lib)

install(TARGETS avuna-dnsd
        RUNTIME DESTINATION bin)

file(GLOB export_headers
    "lib/include/avuna/*.h"
)

file(GLOB config_files
    "cfg-default/*"
)

install(FILES ${export_headers} DESTINATION "include/avuna/")
install(FILES ${config_files} DESTINATION "/etc/avuna/dnsd/")

set(CPACK_DEBIAN_PACKAGE_NAME avunadnsd)
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_PACKAGE_VERSION 3.0.0)
if (MYSQL)
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "libmysqlclient20 (>= 5.7.25), avunautils (>= 1.0.0)")
endif()
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Max Bruce")
set(CPACK_DEBIAN_PACKAGE_DESCRIPTION "Adaptable authoritative nameserver")
set(CPACK_GENERATOR DEB)

include(CPack)