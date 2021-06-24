cmake_minimum_required(VERSION 3.0)
project(libltnginx)

include_directories("lib/liblpm")

set(CFLAGS "-Os -s")
set(LDFLAGS "-s")

set(CMAKE_C_FLAGS ${CFLAGS})
set(CMAKE_CXX_FLAGS ${CFLAGS})
set(CMAKE_EXE_LINKER_FLAGS ${LDFLAGS})

file(GLOB_RECURSE ltnginx_SRC
    "src/*.h"
    "src/*.c"
    "src/*.cpp"
)

add_library(ltnginx SHARED
    ${ltnginx_SRC}
    "lib/liblpm/lpm.c"
)

add_executable(test_whois "test/whois.c")
target_link_libraries(test_whois ltnginx)
