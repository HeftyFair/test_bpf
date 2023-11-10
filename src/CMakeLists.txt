project(test_bpf VERSION 0.1.0 LANGUAGES C)
set(CMAKE_C_COMPILER clang)
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -target bpf")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -Wall -target bpf -I/usr/include/aarch64-linux-gnu")



include_directories("/usr/include/aarch64-linux-gnu" "include" ${LIBBPF_INCLUDE_DIRS})
#include_directories()
#include_directories("include")


file(GLOB SOURCES "*.c")
foreach(source ${SOURCES})

    get_filename_component(name ${source} NAME_WE)
    add_library(${name} OBJECT ${source})
    
    target_link_libraries(${name} ${LIBBPF_LIBRARIES})
    #target_link_libraries(${name} bcc-static)
    set_target_properties(${name} PROPERTIES OUTPUT_NAME ${name}.o)
endforeach()

