cmake_minimum_required(VERSION 3.0.0)
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -target bpf")
project(myproj)
include(cmake/FindLibBpf.cmake)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)


find_package(LibBpf)

if(${LIBBPF_FOUND})
    message("found")
endif()


message("${LIBBPF_INCLUDE_DIRS}")




add_subdirectory(src)
add_subdirectory(app)

#add_executable(test_bpf main.c)
#target_link_libraries(test_bpf bpf)