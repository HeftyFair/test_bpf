cmake_minimum_required(VERSION 3.0.0)
project(runBPF VERSION 0.1.0 LANGUAGES C)


message("${LIBBPF_LIBRARIES}")


add_executable(runBPF app.c)
target_link_libraries(runBPF bpf)