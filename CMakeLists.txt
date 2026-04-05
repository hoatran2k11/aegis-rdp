cmake_minimum_required(VERSION 3.10)

project(AegisRDP VERSION 0.3.0)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include_directories(src/include)

file(GLOB SOURCES "src/*.c")

add_executable(aegisrdp ${SOURCES})

target_link_libraries(aegisrdp 
    wevtapi 
    advapi32 
    ws2_32
)

if(MSVC)
    target_compile_options(aegisrdp PRIVATE /W4 /O2 /MT)
    target_compile_definitions(aegisrdp PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

set_target_properties(aegisrdp PROPERTIES OUTPUT_NAME "aegisrdp")