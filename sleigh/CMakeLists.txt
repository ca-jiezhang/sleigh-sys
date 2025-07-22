cmake_minimum_required(VERSION 3.10)

project(sleigh)

set(CMAKE_CXX_STANDARD_REQUIRED on)
set(CMAKE_CXX_STANDARD 17)

# we need to define these to make sure local zlib compiling work
# you can comment the following links to use standard zlib

add_compile_definitions(LOCAL_ZLIB=1 NO_GZIP=1)

# build zlib

aux_source_directory(zlib ZLIB_SRC)
add_library(zlib STATIC ${ZLIB_SRC})
target_include_directories(zlib PUBLIC zlib)

# build sleigh

aux_source_directory(sleigh SLEIGH_SRC)
add_library(sleigh STATIC ${SLEIGH_SRC})
target_include_directories(sleigh PUBLIC zlib PUBLIC sleigh)
target_link_libraries(sleigh PRIVATE zlib)

# build example tool

aux_source_directory(example EXAMPLE_SRC)
add_executable(example ${EXAMPLE_SRC})
target_include_directories(example PUBLIC sleigh)
target_link_libraries(example PRIVATE sleigh PRIVATE zlib)

# build compiler tool

aux_source_directory(compiler COMPILER_SRC)
add_executable(compiler ${COMPILER_SRC})
target_include_directories(compiler PUBLIC sleigh)
target_link_libraries(compiler PRIVATE sleigh PRIVATE zlib)
