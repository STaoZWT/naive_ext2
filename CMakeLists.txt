# CMake 最低版本号要求
cmake_minimum_required(VERSION 3.0.0)
# 项目信息
project(fsystem VERSION 0.1.0)

# 添加头文件目录
include_directories(.)
# 查找当前目录下的所有源文件，并将名称保存到SRCS变量
aux_source_directory(. SRCS)
# 指定生成目标
add_executable(main ${SRCS})

SET(CMAKE_BUILD_TYPE "Debug")
