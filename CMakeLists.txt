cmake_minimum_required(VERSION 3.16)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
  endif()
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(stai LANGUAGES C CXX ASM)

include("${VITASDK}/share/vita.cmake" REQUIRED)

option(LOG_LEVEL "Log Level, 0=none, 1=info, 2=debug" "0")

set(COMPILER_FLAGS "-g -Wall -Os -ffunction-sections -fdata-sections -fvisibility=hidden -fno-builtin-printf")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${COMPILER_FLAGS} -std=gnu11")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${COMPILER_FLAGS} -std=gnu++17 -fno-rtti -fno-exceptions")

add_compile_definitions(LOG_LEVEL=${LOG_LEVEL})
if(LOG_LEVEL GREATER 1)
  add_compile_definitions(TRANSFORM_DIS_VERBOSE=1)
endif()

execute_process(
  COMMAND git rev-parse HEAD
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE GIT_COMMIT_HASH
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_QUIET
)
if(NOT GIT_COMMIT_HASH)
  set(GIT_COMMIT_HASH "unknown")
endif()

set(VERSION_HEADER "${CMAKE_CURRENT_BINARY_DIR}/version.h")
file(WRITE ${VERSION_HEADER}
  "#pragma once\n"
  "#define GIT_COMMIT \"${GIT_COMMIT_HASH}\"\n"
)

add_library(substitute STATIC
  substitute/lib/hook-functions.c
  substitute/lib/jump-dis.c
  substitute/lib/strerror.c
  substitute/lib/transform-dis.c
  substitute/lib/cbit/vec.c
)

target_include_directories(substitute PRIVATE
  substitute/lib/
)

target_compile_definitions(substitute PUBLIC
  -DNO_DYNAMIC_LINKER_STUFF
  -DNO_PTHREADS
)

target_compile_options(substitute PRIVATE
  -Wno-unused-variable
  -Wno-unused-but-set-variable
  -Wno-format
  -Wno-strict-aliasing
  -Wno-attributes
)

set_property(TARGET substitute PROPERTY INTERPROCEDURAL_OPTIMIZATION ON)

add_executable(stai
  src/stai.cpp
  src/hooks.cpp
  src/std.c
  src/stubs.s
)

target_include_directories(stai PRIVATE
  ${CMAKE_CURRENT_BINARY_DIR}
)

target_link_libraries(stai PRIVATE
  SceDebugForDriver_stub
  SceCpuForDriver_stub
  SceSysmemForDriver_stub
  SceThreadmgrForDriver_stub
  SceProcEventForDriver_stub
  SceSysclibForDriver_stub
  SceModulemgrForDriver_stub
  SceProcessmgrForDriver_stub
  taihenForKernel_stub
  gcc

  substitute
)

target_link_options(stai PRIVATE
  -nostdlib
  --entry=module_start
)

set_property(TARGET stai PROPERTY INTERPROCEDURAL_OPTIMIZATION ON)

vita_create_self(stai.skprx stai
  CONFIG exports.yml
  UNSAFE
  STRIPPED
  REL_OPTIMIZE
)

vita_create_stubs(stai-stubs stai ${CMAKE_SOURCE_DIR}/exports.yml
  KERNEL
)

add_custom_command(OUTPUT stai-vdpm-package.tar.xz
  COMMAND mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/package/lib
  COMMAND mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/package/include
  COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/libstai_stub.a ${CMAKE_CURRENT_BINARY_DIR}/package/lib/
  COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/libstai_stub_weak.a ${CMAKE_CURRENT_BINARY_DIR}/package/lib/
  COMMAND cp -r ${CMAKE_SOURCE_DIR}/include/stai ${CMAKE_CURRENT_BINARY_DIR}/package/include/
  COMMAND tar -C ${CMAKE_CURRENT_BINARY_DIR}/package -cJf stai-vdpm-package.tar.xz lib include
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  DEPENDS stai-stubs ${CMAKE_SOURCE_DIR}/include/stai/stai.h
)

add_custom_target(package ALL
  DEPENDS stai-vdpm-package.tar.xz
)

add_custom_command(
  TARGET stai POST_BUILD
  COMMAND arm-vita-eabi-objdump -d -C $<TARGET_FILE:stai> > ${CMAKE_CURRENT_BINARY_DIR}/stai.s
  VERBATIM
)

add_subdirectory(test_plugin)

add_custom_target(push
  DEPENDS test_plugin.suprx-self stai.skprx-self
  COMMAND curl -T ${CMAKE_CURRENT_BINARY_DIR}/stai.skprx ftp://$ENV{VITAIP}:1337/ur0:tai/stai.skprx
  COMMAND curl -T ${CMAKE_CURRENT_BINARY_DIR}/test_plugin/test_plugin.suprx ftp://$ENV{VITAIP}:1337/ur0:tai/test_plugin.suprx
  COMMAND sleep 1
  COMMAND echo reboot | ncat $ENV{VITAIP} 1338
)

add_custom_target(push2
  DEPENDS stai.skprx-self
  COMMAND curl -T ${CMAKE_CURRENT_BINARY_DIR}/stai.skprx ftp://$ENV{VITAIP}:1337/ux0:app/KLOADER00/plugin.skprx
)
