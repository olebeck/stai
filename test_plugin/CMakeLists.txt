cmake_minimum_required(VERSION 3.16)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
  endif()
endif()

project(test_plugin)
include("${VITASDK}/share/vita.cmake" REQUIRED)

set(COMPILER_FLAGS "-g -Wall -Os -ffunction-sections -fdata-sections")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11 ${COMPILER_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11 ${COMPILER_FLAGS} -fno-rtti -fno-exceptions")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -nostdlib --entry=module_start")

add_executable(test_plugin
  main.c
)

target_link_directories(test_plugin PRIVATE
  ${CMAKE_BINARY_DIR}
)

target_link_libraries(test_plugin PRIVATE
  gcc

  SceKernelThreadMgr_stub
  SceKernelModulemgr_stub
  SceLibKernel_stub
  SceSysmodule_stub

  stai_stub
)

unset(VITA_ELF_CREATE_FLAGS)
vita_create_self(test_plugin.suprx test_plugin
  UNSAFE
  STRIPPED
)
