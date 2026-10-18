cmake_minimum_required(VERSION 3.7)

project(tracewise_dr)

# Make sure DYNAMORIO_HOME is set in the environment or passed to CMake
find_package(DynamoRIO)
if (NOT DynamoRIO_FOUND)
    message(FATAL_ERROR "DynamoRIO package required to build")
endif()

# We use the standard DynamoRIO extensions: drwrap, drmgr, drx
add_library(tracewise_dr SHARED tracewise_dr.c)
configure_DynamoRIO_client(tracewise_dr tracewise_dr.c)
use_DynamoRIO_extension(tracewise_dr drmgr)
use_DynamoRIO_extension(tracewise_dr drwrap)
use_DynamoRIO_extension(tracewise_dr drx)
use_DynamoRIO_extension(tracewise_dr drreg)
