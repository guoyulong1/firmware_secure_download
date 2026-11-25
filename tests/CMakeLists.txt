# GTest 单元测试。ctest 负责编排：gtest_discover_tests 会把每个 TEST 用例
# 注册成独立的 ctest 条目，例如 ctest -R fsd_test_url 只跑 URL 一组。
# googletest 源码由 3rdparty/fetch.sh 按固定标签下载，不入库。

if(NOT EXISTS "${CMAKE_SOURCE_DIR}/3rdparty/googletest/.fsd-source-tag")
  message(FATAL_ERROR
    "missing 3rdparty/googletest; run 3rdparty/fetch.sh first")
endif()

# 只编测试需要的部分：不装 gtest、不编它自带的示例与自测。
set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(gtest_build_tests OFF CACHE BOOL "" FORCE)
set(gtest_build_samples OFF CACHE BOOL "" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)

# gtest_discover_tests 来自 CMake 自带的 GoogleTest 模块。
include(GoogleTest)

add_subdirectory("${CMAKE_SOURCE_DIR}/3rdparty/googletest"
                 "${CMAKE_BINARY_DIR}/googletest-build"
                 EXCLUDE_FROM_ALL)

# 每个模块一个测试可执行文件，统一链接 fsd_core 与 gtest_main。
function(fsd_add_module_test name)
  add_executable(fsd_test_${name} ${ARGN})
  target_link_libraries(fsd_test_${name} PRIVATE fsd_core GTest::gtest_main)
  target_include_directories(fsd_test_${name}
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
  target_compile_options(fsd_test_${name} PRIVATE -Wall -Wextra)
  gtest_discover_tests(fsd_test_${name} DISCOVERY_TIMEOUT 120)
endfunction()

fsd_add_module_test(text_util test_text_util.cc)
fsd_add_module_test(status test_status.cc)
fsd_add_module_test(url test_url.cc)
fsd_add_module_test(sha256 test_sha256.cc)
fsd_add_module_test(md5 test_md5.cc)
fsd_add_module_test(manifest test_manifest.cc)
fsd_add_module_test(http_client test_http_client.cc)
fsd_add_module_test(secure_downloader test_secure_downloader.cc)
