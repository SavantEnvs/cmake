/*
 * Fuzzer for CMake's Java source dependency scanner: cmDependsJavaParserHelper::ParseString, the flex
 * lexer and bison parser (cmDependsJavaLexer / cmDependsJavaParser) that the Makefile generator's
 * cmDependsJava runs over every .java source of a project to find the classes it uses and the class
 * files it produces. Java sources come from the project being built, i.e. from whoever wrote it.
 *
 * Not in upstream's Tests/Fuzzing; built from the same compile and link commands as the upstream
 * harnesses (mayhem/build.sh).
 */

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>

#include "cmDependsJavaParserHelper.h"
#include "cmSystemTools.h"

static constexpr size_t kMaxInputSize = 256 * 1024;

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
  (void)argc;
  (void)argv;

  // The parser reports a failed parse on cout and cerr, once per input.
  std::cout.setstate(std::ios::failbit);
  std::cerr.setstate(std::ios::failbit);
  cmSystemTools::SetMessageCallback(
    [](std::string const&, cmMessageMetadata const&) {});
  cmSystemTools::SetStdoutCallback([](std::string const&) {});
  cmSystemTools::SetStderrCallback([](std::string const&) {});
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
  if (size == 0 || size > kMaxInputSize) {
    return -1;
  }

  // ParseString takes a C string, as cmDependsJava hands it (ParseFile builds one from the file).
  std::string const source(reinterpret_cast<char const*>(data), size);

  cmDependsJavaParserHelper helper;
  if (helper.ParseString(source.c_str(), 0)) {
    // What cmDependsJava reads back from a successful parse.
    (void)helper.GetClassesFound();
    (void)helper.GetFilesProduced();
  }
  return 0;
}
