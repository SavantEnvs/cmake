/*
 * Fuzzer for CMake's C/C++ #include scanner, cmDependsC::Scan: the line reader, the include-directive
 * regular expression and the CMAKE_INCLUDE_TRANSFORMS rewriting that the Makefile generator runs over
 * every C/C++ source and every header it reaches to write its depend files. Those files come from the
 * project being built, i.e. from whoever wrote it.
 *
 * Scan() is protected, so the harness drives it through a trivial subclass. A real cmDependsC is built
 * from a local generator and reads and writes an on-disk include cache; none of that is the scanner,
 * so the subclass is the default-constructed "checking instance" with the same regular expressions
 * and one transform rule installed by hand, and it never touches the disk.
 *
 * Not in upstream's Tests/Fuzzing; built from the same compile and link commands as the upstream
 * harnesses (mayhem/build.sh).
 */

#include <cstddef>
#include <cstdint>
#include <sstream>
#include <string>

#include "cmDependsC.h"

namespace {

constexpr size_t kMaxInputSize = 256 * 1024;

class Scanner : public cmDependsC
{
public:
  Scanner()
  {
    // Source/cmDependsC.cxx: INCLUDE_REGEX_LINE, and CMAKE_<LANG>_INCLUDE_REGEX_SCAN's default.
    this->IncludeRegexLine.compile(
      "^[ \t]*[#%][ \t]*(include|import)[ \t]*[<\"]([^\">]+)([\">])");
    this->IncludeRegexScan.compile("^.*$");

    // cmDependsC::SetupTransforms for the rule CMAKE_INCLUDE_TRANSFORMS = "HEADER(%)=<%.h>".
    this->ParseTransform("HEADER(%)=<%.h>");
    this->IncludeRegexTransform.compile(
      "^([ \t]*[#%][ \t]*(include|import)[ \t]*)(HEADER)[ \t]*\\(([^),]*)\\)");
  }

  void ScanText(std::string const& text)
  {
    std::istringstream is(text);
    this->Scan(is, "/src", "/src/input.c");
  }
};

} // namespace

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
  if (size == 0 || size > kMaxInputSize) {
    return -1;
  }

  Scanner scanner;
  scanner.ScanText(std::string(reinterpret_cast<char const*>(data), size));
  return 0;
}
