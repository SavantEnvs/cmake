/*
 * Mayhem variant of upstream's Tests/Fuzzing/cmScriptFuzzer.cxx: run the input as a CMake script in
 * script mode (cmake -P) through the same entry point, cmake::Run().
 *
 * Upstream's harness hands the fuzzer the whole command set, so an input can run any program
 * (execute_process, exec_program, site_name), write or delete any file the process can reach
 * (file(WRITE|REMOVE_RECURSE|DOWNLOAD|...), configure_file, write_file, make_directory) and change
 * the process environment (set(ENV{...})). Those effects outlive the input, so the result of one
 * input would depend on the ones before it. This variant keeps the interpreter and removes that:
 *
 *   - commands are ALLOW-LISTED on the cmState after the interpreter is constructed (so the check is
 *     made on the command the interpreter resolved, after its own unescaping, and also covers
 *     cmake_language(CALL|EVAL)); everything not listed below is unregistered and fails as an
 *     unknown command;
 *   - file() is kept only for its path-conversion sub-commands, which touch nothing on disk;
 *   - the process environment is restored after every input;
 *   - cmSystemTools' process-global error flags are reset before every input (upstream leaves them
 *     set, and a set fatal-error flag makes the interpreter stop processing commands).
 *
 * The script is delivered through a memfd, as upstream does, so nothing is written to disk at all.
 */

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <sys/mman.h>
#include <unistd.h>

#include "cmExecutionStatus.h"
#include "cmFileCommand.h"
#include "cmState.h"
#include "cmSystemTools.h"
#include "cmake.h"

#ifndef MFD_CLOEXEC
#  define MFD_CLOEXEC 0x0001U
#endif

extern char** environ;

namespace {

// Same input bound as upstream's harness.
constexpr size_t kMaxInputSize = 256 * 1024;

std::string g_homeDir;
std::string g_scriptFile;
int g_scriptFd = -1;
std::vector<std::string> g_savedEnv;

// Commands whose effect is confined to the interpreter's own state (variables, properties, policies,
// control flow) or to its (suppressed) output.
char const* const kAllowedCommands[] = {
  // control flow, and the "unexpected end-command" diagnostics that go with it
  "block",
  "break",
  "continue",
  "else",
  "elseif",
  "endblock",
  "endforeach",
  "endfunction",
  "endif",
  "endmacro",
  "endwhile",
  "foreach",
  "function",
  "if",
  "macro",
  "return",
  "while",
  // interpreter state
  "cmake_diagnostic",
  "cmake_language",
  "cmake_minimum_required",
  "cmake_parse_arguments",
  "cmake_policy",
  "define_property",
  "get_cmake_property",
  "get_directory_property",
  "get_property",
  "include_guard",
  "mark_as_advanced",
  "option",
  "set",
  "set_directory_properties",
  "set_property",
  "unset",
  "variable_watch",
  // pure data operations
  "cmake_path",
  "list",
  "math",
  "message",
  "remove",
  "separate_arguments",
  "string",
};

// file() sub-commands that only transform their arguments.
char const* const kAllowedFileModes[] = {
  "RELATIVE_PATH",
  "TO_CMAKE_PATH",
  "TO_NATIVE_PATH",
};

bool IsAllowedCommand(std::string const& name)
{
  return std::any_of(
    std::begin(kAllowedCommands), std::end(kAllowedCommands),
    [&name](char const* allowed) { return name == allowed; });
}

bool PathOnlyFileCommand(std::vector<std::string> const& args,
                         cmExecutionStatus& status)
{
  if (!args.empty()) {
    for (char const* mode : kAllowedFileModes) {
      if (args[0] == mode) {
        return cmFileCommand(args, status);
      }
    }
  }
  status.SetError("sub-command is not available in this fuzz harness");
  return false;
}

void RestoreEnvironment()
{
  clearenv();
  for (std::string const& entry : g_savedEnv) {
    std::string::size_type const eq = entry.find('=');
    if (eq != std::string::npos && eq != 0) {
      setenv(entry.substr(0, eq).c_str(), entry.c_str() + eq + 1, 1);
    }
  }
}

} // namespace

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
  (void)argc;
  (void)argv;

  // Suppress output during fuzzing (set once at init), as upstream's harness does.
  cmSystemTools::SetMessageCallback(
    [](std::string const&, cmMessageMetadata const&) {});
  cmSystemTools::SetStdoutCallback([](std::string const&) {});
  cmSystemTools::SetStderrCallback([](std::string const&) {});

  for (char** e = environ; e && *e; ++e) {
    g_savedEnv.emplace_back(*e);
  }

  // The interpreter wants a home directory; nothing is ever written into it.
  char const* tmp = getenv("TMPDIR");
  std::string tmpl =
    std::string(tmp && *tmp ? tmp : "/tmp") + "/cmake_fuzz_script_XXXXXX";
  if (!mkdtemp(&tmpl[0])) {
    abort();
  }
  g_homeDir = tmpl;

  g_scriptFd = memfd_create("cmake_fuzz", MFD_CLOEXEC);
  if (g_scriptFd < 0) {
    abort();
  }
  g_scriptFile = "/proc/self/fd/" + std::to_string(g_scriptFd);
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
  if (size == 0 || size > kMaxInputSize) {
    return -1;
  }

  if (ftruncate(g_scriptFd, 0) != 0 || lseek(g_scriptFd, 0, SEEK_SET) != 0 ||
      write(g_scriptFd, data, size) != static_cast<ssize_t>(size)) {
    abort();
  }

  cmSystemTools::ResetErrorOccurredFlag();

  {
    cmake cm(cmState::Role::Script);
    cm.SetHomeDirectory(g_homeDir);
    cm.SetHomeOutputDirectory(g_homeDir);

    cmState* state = cm.GetState();
    for (std::string const& name : state->GetCommandNames()) {
      if (!IsAllowedCommand(name)) {
        state->RemoveBuiltinCommand(name);
      }
    }
    state->AddBuiltinCommand("file", PathOnlyFileCommand);

    std::vector<std::string> args;
    args.emplace_back("cmake");
    args.emplace_back("-P");
    args.emplace_back(g_scriptFile);
    (void)cm.Run(args, false);
  }

  RestoreEnvironment();
  return 0;
}
