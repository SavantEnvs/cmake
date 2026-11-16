/*
 * Mayhem variant of upstream's Tests/Fuzzing/cmArchiveExtractFuzzer.cxx: cmSystemTools::ExtractTar over
 * the bundled libarchive, with the same two extractions (timestamps on / quiet, off / verbose).
 *
 * Why a variant: ExtractTar sets only ARCHIVE_EXTRACT_SECURE_NODOTDOT | ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS
 * (Source/cmSystemTools.cxx), not ARCHIVE_EXTRACT_SECURE_SYMLINKS. archive_write_disk(3) documents that
 * without that flag extraction follows symbolic links already on disk, and a hard link entry is created
 * to wherever its target names. So a fuzzed tar holding a symlink `l -> /some/dir` followed by a file
 * `l/x` writes outside the scratch directory, and what it wrote stays for every later input and the
 * container. Upstream's harness removes only its own scratch files.
 *
 * What this variant does differently:
 *   - the input is first read with libarchive's header reader (same filters, formats and header charset
 *     as ExtractTar; no data is read), and an archive that has any symlink or hard link entry is NOT
 *     extracted. It is read through cmSystemTools::ListTar instead, which never writes: the link
 *     entries are still parsed and printed, only creating them on disk is not exercised;
 *   - archives without link entries are extracted exactly as upstream does, into a scratch directory
 *     that is emptied after every input. With no link entries in the archive and a scratch directory
 *     that starts empty, nothing on disk can redirect a path out of it, and "../" and absolute entry
 *     paths are refused by the flags ExtractTar sets;
 *   - the scratch directory is under $TMPDIR (default /tmp).
 */

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include <cm3p/archive.h>
#include <cm3p/archive_entry.h>

#include "cmSystemTools.h"

static constexpr size_t kMinInputSize = 4;          // Minimum magic bytes
static constexpr size_t kMaxInputSize = 256 * 1024; // Same bound as upstream

static std::string g_extractDir;

namespace {

// True if the archive has a symlink or hard link entry. Stops where ExtractTar's own loop stops: at the
// first header that is not ARCHIVE_OK.
bool HasLinkEntries(uint8_t const* data, size_t size)
{
  struct archive* a = archive_read_new();
  archive_read_support_filter_all(a);
  archive_read_support_format_all(a);
  archive_read_set_options(a, "hdrcharset=UTF-8");
  bool links = false;
  if (archive_read_open_memory(a, data, size) == ARCHIVE_OK) {
    struct archive_entry* entry;
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
      if (archive_entry_filetype(entry) == AE_IFLNK ||
          archive_entry_symlink(entry) || archive_entry_hardlink(entry)) {
        links = true;
        break;
      }
    }
  }
  archive_read_free(a);
  return links;
}

} // namespace

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
  (void)argc;
  (void)argv;

  char const* tmp = getenv("TMPDIR");
  std::string tmpl =
    std::string(tmp && *tmp ? tmp : "/tmp") + "/cmake_fuzz_extract_XXXXXX";
  if (!mkdtemp(&tmpl[0])) {
    abort();
  }
  g_extractDir = tmpl;
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
  if (size < kMinInputSize || size > kMaxInputSize) {
    return -1;
  }

  std::string archiveFile = g_extractDir + "/test_archive";
  {
    FILE* fp = fopen(archiveFile.c_str(), "wb");
    if (!fp) {
      return 0;
    }
    fwrite(data, 1, size, fp);
    fclose(fp);
  }

  std::vector<std::string> files;
  std::vector<std::string> excludeFiles;

  if (HasLinkEntries(data, size)) {
    (void)cmSystemTools::ListTar(archiveFile, files, excludeFiles, "UTF-8",
                                 true);
    cmSystemTools::RemoveFile(archiveFile);
    return 0;
  }

  std::string extractSubDir = g_extractDir + "/out";
  cmSystemTools::RemoveADirectory(extractSubDir);
  cmSystemTools::MakeDirectory(extractSubDir);

  std::string cwd = cmSystemTools::GetCurrentWorkingDirectory();

  if (cmSystemTools::ChangeDirectory(extractSubDir)) {
    (void)cmSystemTools::ExtractTar(
      archiveFile, files, excludeFiles,
      cmSystemTools::cmTarExtractTimestamps::Yes, "UTF-8", false);

    // Restore directory BEFORE removing (can't remove cwd)
    cmSystemTools::ChangeDirectory(cwd);
    cmSystemTools::RemoveADirectory(extractSubDir);
    cmSystemTools::MakeDirectory(extractSubDir);

    if (cmSystemTools::ChangeDirectory(extractSubDir)) {
      files.clear();
      (void)cmSystemTools::ExtractTar(
        archiveFile, files, excludeFiles,
        cmSystemTools::cmTarExtractTimestamps::No, "UTF-8", true);
      cmSystemTools::ChangeDirectory(cwd);
    }
  }

  cmSystemTools::RemoveADirectory(extractSubDir);
  cmSystemTools::RemoveFile(archiveFile);
  return 0;
}
