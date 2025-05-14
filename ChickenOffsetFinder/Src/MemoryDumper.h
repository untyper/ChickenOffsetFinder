#ifndef COF_MEMORY_DUMPER_H
#define COF_MEMORY_DUMPER_H

// TODO: Implement Memory_Dumper::dump<Mode::Sparse>(...)

#define NOMINMAX
#include "pmm.h"

#include <cstdint>
#include <cstddef>
#include <fstream>
#include <optional>
#include <string>

namespace COF
{
#ifndef COF_MODE
#define COF_MODE
  enum class Mode
  {
    Regions, // Dumps all memory regions tracked in VAD tree
    Sparse   // Dumps all pages (even ones allocated between regions) upto last memory region's end
  };
#endif

  class MemoryDumper
  {
    pmm::Process ProcessInstance;
    mutable std::ofstream OutFile;
    std::uint64_t CurrentOffset = 0;

    std::uint32_t Pid = 0;
    std::uint64_t BaseAddress = 0;

    template <typename T>
    void Write(const T& Data, std::optional<std::uint64_t> Offset = std::nullopt, std::size_t Size = 0);

  public:
    // Metadata for parsing
    struct Metadata
    {
      std::size_t RegionsSectionSize = 0;
      std::size_t DumpSectionSize = 0;
      std::uint64_t BaseAddress = 0;
    };

    struct DataChunk
    {
      std::uint8_t Data[pmm::Page::Size::Small];
    };

    template <Mode M = Mode::Regions>
    std::size_t Dump(const std::string& FilePath);
    bool Attach(std::uint32_t Pid);

    MemoryDumper(std::uint32_t Pid);

    MemoryDumper& operator=(const MemoryDumper& Other);
    MemoryDumper(const MemoryDumper& Other);
    MemoryDumper() = default;
  };
}

#endif // !COF_MEMORY_DUMPER_H
