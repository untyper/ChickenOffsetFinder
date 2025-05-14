#include "MemoryDumper.h"

#include <cstdint>
#include <algorithm>
#include <iostream>

// TODO: Use COF_LOG for logging

namespace COF
{
  using Page = pmm::Page;
  using Region = pmm::Region;
  using Metadata = MemoryDumper::Metadata;

  template <typename T>
  void MemoryDumper::Write(const T& Data, std::optional<std::uint64_t> Offset, std::size_t Size)
  {
    // Seek offset if provided,
    // otherwise keep stream pointer where it is.
    if (Offset)
    {
      //this->OutFile.clear();
      this->OutFile.seekp(*Offset, std::ios::beg);
    }

    if (!Size)
    {
      Size = sizeof(T);
    }

    this->OutFile.write(reinterpret_cast<const char*>(&Data), Size);
  }

  template <Mode M>
  std::size_t MemoryDumper::Dump(const std::string& FilePath)
  {
    this->OutFile.open(FilePath, std::ios::binary);

    if (!this->OutFile)
    {
      //std::cerr << "[!] Failed to create output file.\n";
      return 0;
    }

    std::size_t CurrentOffset = 0;

    // Pre-write metadata to move file pointer to the next offset
    Metadata metadata;
    this->Write<Metadata>(metadata);

    // Only dump valid (hypervisor) readable pages
    const auto regions = this->ProcessInstance.GetRegions([&](const Region& region)
    {
      bool Readable = false;

      this->ProcessInstance.ForEachPage(region, [&](const Page& page)
      {
        if (page.Committed && page.MemoryType == pmm::Page::MemoryType::WriteBack)
        {
          Readable = true;

          // Readable page found.
          // Stop enumerating, we'll dump this region.
          return false;
        }

        // Continue enumerating until a readable page is found
        // or until we reach the end of the region.
        return true;
      });

      // If readable is false, the current region
      // will be filtered out from the final list.
      return Readable;
    });

    if (regions->empty())
    {
      //std::cerr << "[!] No memory regions found.\n";
      this->OutFile.close();
      return 0;
    }

    std::size_t RegionCount = 0;

    // Enumerate regions for metadata
    for (const auto& region : *regions)
    {
      this->Write<Region>(region);

      std::size_t region_size = (region.AddressEnd + 1) - region.AddressBegin;
      metadata.DumpSectionSize += region_size;
      ++RegionCount;
    }

    // Enumerate regions to actually dump
    for (const auto& region : *regions)
    {
      DataChunk dataChunk;
      const std::size_t chunk_size = sizeof(dataChunk);
      std::size_t region_size = (region.AddressEnd + 1) - region.AddressBegin;

      std::size_t read = 0;

      std::cout << "[>] Dumping region: [0x" << std::hex << region.AddressBegin
        << ", 0x" << region.AddressEnd << "], size: 0x" << region_size << std::endl;

      while (read < region_size)
      {
        std::size_t bytes_to_write = std::min(chunk_size, region_size - read);
        dataChunk = this->ProcessInstance.Read<DataChunk>(region.AddressBegin + read);
        this->Write<DataChunk>(dataChunk, std::nullopt, bytes_to_write);
        read += bytes_to_write;
      }
    }

    // Finally fill the remaining metadata
    metadata.RegionsSectionSize = RegionCount * sizeof(Region);
    metadata.BaseAddress = this->BaseAddress;

    // Write it to the file and exit
    this->Write<Metadata>(metadata, 0, 0);
    this->OutFile.close();

    // Success, return number of dumped regions
    return RegionCount;
  }

  bool MemoryDumper::Attach(std::uint32_t Pid)
  {
    if (!Pid)
    {
      return false;
    }

    if (!this->ProcessInstance.Attach(Pid))
    {
      return false;
    }

    if (!(this->BaseAddress = this->ProcessInstance.GetBaseAddress()))
    {
      return false;
    }

    this->Pid = Pid;
    return true;
  }

  MemoryDumper::MemoryDumper(std::uint32_t Pid)
  {
    this->Attach(Pid);
  }

  MemoryDumper& MemoryDumper::operator=(const MemoryDumper& Other) {
    if (this == &Other)
      return *this; // handle self-assignment

    this->ProcessInstance = Other.ProcessInstance;
    this->CurrentOffset = Other.CurrentOffset;
    this->Pid = Other.Pid;
    this->BaseAddress = Other.BaseAddress;

    // Note: We don't copy OutFile because std::ofstream is not copyable.

    return *this;
  }

  MemoryDumper::MemoryDumper(const MemoryDumper& Other) :
    ProcessInstance(Other.ProcessInstance),
    CurrentOffset(Other.CurrentOffset),
    Pid(Other.Pid),
    BaseAddress(Other.BaseAddress)
  {
    // Note: We don't copy OutFile because std::ofstream is not copyable.
  }

  // Explicit instantiation for definition of template function in implementation file
  // _read -> memory_dumper.h
  // read  -> memory_dumper.h

  template void MemoryDumper::Write<Metadata>(const Metadata& Data, std::optional<std::uint64_t> Offset, std::size_t Size);

  template std::size_t MemoryDumper::Dump<Mode::Regions>(const std::string& FilePath);
  template std::size_t MemoryDumper::Dump<Mode::Sparse>(const std::string& FilePath);
}
