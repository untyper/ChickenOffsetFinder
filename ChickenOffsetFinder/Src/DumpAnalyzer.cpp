#include "DumpAnalyzer.h"
#include "Util.h"

#include <Windows.h>
#include <winver.h>

#include <iostream>
#include <filesystem>
#include <algorithm>
#include <sstream>
#include <string>
#include <limits>
#include <climits>
#include <unordered_map>
#include <vector>
#include <optional>
#include <cstdint>
#include <cstdio>

// TODO: Get version details from dump (from PE header maybe?)
// TODO: Alias function return types for pretty reasons
// 
// TODO:
//  Make FindInstructionSequence and FindInstructionSubsequence
//  accept a list of instruction strings and parse the strings
//  directly in the function(s) instead of separately parsing
//  them with COF::AssemblyParser prior to use.

namespace COF
{
  using PeHeader = DumpAnalyzer::PeHeader;
  using PeSection = DumpAnalyzer::PeSection;
  using PeSections = DumpAnalyzer::PeSections;
  using StringType = DumpAnalyzer::StringType;
  using PatternElem = DumpAnalyzer::PatternElem;

  PeSection::PeSection(const std::string& Name, std::uint64_t Offset, std::uint64_t Size)
    : Name(Name), Offset(Offset), Size(Size)
  {
  }

  const std::string& PeSection::GetName() const
  {
    return this->Name;
  }

  std::uint64_t PeSection::GetOffset() const
  {
    return this->Offset;
  }

  std::size_t PeSection::GetSize() const
  {
    return this->Size;
  }

  PeSections::PeSections(const std::vector<PeSection>& Sections)
    : Sections_(Sections)
  {
  }

  const std::vector<PeSection>& PeSections::GetAll() const
  {
    return this->Sections_;
  }

  std::optional<PeSection> PeSections::GetSection(const std::string& Name) const
  {
    for (const PeSection& Section : this->Sections_)
    {
      if (Section.GetName() == Name)
      {
        return Section;
      }
    }
    return std::nullopt;
  }

  DumpAnalyzer::Metadata& DumpAnalyzer::Metadata::operator=(const MemoryDumper::Metadata& Base)
  {
    this->RegionsSectionSize = Base.RegionsSectionSize;
    this->DumpSectionSize = Base.DumpSectionSize;
    this->BaseAddress = Base.BaseAddress;
    return *this;
  }

  DumpAnalyzer::Metadata::Metadata(const MemoryDumper::Metadata& Base)
  {
    this->RegionsSectionSize = Base.RegionsSectionSize;
    this->DumpSectionSize = Base.DumpSectionSize;
    this->BaseAddress = Base.BaseAddress;
  }

  std::optional<std::uint64_t> DumpAnalyzer::TranslateVirtualOffsetToFileOffset(std::uint64_t VirtualOffset) const
  {
    std::uint64_t VirtualAddress = this->InMetadata.BaseAddress + VirtualOffset;
    std::uint64_t DumpSectionOffset = this->InMetadata.DumpSectionOffset;
    std::uint64_t FileOffset = DumpSectionOffset;

    for (const auto& Region : this->InMemoryRegions)
    {
      std::size_t RegionSize = (Region.AddressEnd + 1) - Region.AddressBegin;

      if (VirtualAddress >= Region.AddressBegin && VirtualAddress <= Region.AddressEnd)
      {
        std::uint64_t RegionOffset = VirtualAddress - Region.AddressBegin;
        FileOffset += RegionOffset;
        return FileOffset;
      }

      FileOffset += RegionSize;
    }

    return std::nullopt;
  }

  std::vector<std::uint8_t> DumpAnalyzer::_Read(std::uint64_t Offset, std::size_t Size) const
  {
    std::vector<std::uint8_t> Buffer(Size);
    this->InFile.clear();
    this->InFile.seekg(Offset, std::ios::beg);
    this->InFile.read(reinterpret_cast<char*>(Buffer.data()), Size);
    return Buffer;
  }

  std::vector<std::uint8_t> DumpAnalyzer::Read(std::uint64_t Offset, std::size_t Size) const
  {
    if (this->AnalysisMode == Mode::Regions)
    {
      auto FileOffset = this->TranslateVirtualOffsetToFileOffset(Offset);

      if (FileOffset)
      {
        return this->_Read(*FileOffset, Size);
      }

      return {};
    }
    else if (this->AnalysisMode == Mode::Sparse)
    {
      return this->_Read(Offset, Size);
    }

    return {};
  }

  std::optional<std::string> DumpAnalyzer::GetFileVersionInternal() const
  {
    if (!this->InPeSections)
    {
      return std::nullopt;
    }

    auto SectionOpt = this->InPeSections->GetSection(".rsrc");

    if (!SectionOpt)
    {
      return std::nullopt;
    }

    auto Section = *SectionOpt;

    std::uint64_t SectionBase = Section.GetOffset();
    std::uint32_t SectionSize = static_cast<std::uint32_t>(Section.GetSize());
    auto SectionData = this->Read(SectionBase, SectionSize);

    if (SectionData.empty())
    {
      return std::nullopt;
    }

    const std::uint8_t* Base = SectionData.data();
    std::uint32_t DirOff = 0;

    auto WalkDirectory = [&](std::uint32_t& OutCount, std::uint32_t& OutEntriesOff)
    {
      auto Dir = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY*>(Base + DirOff);
      OutCount = Dir->NumberOfNamedEntries + Dir->NumberOfIdEntries;
      OutEntriesOff = DirOff + sizeof(IMAGE_RESOURCE_DIRECTORY);
    };

    // Level 1: find RT_VERSION (16)
    {
      std::uint32_t Count, EntriesOff;
      WalkDirectory(Count, EntriesOff);

      bool Found = false;
      constexpr std::uint16_t RtVersionId = 16;

      for (std::uint32_t i = 0; i < Count; ++i)
      {
        std::uint32_t EntryOff = EntriesOff + i * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
        auto E = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY_ENTRY*>(Base + EntryOff);

        if (E->DataIsDirectory && E->Id == RtVersionId)
        {
          DirOff = (E->OffsetToDirectory & 0x7FFFFFFF);
          Found = true;
          break;
        }
      }

      if (!Found)
      {
        return std::nullopt;
      }
    }

    // Level 2: find Name=1
    {
      std::uint32_t Count, EntriesOff;
      WalkDirectory(Count, EntriesOff);

      bool Found = false;
      constexpr std::uint16_t NameId = 1;

      for (std::uint32_t i = 0; i < Count; ++i)
      {
        std::uint32_t EntryOff = EntriesOff + i * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
        auto E = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY_ENTRY*>(Base + EntryOff);

        if (E->DataIsDirectory && E->Id == NameId)
        {
          DirOff = (E->OffsetToDirectory & 0x7FFFFFFF);
          Found = true;
          break;
        }
      }

      if (!Found)
      {
        return std::nullopt;
      }
    }

    // Level 3: should point directly at a DATA_ENTRY
    std::uint32_t DataEntryOff;
    {
      std::uint32_t Count, EntriesOff;
      WalkDirectory(Count, EntriesOff);

      if (Count == 0)
      {
        return std::nullopt;
      }

      auto E = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY_ENTRY*>(Base + EntriesOff);

      if (E->DataIsDirectory)
      {
        return std::nullopt;
      }

      DataEntryOff = (E->OffsetToData & 0x7FFFFFFF);
    }

    // Read IMAGE_RESOURCE_DATA_ENTRY
    if (DataEntryOff + sizeof(IMAGE_RESOURCE_DATA_ENTRY) > SectionSize)
    {
      return std::nullopt;
    }

    auto DataEnt = *reinterpret_cast<const IMAGE_RESOURCE_DATA_ENTRY*>(Base + DataEntryOff);
    std::uint32_t DataBase = DataEnt.OffsetToData;
    std::uint32_t DataSize = DataEnt.Size;

    if (DataBase < SectionBase)
    {
      return std::nullopt;
    }

    std::uint32_t DataOffset = DataBase - static_cast<std::uint32_t>(SectionBase);

    if (DataOffset + DataSize > SectionSize)
    {
      return std::nullopt;
    }

    // Parse VS_VERSIONINFO
    const std::uint8_t* Ver = Base + DataOffset;
    std::uint32_t Total = DataSize;
    std::uint32_t Pos = 0;

    if (Pos + 6 > Total)
    {
      return std::nullopt;
    }

    // Advance Pos cursor by 2.
    // VS_VERSIONINFO: wLength, ValueLength, wType
    std::uint16_t Length = *reinterpret_cast<const std::uint16_t*>(Ver + Pos); Pos += 2;
    std::uint16_t ValueLength = *reinterpret_cast<const std::uint16_t*>(Ver + Pos); Pos += 2;
    std::uint16_t Type = *reinterpret_cast<const std::uint16_t*>(Ver + Pos); Pos += 2;

    // Skip the Unicode key "VS_VERSION_INFO"
    while (Pos + 2 <= Total)
    {
      std::uint16_t Ch = *reinterpret_cast<const std::uint16_t*>(Ver + Pos);
      Pos += 2;

      if (Ch == 0)
      {
        break;
      }
    }

    // Align to DWORD
    Pos = (Pos + 3) & ~3;

    // Read VS_FIXEDFILEINFO
    if (ValueLength >= sizeof(VS_FIXEDFILEINFO) && Pos + sizeof(VS_FIXEDFILEINFO) <= Total)
    {
      auto Ffi = reinterpret_cast<const VS_FIXEDFILEINFO*>(Ver + Pos);

      if (Ffi->dwSignature != 0xFEEF04BD)
      {
        return std::nullopt;
      }

      auto HighWord = [](std::uint32_t X)
      {
        return static_cast<std::uint16_t>(X >> 16);
      };

      auto LowWord = [](std::uint32_t X)
      {
        return static_cast<std::uint16_t>(X & 0xFFFF);
      };

      std::uint16_t Major = HighWord(Ffi->dwFileVersionMS);
      std::uint16_t Minor = LowWord(Ffi->dwFileVersionMS);
      std::uint16_t Build = HighWord(Ffi->dwFileVersionLS);
      std::uint16_t Rev = LowWord(Ffi->dwFileVersionLS);

      char Buffer[32];
      std::snprintf(Buffer, sizeof(Buffer), "%u.%u.%u.%u", Major, Minor, Build, Rev);
      return std::string(Buffer);
    }

    return std::nullopt;
  }

  void DumpAnalyzer::ExtractAndSavePeHeaderAndSections()
  {
    std::vector<PeSection> Sections;

    auto SetNullopt = [this]()
    {
      this->InPeHeader = std::nullopt;
      this->InPeSections = std::nullopt;
    };

    this->InFile.clear();
    this->InFile.seekg(0, std::ios::end);
    const std::uint64_t FileSize = static_cast<std::uint64_t>(this->InFile.tellg());

    // Validate DOS header
    if (FileSize < sizeof(IMAGE_DOS_HEADER))
    {
      return SetNullopt();
    }

    IMAGE_DOS_HEADER DosHeader = this->Read<IMAGE_DOS_HEADER>(0);

    if (DosHeader.e_magic != IMAGE_DOS_SIGNATURE)
    {
      return SetNullopt();
    }

    // Validate PE header
    const std::uint64_t PeOffset = DosHeader.e_lfanew;

    if (PeOffset + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) > FileSize)
    {
      return SetNullopt();
    }

    const uint32_t Signature = this->Read<uint32_t>(PeOffset);

    if (Signature != IMAGE_NT_SIGNATURE)
    {
      return SetNullopt();
    }

    IMAGE_FILE_HEADER FileHeader = this->Read<IMAGE_FILE_HEADER>(PeOffset + sizeof(uint32_t));

    if (PeOffset + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) + FileHeader.SizeOfOptionalHeader > FileSize)
    {
      return SetNullopt();
    }

    // Skip reading OptionalHeader entirely
    const std::uint64_t SectionTableOffset = PeOffset + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) + FileHeader.SizeOfOptionalHeader;
    const std::uint64_t ExpectedSectionTableSize = static_cast<std::uint64_t>(FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);

    if (SectionTableOffset + ExpectedSectionTableSize > FileSize)
    {
      return SetNullopt();
    }

    // Define .header pseudo-section
    this->InPeHeader = { ".header", 0, SectionTableOffset + ExpectedSectionTableSize };

    // Parse section headers
    for (int i = 0; i < FileHeader.NumberOfSections; ++i)
    {
      const auto Offset = SectionTableOffset + i * sizeof(IMAGE_SECTION_HEADER);
      IMAGE_SECTION_HEADER Sec = this->Read<IMAGE_SECTION_HEADER>(Offset);

      std::string Name(reinterpret_cast<char*>(Sec.Name), 8);
      Name = Name.c_str(); // Remove trailing nulls

      if (Name.empty())
      {
        Name = ".section" + std::to_string(i + 1);
      }

      Sections.push_back({
        Name,
        static_cast<std::uint64_t>(Sec.VirtualAddress),
        static_cast<std::uint64_t>(Sec.Misc.VirtualSize)
        });
    }

    std::sort(Sections.begin(), Sections.end(), [](const PeSection& A, const PeSection& B)
    {
      return A.GetOffset() < B.GetOffset();
    });

    this->InPeSections = PeSections(Sections);
  }

  // Enumerate instructions in the .text section to find direct call targets.
  void DumpAnalyzer::ExtractAndSaveFunctions()
  {
    if (!this->InPeSections)
    {
      return;
    }

    auto TextSection = this->InPeSections->GetSection(".text");

    if (!TextSection)
    {
      return;
    }

    std::size_t TextSectionSize = TextSection->GetSize();
    std::uint64_t TextSectionOffset = TextSection->GetOffset();
    std::uint64_t TextSectionEnd = TextSectionOffset + TextSectionSize;

    auto Buffer = this->Read(TextSectionOffset, TextSectionSize);
    std::size_t BytesRead = this->InFile.gcount();
    std::size_t Offset = 0;
    ZydisDecoderContext Context;

    while (Offset < BytesRead)
    {
      ZydisDecodedInstruction Instruction;

      ZyanStatus Status = ZydisDecoderDecodeInstruction(
        &this->Decoder,
        &Context,
        Buffer.data() + Offset,
        BytesRead - Offset,
        &Instruction
      );

      if (!ZYAN_SUCCESS(Status))
      {
        Offset += 1;
        continue;
      }

      // Look for: call <imm>
      if (Instruction.mnemonic == ZYDIS_MNEMONIC_CALL && Instruction.operand_count >= 1)
      {
        ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];

        if (ZYAN_SUCCESS(ZydisDecoderDecodeOperands(
          &this->Decoder,
          &Context,
          &Instruction,
          Operands,
          Instruction.operand_count)))
        {
          const auto& Target = Operands[0];

          if (Target.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
          {
            // Do some casting to avoid negative wraparound due to integer promotion (in std::uint64_t)
            std::int64_t CallEnd = static_cast<std::int64_t>(TextSectionOffset + Offset + Instruction.length);
            std::int64_t Immediate = static_cast<std::int64_t>(Target.imm.value.s);
            std::uint64_t FunctionOffset = static_cast<std::uint64_t>(CallEnd + Immediate);

            // Ignore any calls to outside of the .Text section.
            // This will ignore any valid function offsets in custom sections.
            // TODO: Allow custom sections too, but for now this is just fine.
            if (FunctionOffset >= TextSectionEnd)
            {
              Offset += Instruction.length;
              continue;
            }

            this->InFunctionOffsets.insert(FunctionOffset);
          }
        }
      }

      Offset += Instruction.length;
    }
  }

  void DumpAnalyzer::ExtractAndSaveFileVersion()
  {
    this->InFileVersion = this->GetFileVersionInternal();
  }

  const std::vector<pmm::Region>& DumpAnalyzer::GetMemoryRegions() const
  {
    return this->InMemoryRegions;
  }

  const std::optional<std::string>& DumpAnalyzer::GetFileVersion() const
  {
    return this->InFileVersion;
  }

  const std::optional<PeHeader>& DumpAnalyzer::GetPeHeader() const
  {
    return this->InPeHeader;
  }

  const std::optional<PeSections>& DumpAnalyzer::GetPeSections() const
  {
    return this->InPeSections;
  }

  const std::set<std::uint64_t>& DumpAnalyzer::GetFunctions() const
  {
    return this->InFunctionOffsets;
  }

  template<StringType T>
  std::optional<DumpAnalyzer::Result<std::vector<std::uint64_t>>>
    DumpAnalyzer::FindString(const std::string& Str, std::size_t MaxMatches) const
  {
    if (!this->InPeSections)
    {
      return std::nullopt;
    }

    auto RdataSection = this->InPeSections->GetSection(".rdata");

    if (!RdataSection)
    {
      return std::nullopt;
    }

    Result<std::vector<std::uint64_t>> Out;
    std::vector<std::uint64_t> Matches;

    // Helper to not repeat code
    auto SetSizeAndValue = [&Out](std::size_t Size,
      const std::vector<std::uint64_t>& Value)
    {
      Out.Range.Size;
      Out.Value = Value;
    };

    std::uint64_t RdataSectionOffset = RdataSection->GetOffset();
    std::size_t RdataSectionSize = RdataSection->GetSize();
    auto Buffer = this->Read(RdataSectionOffset, RdataSectionSize);

    if (Buffer.empty())
    {
      return std::nullopt;
    }

    std::vector<std::uint8_t> Pattern;

    if constexpr (T == StringType::ASCII)
    {
      Pattern.assign(Str.begin(), Str.end());
    }
    else if constexpr (T == StringType::UTF16_LE)
    {
      for (char C : Str)
      {
        Pattern.push_back(static_cast<std::uint8_t>(C));
        Pattern.push_back(0x00);
      }
    }

    const std::size_t PatternSize = Pattern.size();
    bool FirstMatch = true;

    for (std::size_t I = 0; I + PatternSize <= Buffer.size(); I++)
    {
      bool Match = true;

      for (std::size_t J = 0; J < PatternSize; ++J)
      {
        if (Buffer[I + J] != Pattern[J])
        {
          Match = false;
          break;
        }
      }

      if (Match)
      {
        std::uint64_t MatchOffset = RdataSectionOffset + I;
        Matches.push_back(MatchOffset);

        if (FirstMatch)
        {
          Out.Range.Offset = MatchOffset;
          FirstMatch = false;
        }

        // Maximum amount of matches reached, return matches
        if (Matches.size() >= MaxMatches)
        {
          SetSizeAndValue((MatchOffset + PatternSize) - Out.Range.Offset, Matches);
          return Out;
        }
      }
    }

    // Some matches found, return them
    if (!Matches.empty())
    {
      auto LastOffset = Matches.back();
      SetSizeAndValue((LastOffset + PatternSize) - Out.Range.Offset, Matches);
      return Out;
    }

    // No matches found
    return std::nullopt;
  }

  std::vector<PatternElem>
    DumpAnalyzer::ParsePattern(const std::string& PatternStr) const
  {
    std::vector<PatternElem> Pattern;
    std::istringstream Stream(PatternStr);
    std::string Token;

    // Helper to build mask/value for one hex digit at bit‐shift Shift
    auto MakeNibble = [&](char Char, int Shift) -> std::pair<std::uint8_t, std::uint8_t>
    {
      if (Char == '?')
      {
        return { 0x0, 0x0 };
      }

      std::uint8_t NibbleValue = static_cast<std::uint8_t>(
        std::stoul(std::string(1, Char), nullptr, 16)
        );

      return {
        static_cast<std::uint8_t>(0xF << Shift),
        static_cast<std::uint8_t>(NibbleValue << Shift)
      };
    };

    while (Stream >> Token)
    {
      PatternElem Elem{ 0x00, 0x00 };

      // Full‐byte wildcard
      if (Token == "?" || Token == "??")
      {
        Elem = { 0x00, 0x00 };
      }
      // Two‐character token, possibly with '?' nibble
      else if (Token.size() == 2 &&
        (isxdigit(Token[0]) || Token[0] == '?') &&
        (isxdigit(Token[1]) || Token[1] == '?'))
      {
        auto [MaskHigh, ValueHigh] = MakeNibble(Token[0], 4);
        auto [MaskLow, ValueLow] = MakeNibble(Token[1], 0);
        Elem.first = MaskHigh | MaskLow;
        Elem.second = ValueHigh | ValueLow;
      }
      // Fixed byte
      else
      {
        std::uint8_t ByteValue = static_cast<std::uint8_t>(
          std::stoul(Token, nullptr, 16)
          );
        Elem = { 0xFF, ByteValue };
      }

      Pattern.push_back(Elem);
    }

    return Pattern;
  }

  std::optional<uint64_t> DumpAnalyzer::FindPattern(const std::vector<std::uint8_t>& Buffer,
    const std::vector<PatternElem>& Pattern) const
  {
    if (Buffer.size() < Pattern.size())
    {
      return std::nullopt;
    }

    for (std::size_t Index = 0; Index <= Buffer.size() - Pattern.size(); ++Index)
    {
      bool IsMatched = true;

      for (std::size_t PatternIndex = 0; PatternIndex < Pattern.size(); ++PatternIndex)
      {
        auto [Mask, Value] = Pattern[PatternIndex];
        std::uint8_t BufferByte = Buffer[Index + PatternIndex];

        if ((BufferByte & Mask) != Value)
        {
          IsMatched = false;
          break;
        }
      }

      if (IsMatched)
      {
        return Index;
      }
    }

    return std::nullopt;
  }

  std::optional<DumpAnalyzer::Result<>>
    DumpAnalyzer::FindPattern(std::uint64_t StartOffset, std::size_t Size, const std::string& IdaPattern) const
  {
    // Patterns could be larger than specified Size,
    // so make sure that Pattern is handled even if the
    // specified Size is smaller than the size of the Pattern.
    // TODO:
    //  Remove this.
    //  Its the users responsibility to make sure the size is valid.
    auto ParsedPattern = ParsePattern(IdaPattern);
    std::size_t PatternSize = ParsedPattern.size();

    std::size_t BufferSize = (PatternSize > Size) ? PatternSize : Size;
    auto Buffer = this->Read(StartOffset, BufferSize);

    if (Buffer.empty())
    {
      return std::nullopt;
    }

    auto Parsed = ParsePattern(IdaPattern);
    auto MatchOffset = FindPattern(Buffer, ParsedPattern);

    if (MatchOffset)
    {
      // Return offset & size of successfully matched pattern
      return Result<>{
        MatchRange{
          StartOffset + *MatchOffset,
          PatternSize
        }
      };
    }

    return std::nullopt;
  }

  std::optional<DumpAnalyzer::Result<std::vector<DumpAnalyzer::MatchRange>>>
    DumpAnalyzer::FindPatternSubsequence(std::uint64_t StartOffset, std::size_t Size,
      const std::vector<std::string>& IdaPatterns) const
  {
    Result<std::vector<MatchRange>> Out;

    // List of offset & size info of all patterns that matched
    std::vector<MatchRange> MatchOffsets;

    std::size_t PatternIndex = 0;
    std::uint64_t NextOffset = StartOffset;
    std::size_t NextSize = Size;

    for (const auto& IdaPattern : IdaPatterns)
    {
      auto Pattern = this->FindPattern(NextOffset, NextSize, IdaPattern);

      if (!Pattern)
      {
        // No match found
        break;
      }

      std::uint64_t PatternOffset = Pattern->Range.Offset;
      std::size_t PatternSize = Pattern->Range.Size;
      MatchOffsets.push_back({ PatternOffset, PatternSize });

      // Start matching the next pattern at the next offset beyond
      // the range of the current match.
      NextOffset = PatternOffset + PatternSize;
      NextSize = Size - (NextOffset - StartOffset);
      ++PatternIndex;

      if (PatternIndex == 1)
      {
        // Start offset of the pattern
        Out.Range.Offset = PatternOffset;
      }
      
      if (PatternIndex == IdaPatterns.size())
      {
        // Final pattern found, return pattern coverage range.
        Out.Range.Size = (PatternOffset + PatternSize) - Out.Range.Offset;
        Out.Value = MatchOffsets;
        return Out;
      }
    }

    return std::nullopt;
  }

  std::optional<DumpAnalyzer::Result<std::vector<DumpAnalyzer::MatchRange>>>
    DumpAnalyzer::FindInstructionSequence(std::uint64_t StartOffset, std::size_t Size,
      const std::vector<MatchInstruction>& Pattern) const
  {
    if (Pattern.empty())
    {
      // Pattern cant be empty
      return std::nullopt;
    }

    // Read a chunk from the function start
    auto Buffer = this->Read(StartOffset, Size);

    if (Buffer.empty())
    {
      return std::nullopt;
    }

    Result<std::vector<MatchRange>> Out;
    std::vector<MatchRange> MatchOffsets;
    std::size_t PatternIndex = 0;
    std::size_t Offset = 0;
    ZydisDecoderContext Context;

    // Helper to reset sequence state
    auto ResetMatcher = [&]()
    {
      PatternIndex = 0;
      MatchOffsets.clear();
    };

    while (Offset < Buffer.size())
    {
      ZydisDecodedInstruction Instruction;

      if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(
        &this->Decoder,
        &Context,
        Buffer.data() + Offset,
        Buffer.size() - Offset,
        &Instruction)))
      {
        // Decode failure, reset and advance by one byte
        ++Offset;
        ResetMatcher();
        continue;
      }

      ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];

      if (!ZYAN_SUCCESS(ZydisDecoderDecodeOperands(
        &this->Decoder,
        &Context,
        &Instruction,
        Operands,
        Instruction.operand_count_visible)))
      {
        // Invalid operands, reset and skip instruction
        Offset += Instruction.length;
        ResetMatcher();
        continue;
      }

      std::uint64_t InstructionOffset = StartOffset + Offset;
      const MatchInstruction& MIInstruction = Pattern[PatternIndex];

      // Mnemonic check (wildcard if nullopt)
      if (MIInstruction.Mnemonic)
      {
        if (*MIInstruction.Mnemonic == ZYDIS_MNEMONIC_INVALID ||
          *MIInstruction.Mnemonic != Instruction.mnemonic)
        {
          // Mismatch, reset and skip
          Offset += Instruction.length;
          ResetMatcher();
          continue;
        }
      }

      // Operand count check
      if (Instruction.operand_count_visible != MIInstruction.Operands.size())
      {
        Offset += Instruction.length;
        ResetMatcher();
        continue;
      }

      // Per-operand checks
      std::size_t OperandsMatched = 0;

      for (std::size_t I = 0; I < Instruction.operand_count_visible; ++I)
      {
        const auto& Operand = Operands[I];
        const auto& MIOperand = MIInstruction.Operands[I];

        if (!MIOperand)
        {
          ++OperandsMatched;
          continue;
        }

        if (Operand.type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
          if (!MIOperand->Reg || MIOperand->Imm || MIOperand->Mem ||
            Operand.reg.value != *MIOperand->Reg)
          {
            ResetMatcher();
            break;
          }

          ++OperandsMatched;
        }
        else if (Operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
          if (!MIOperand->Imm || MIOperand->Reg || MIOperand->Mem)
          {
            ResetMatcher();
            break;
          }
          
          bool ImmediateMatch = false;

          if (Operand.imm.is_signed)
          {
            if (Operand.imm.size == sizeof(std::uint8_t) * CHAR_BIT) // 8-bits
            {
              ImmediateMatch = (static_cast<std::uint8_t>(Operand.imm.value.u) == *MIOperand->Imm);
            }
            else if (Operand.imm.size == sizeof(std::uint16_t) * CHAR_BIT) // 16-bits
            {
              ImmediateMatch = (static_cast<std::uint16_t>(Operand.imm.value.u) == *MIOperand->Imm);
            }
            else if (Operand.imm.size == sizeof(std::uint32_t) * CHAR_BIT) // 32-bits
            {
              ImmediateMatch = (static_cast<std::uint32_t>(Operand.imm.value.u) == *MIOperand->Imm);
            }
            else // 64-bits
            {
              ImmediateMatch = (static_cast<std::uint64_t>(Operand.imm.value.u) == *MIOperand->Imm);
            }
          }
          else
          {
            ImmediateMatch = (Operand.imm.value.u == *MIOperand->Imm);
          }

          if (!ImmediateMatch)
          {
            ResetMatcher();
            break;
          }

          ++OperandsMatched;
        }
        else if (Operand.type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
          if (!MIOperand->Mem || MIOperand->Reg || MIOperand->Imm)
          {
            ResetMatcher();
            break;
          }

          if (MIOperand->Mem->Base && Operand.mem.base != *MIOperand->Mem->Base)
          {
            ResetMatcher();
            break;
          }

          if (MIOperand->Mem->Index && Operand.mem.index != *MIOperand->Mem->Index)
          {
            ResetMatcher();
            break;
          }

          if (MIOperand->Mem->Scale && Operand.mem.scale != *MIOperand->Mem->Scale)
          {
            ResetMatcher();
            break;
          }

          if (MIOperand->Mem->Disp && Operand.mem.disp.value != *MIOperand->Mem->Disp)
          {
            ResetMatcher();
            break;
          }

          ++OperandsMatched;
        }
      }

      // If any operand failed to match
      if (OperandsMatched != Instruction.operand_count_visible)
      {
        Offset += Instruction.length;
        ResetMatcher();
        continue;
      }

      // Record the match and advance the sequence
      MatchOffsets.push_back({ InstructionOffset, Instruction.length });
      ++PatternIndex;

      if (PatternIndex == 1)
      {
        Out.Range.Offset = InstructionOffset;
      }

      if (PatternIndex == Pattern.size())
      {
        Out.Range.Size = (InstructionOffset + Instruction.length) - Out.Range.Offset;
        Out.Value = MatchOffsets;
        return Out;
      }

      Offset += Instruction.length;
    }

    return std::nullopt;
  }

  std::optional<DumpAnalyzer::Result<std::vector<DumpAnalyzer::MatchRange>>>
    DumpAnalyzer::FindInstructionSubsequence(std::uint64_t StartOffset, std::size_t Size,
      const std::vector<MatchInstruction>& Pattern) const
  {
    if (Pattern.empty())
    {
      // Pattern cant be empty
      return std::nullopt;
    }

    // Read a chunk from the function start
    auto Buffer = this->Read(StartOffset, Size);

    if (Buffer.empty())
    {
      return std::nullopt;
    }

    Result<std::vector<MatchRange>> Out;

    // List of offset & size info of all pattern matched instructions
    std::vector<MatchRange> MatchOffsets;

    // Currently matched instruction index in subsequence
    std::size_t PatternIndex = 0;

    std::size_t Offset = 0;
    ZydisDecoderContext Context;

    while (Offset < Buffer.size())
    {
      ZydisDecodedInstruction Instruction;

      if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(
        &this->Decoder,
        &Context,
        Buffer.data() + Offset,
        Buffer.size() - Offset,
        &Instruction)))
      {
        ++Offset;
        continue;
      }

      ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];

      if (!ZYAN_SUCCESS(ZydisDecoderDecodeOperands(
        &this->Decoder,
        &Context,
        &Instruction,
        Operands,
        Instruction.operand_count_visible)))
      {
        // Invalid Instruction?
        Offset += Instruction.length;
        continue;
      }

      std::uint64_t InstructionOffset = StartOffset + Offset;
      const MatchInstruction& MIInstruction = Pattern[PatternIndex];

      // We only care about matching the mnemonic if
      // our pattern mnemonic is not a wildcard.
      if (MIInstruction.Mnemonic)
      {
        // If this condition is true, our pattern isnt a wildcad.
        // We mus therefore check if our mnemonics
        // match with the current instruction.

        if (*MIInstruction.Mnemonic == ZYDIS_MNEMONIC_INVALID ||
          *MIInstruction.Mnemonic != Instruction.mnemonic)
        {
          // Mnemonic doesnt match
          Offset += Instruction.length;
          continue;
        }
      }

      if (Instruction.operand_count_visible != MIInstruction.Operands.size())
      {
        // Pattern size must match instruction size (operands)
        Offset += Instruction.length;
        continue;
      }

      std::size_t OperandsMatched = 0;

      for (std::size_t I = 0; I < Instruction.operand_count_visible; ++I)
      {
        const auto& Operand = Operands[I];
        auto& MIOperand = MIInstruction.Operands[I];

        // Empty operand means we hit a wildcard.
        // Operand is therefore a match no matter what.
        if (!MIOperand)
        {
          ++OperandsMatched;
          continue;
        }

        if (Operand.type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
          if (!MIOperand->Reg || MIOperand->Imm || MIOperand->Mem)
          {
            // Decoded operand is a register but pattern operand
            // is not a register.
            break;
          }

          if (Operand.reg.value != *MIOperand->Reg)
          {
            // Pattern operand doesnt match decoded operand
            break;
          }

          // Reaching this point means that the registers match
          ++OperandsMatched;
        }
        else if (Operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
          if (!MIOperand->Imm || MIOperand->Reg || MIOperand->Mem)
          {
            // Decoded operand is an immediate value but pattern operand
            // is not an immediate value.
            break;
          }

          // Signed immediate values must be converted to unsigned
          // because our MemoryOperand struct defines an unsigned 'Imm' field.
          // The reason we do it this way is to handle jmp, jz, jnz etc.
          // signed immediate displacements.
          if (Operand.imm.is_signed)
          {
            if (Operand.imm.size == sizeof(std::uint8_t) * CHAR_BIT) // 8-bits
            {
              if (static_cast<std::uint8_t>(Operand.imm.value.u) != *MIOperand->Imm)
              {
                break;
              }
            }
            else if (Operand.imm.size == sizeof(std::uint16_t) * CHAR_BIT) // 16-bits
            {
              if (static_cast<std::uint16_t>(Operand.imm.value.u) != *MIOperand->Imm)
              {
                break;
              }
            }
            else if (Operand.imm.size == sizeof(std::uint32_t) * CHAR_BIT) // 32-bits
            {
              if (static_cast<std::uint32_t>(Operand.imm.value.u) != *MIOperand->Imm)
              {
                break;
              }
            }
            // Redundant? Can signed immediates exist in 64-bit Intel ASM?
            else if (Operand.imm.size == sizeof(std::uint64_t) * CHAR_BIT) // 64-bits
            {
              if (static_cast<std::uint64_t>(Operand.imm.value.u) != *MIOperand->Imm)
              {
                break;
              }
            }
          }
          else
          {
            // Unsigned immediates, no matter size can simply be compared,
            // as we dont need to think about 2s complement conversions.
            if (Operand.imm.value.u != *MIOperand->Imm)
            {
              // Pattern operand doesnt match decoded operand
              break;
            }
          }

          // Reaching this point means that the immediate values match
          ++OperandsMatched;
        }
        else if (Operand.type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
          if (!MIOperand->Mem || MIOperand->Reg || MIOperand->Imm)
          {
            // Decoded operand is a memory operand but pattern operand
            // is not a memory operand.
            break;
          }

          // If none of these are true,
          // treat entire operand as a matched wildcard and move to next.

          if (MIOperand->Mem->Base)
          {
            if (Operand.mem.base != *MIOperand->Mem->Base)
            {
              break;
            }
          }

          if (MIOperand->Mem->Index)
          {
            if (Operand.mem.index != *MIOperand->Mem->Index)
            {
              break;
            }
          }

          if (MIOperand->Mem->Scale)
          {
            if (Operand.mem.scale != *MIOperand->Mem->Scale)
            {
              break;
            }
          }

          if (MIOperand->Mem->Disp)
          {
            // Unlike for the immediate handler above,
            // there is no need to check the size of the displacement
            // or convert between signed and unsigned values
            // because both Zydis' disp value and our Disp are signed.
            if (Operand.mem.disp.value != *MIOperand->Mem->Disp)
            {
              break;
            }
          }

          // All effective address components in memory operand
          // match, therefore our operand matches the pattern.
          ++OperandsMatched;
        }
      }

      if (OperandsMatched != Instruction.operand_count_visible)
      {
        // Not all operands matched the pattern,
        // welp move to the next instruction to try again
        Offset += Instruction.length;
        continue;
      }

      // For each subsequence match, save the offset & size
      MatchOffsets.push_back({ InstructionOffset, Instruction.length });
      ++PatternIndex;

      if (PatternIndex == 1)
      {
        // Start offset of the pattern
        Out.Range.Offset = InstructionOffset;
      }

      if (PatternIndex == Pattern.size())
      {
        // Final pattern found, return pattern coverage range.
        Out.Range.Size = (InstructionOffset + Instruction.length) - Out.Range.Offset;
        Out.Value = MatchOffsets;
        return Out;
      }

      Offset += Instruction.length;
    }

    return std::nullopt;
  }

  // Resolves the RIP relative address of the first instruction
  // it encounters that matches the conditions (i.e. RIP + DISP).
  // InstructionSize should be large enough to hold the full instruction (e.g., 10–15 bytes for x64).
  std::optional<DumpAnalyzer::Result<std::uint64_t>>
    DumpAnalyzer::ResolveRipRelativeOffset(std::uint64_t StartOffset, std::size_t Size,
    std::function<bool(ZydisDecodedInstruction*, ZydisDecodedOperand*)> Filter) const
  {
    auto Buffer = this->Read(StartOffset, Size);

    if (Buffer.empty())
    {
      // Reading failed, buffer too small?
      return std::nullopt;
    }

    std::size_t Offset = 0;
    ZydisDecoderContext Context;

    while (Offset < Buffer.size())
    {
      ZydisDecodedInstruction Instruction;

      if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(
        &this->Decoder,
        &Context,
        Buffer.data() + Offset,
        Buffer.size() - Offset,
        &Instruction)))
      {
        // Invalid Instruction address?
        Offset += 1;
        continue;
      }

      ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];

      if (!ZYAN_SUCCESS(ZydisDecoderDecodeOperands(
        &this->Decoder,
        &Context,
        &Instruction,
        Operands,
        Instruction.operand_count)))
      {
        // Invalid Instruction address?
        Offset += Instruction.length;
        continue;
      }

      if (Filter && !Filter(&Instruction, Operands))
      {
        // Filtering out
        Offset += Instruction.length;
        continue;
      }

      std::uint64_t InstructionStart = StartOffset + Offset;
      std::int64_t InstructionEnd = static_cast<std::int64_t>(InstructionStart + Instruction.length);

      Result<std::uint64_t> Out = {
        MatchRange{
          InstructionStart,
          Instruction.length
        }
      };

      // For now, in 64-bit assembly, only one operand can use RIP relative addressing.
      // So enumerate over all operands to find it.
      for (int I = 0; I < Instruction.operand_count; ++I)
      {
        const auto& Operand = Operands[I];

        // Displacement relative value
        if (Operand.type == ZYDIS_OPERAND_TYPE_MEMORY &&
          Operand.mem.base == ZYDIS_REGISTER_RIP &&
          Operand.mem.disp.size > 0)
        {
          // Do some casting to avoid negative wraparound due to integer promotion (in std::uint64_t)
          std::int64_t Displacement = static_cast<std::int64_t>(Operand.mem.disp.value);
          std::uint64_t ResolvedOffset = static_cast<std::uint64_t>(InstructionEnd + Displacement);
          Out.Value = ResolvedOffset;

          return Out;
        }
        // Immediate relative value
        else if (Operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
          Operand.imm.is_signed)
        {
          std::int64_t Immediate = static_cast<std::int64_t>(Operand.imm.value.s);
          std::uint64_t ResolvedOffset = static_cast<std::uint64_t>(InstructionEnd + Immediate);
          Out.Value = ResolvedOffset;

          return Out;
        }
      }

      Offset += Instruction.length;
    }

    // Unable to resolve RIP relative address for some reason
    return std::nullopt;
  }

  // TODO:
  //  Handle negative offsets, for now this is fine since
  //  we're working mainly with .Text and .Rdata sections.
  std::optional<DumpAnalyzer::Result<std::uint64_t>>
    DumpAnalyzer::FindRipRelativeReference(std::uint64_t StartOffset, std::size_t Size, std::uint64_t TargetOffset,
    std::function<bool(ZydisDecodedInstruction*, ZydisDecodedOperand*)> Filter) const
  {
    auto Buffer = this->Read(StartOffset, Size);

    if (Buffer.empty())
    {
      return std::nullopt;
    }

    std::size_t Offset = 0;
    ZydisDecoderContext Context;

    while (Offset < Buffer.size())
    {
      ZydisDecodedInstruction Instruction;

      if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(
        &this->Decoder,
        &Context,
        Buffer.data() + Offset,
        Buffer.size() - Offset,
        &Instruction)))
      {
        Offset += 1;
        continue;
      }

      ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];

      if (!ZYAN_SUCCESS(ZydisDecoderDecodeOperands(
        &this->Decoder,
        &Context,
        &Instruction,
        Operands,
        Instruction.operand_count)))
      {
        Offset += Instruction.length;
        continue;
      }

      if (Filter && !Filter(&Instruction, Operands))
      {
        // Filtering out
        Offset += Instruction.length;
        continue;
      }

      std::uint64_t InstructionStart = StartOffset + Offset;
      std::int64_t InstructionEnd = static_cast<std::int64_t>(InstructionStart + Instruction.length);

      // For now, in 64-bit assembly, only one operand can use RIP relative addressing.
      // So enumerate over all operands to find it.
      for (int I = 0; I < Instruction.operand_count; ++I)
      {
        const auto& Operand = Operands[I];
        std::uint64_t ResolvedOffset = 0;

        // Displacement relative value
        if (Operand.type == ZYDIS_OPERAND_TYPE_MEMORY &&
          Operand.mem.base == ZYDIS_REGISTER_RIP &&
          Operand.mem.disp.size > 0)
        {
          std::int64_t Displacement = static_cast<std::int64_t>(Operand.mem.disp.value);
          ResolvedOffset = static_cast<std::uint64_t>(InstructionEnd + Displacement);
        }
        // Immediate relative value
        else if (Operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
          Operand.imm.is_signed)
        {
          std::int64_t Immediate = static_cast<std::int64_t>(Operand.imm.value.s);
          ResolvedOffset = static_cast<std::uint64_t>(InstructionEnd + Immediate);
        }

        if (ResolvedOffset == TargetOffset)
        {
          return Result<std::uint64_t>{
            MatchRange{
              InstructionStart,
              Instruction.length,
            },
            InstructionStart
          };
        }
      }

      Offset += Instruction.length;
    }

    return std::nullopt;
  }

  // Extracts first displacement encountered.
  std::optional<DumpAnalyzer::Result<std::uint32_t>>
    DumpAnalyzer::ExtractDisplacement(std::uint64_t StartOffset, std::size_t Size) const
  {
    auto Buffer = this->Read(StartOffset, Size);

    if (Buffer.empty())
    {
      return std::nullopt;
    }

    std::size_t Offset = 0;
    ZydisDecoderContext Context;

    while (Offset < Buffer.size())
    {
      ZydisDecodedInstruction Instruction;

      if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(
        &this->Decoder,
        &Context,
        Buffer.data() + Offset,
        Buffer.size() - Offset,
        &Instruction)))
      {
        Offset += 1;
        continue;
      }

      ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];

      if (!ZYAN_SUCCESS(ZydisDecoderDecodeOperands(
        &this->Decoder,
        &Context,
        &Instruction,
        Operands,
        Instruction.operand_count)))
      {
        Offset += Instruction.length;
        continue;
      }

      // Look for an operand with type memory that contains a displacement.
      for (std::size_t i = 0; i < Instruction.operand_count; i++)
      {
        if (Operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY &&
          Operands[i].mem.disp.size > 0)
        {
          return Result<std::uint32_t>{
            MatchRange{
              StartOffset + Offset,
              Instruction.length,
            },
            static_cast<std::uint32_t>(Operands[i].mem.disp.value)
          };
        }
      }

      Offset += Instruction.length;
    }

    return std::nullopt;
  }

  // Extracts first immediate encountered.
  // TODO: Return vector of all immediates within range instead
  std::optional<DumpAnalyzer::Result<std::uint64_t>> DumpAnalyzer::ExtractImmediate(
    std::uint64_t StartOffset, std::size_t Size) const
  {
    auto Buffer = this->Read(StartOffset, Size);

    if (Buffer.empty())
    {
      return std::nullopt;
    }

    std::size_t Offset = 0;
    ZydisDecoderContext Context;

    while (Offset < Buffer.size())
    {
      ZydisDecodedInstruction Instruction;

      if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(
        &this->Decoder,
        &Context,
        Buffer.data() + Offset,
        Buffer.size() - Offset,
        &Instruction)))
      {
        Offset += 1;
        continue;
      }

      ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];
      if (!ZYAN_SUCCESS(ZydisDecoderDecodeOperands(
        &this->Decoder,
        &Context,
        &Instruction,
        Operands,
        Instruction.operand_count)))
      {
        Offset += Instruction.length;
        continue;
      }

      // Look for an operand with type immediate.
      for (std::size_t i = 0; i < Instruction.operand_count; i++)
      {
        if (Operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
          return Result<std::uint64_t>{
            MatchRange{
              StartOffset + Offset,
              Instruction.length
            },
            Operands[i].imm.value.u
          };
        }
      }

      Offset += Instruction.length;
    }

    return std::nullopt;
  }

  template <typename XorT>
  std::optional<DumpAnalyzer::Result<std::vector<DumpAnalyzer::TslDecryption<XorT>>>>
    DumpAnalyzer::ExtractTslDecryptors(std::uint64_t StartOffset, std::size_t Size) const
  {
    auto Buffer = this->Read(StartOffset, Size);

    if (Buffer.empty())
    {
      return std::nullopt;
    }

    bool X32Mode = false;

    if constexpr (std::is_same_v<XorT, std::uint32_t>)
    {
      X32Mode = true;
    }

    struct InstructionChecklist
    {
      bool Xor1 = false;
      bool Xor2 = false;
      bool Xor3 = false;
      bool Shift = false;
      bool Rotate = false;

      bool IsXorExtracted() const
      {
        return (this->Xor1 && this->Xor2 && this->Xor3);
      }

      bool IsAllExtracted() const
      {
        return (this->IsXorExtracted() && this->Shift && this->Rotate);
      }
    };

    // Instruction info, helper
    struct InstructionRange
    {
      std::uint64_t Offset = 0;
      std::size_t Size = 0;
    };

    // Chain of registers and instructions
    // belonging to a single TslDecryption opration.
    struct DecryptionChain
    {
      std::uint8_t ID = 0;
      bool Completed = false;
      TslDecryption<XorT> Extracted;
      InstructionChecklist Checklist;
      std::unordered_map<ZydisRegister, std::string> RegisterPseudocode;

      // Instruction offsets so we can calculate chain start offset and size
      // at the end of the enumeration.
      std::vector<InstructionRange> Ranges;

      std::optional<std::string> GetPseudocode(ZydisRegister Register) const
      {
        auto It = this->RegisterPseudocode.find(Register);

        if (It != this->RegisterPseudocode.end())
        {
          // Currently buffered pseudocode
          // upto this register in chain.
          return It->second;
        }

        return std::nullopt;
      };
    };

    // Pseudocode placeholder identifiers
    constexpr const char* FunctionName = CodeGeneration::FunctionName;
    constexpr const char* ParamName = CodeGeneration::ParamName;

    // Each entry represents a chain of registers and instructions
    // belonging to a single TslDecryption operation.
    std::vector<DecryptionChain> Chains;

    // Chains *could* contain incomplete chains (TslDecryption)
    // by the end of the instruction enumeration.
    // We only want to return TslDecryptions from completed chains.
    std::vector<DecryptionChain> CompletedChains;

    // This maps a related register to a Chain in the Chains array,
    // so that we know which instruction belongs to which decryption chain (if any).
    std::unordered_map<ZydisRegister, std::size_t> ChainMap;

    auto BelongsToChain = [&ChainMap](ZydisRegister Register)
      -> std::optional<std::size_t>
    {
      auto It = ChainMap.find(Register);

      if (It != ChainMap.end())
      {
        return It->second; // Index
      }

      return std::nullopt;
    };

    auto AddToChain = [&ChainMap](ZydisRegister Register, std::size_t ChainIndex)
      -> void
    {
      // Map register to a chain pointed to by ChainIndex
      ChainMap[Register] = ChainIndex;
    };

    auto CreateChain = [&Chains, &ChainMap](ZydisRegister Register)
      -> std::size_t
    {
      static std::uint8_t ChainID = 0;
      Chains.push_back({ ChainID });
      std::size_t ChainIndex = Chains.size() - 1;
      ChainMap[Register] = ChainIndex;
      ++ChainID; // Increment for (potential) next chain
      return ChainIndex;
    };

    // Copy Range info from one instruction chain to another,
    // presumably because the instruction chains are supposed to be one Chain.
    // 
    // This is only needed for X64 decryptor chains whose XOR values are stored
    // in registers instead of as an immediate in the isntruction itself.
    // 
    // This has no effect on the actual operation decryptor finding,
    // it's only needed to save how many bytes the decryptor chain (X64) takes.
    auto CopyRanges = [&Chains](const std::optional<std::size_t>& SrcChainOpt,
      DecryptionChain& DstChain)
    {
      if (SrcChainOpt)
      {
        std::size_t SrcChainIndex = *SrcChainOpt;
        DecryptionChain& SrcChain = Chains[SrcChainIndex];

        for (const auto& SrcRange : SrcChain.Ranges)
        {
          DstChain.Ranges.push_back(SrcRange);
        }
      }
    };

    //std::size_t Count = 0;
    std::size_t Offset = 0;
    RegisterTracker<XorT> Tracker;

    ZydisDecodedInstruction Instruction;
    ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];
    ZydisDecoderContext Context;

    while (Offset < Buffer.size() /*&& Count < MaxInstructions*/)
    {
      if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(
        &this->Decoder,
        &Context,
        Buffer.data() + Offset,
        Buffer.size() - Offset,
        &Instruction)))
      {
        Offset += 1; // Skip one byte if decode failed
        continue;
      }

      if (!ZYAN_SUCCESS(ZydisDecoderDecodeOperands(
        &this->Decoder,
        &Context,
        &Instruction,
        Operands,
        Instruction.operand_count)))
      {
        Offset += Instruction.length;
        continue;
      }

      // We only want to capture 64-bit or 32-bit operands,
      // and we arent interested in any instruction with less than two operands.
      if (Instruction.operand_width != sizeof(XorT) * CHAR_BIT
        || Instruction.operand_count < 2)
      {
        Offset += Instruction.length;
        continue;
      }

      std::uint64_t InstructionOffset = StartOffset + Offset;
      ZydisRegister DstRegister = Operands[0].reg.value;
      ZydisRegister SrcRegister = Operands[1].reg.value;

      auto DstChained = BelongsToChain(DstRegister);
      auto SrcChained = BelongsToChain(SrcRegister);

      // MOV reg, imm
      if ((Instruction.mnemonic == ZYDIS_MNEMONIC_MOV) &&
        Operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        Operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
      {
        if (!DstChained)
        {
          // We should create a Chain for each occurrence of MOV reg, imm
          // so we can record the starting offset of the X64 decryptor chain properly.
          // 
          // This is only needed for X64 decryptors because their XOR values are grabbed
          // from a register during the XOR instruction (e.g. XOR reg, reg).
          // 
          // For X32 decryptors whose XOR values are immediates (e.g. XOR reg, imm)
          // this conditional is unnecessary and has no real effect.
          std::size_t ChainIndex = CreateChain(DstRegister);
          DecryptionChain& Chain = Chains[ChainIndex];

          // Save instruction range info
          Chain.Ranges.push_back({ InstructionOffset, Instruction.length });
        }

        Tracker.Store(DstRegister, static_cast<XorT>(Operands[1].imm.value.u));
      }
      // MOV reg, reg
      else if ((Instruction.mnemonic == ZYDIS_MNEMONIC_MOV) &&
        Operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        Operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
      {
        // NOTE:
        //  It makes no sense to create a new chain or track instruction Range here,
        //  like it does in the condition above.

        Tracker.Propagate(DstRegister, SrcRegister);

        if (SrcChained)
        {
          std::size_t ChainIndex = *SrcChained;
          DecryptionChain& Chain = Chains[ChainIndex];
          AddToChain(DstRegister, ChainIndex);

          if (auto Code = Chain.GetPseudocode(SrcRegister); Code)
          {
            Chain.RegisterPseudocode[DstRegister] = *Code;
          }
          //else
          //{
          //  Chain.RegisterPseudocode[DstRegister] = ParamName;
          //}
        }
      }
      // XOR
      else if (Instruction.mnemonic == ZYDIS_MNEMONIC_XOR)
      {
        // New chain starting from XOR begins:
        if (!DstChained)
        {
          std::size_t ChainIndex = CreateChain(DstRegister);
          DecryptionChain& Chain = Chains[ChainIndex];
          Chain.Extracted.IsX32 = X32Mode;

          if (auto Op1 = Tracker.ResolveOperand(Operands[1]); Op1)
          {
            Chain.RegisterPseudocode[DstRegister] = Util::String::Format("%s ^ 0x%llX", ParamName, *Op1);
            Chain.Extracted.Xor1 = *Op1;
            Chain.Checklist.Xor1 = true;

            // Save instruction range info
            Chain.Ranges.push_back({ InstructionOffset, Instruction.length });
            CopyRanges(SrcChained, Chain);
          }
          else
          {
            if (auto Code = Chain.GetPseudocode(SrcRegister); Code)
            {
              Chain.RegisterPseudocode[DstRegister] = Util::String::Format("%s ^ %s", ParamName, Code->c_str());
            }
            else
            {
              Chain.RegisterPseudocode[DstRegister] = Util::String::Format("%s ^ %s", ParamName, ParamName);
            }
          }
        }
        else if (DstChained)
        {
          std::size_t ChainIndex = *DstChained;
          DecryptionChain& Chain = Chains[ChainIndex];

          if (Chain.Checklist.IsXorExtracted())
          {
            Offset += Instruction.length;
            continue;
          }

          if (auto DstCode = Chain.GetPseudocode(DstRegister); DstCode)
          {
            if (auto Op1 = Tracker.ResolveOperand(Operands[1]); Op1)
            {
              Chain.RegisterPseudocode[DstRegister] = Util::String::Format("%s ^ 0x%llX", DstCode->c_str(), *Op1);

              if (Chain.Extracted.Xor1)
              {
                Chain.Extracted.Xor2 = *Op1;
                Chain.Checklist.Xor2 = true;
              }
              else // Xor1 not not set yet, so this must be it
              {
                Chain.Extracted.Xor1 = *Op1;
                Chain.Checklist.Xor1 = true;
              }

              CopyRanges(SrcChained, Chain);
            }
            else
            {
              if (auto SrcCode = Chain.GetPseudocode(SrcRegister); SrcCode)
              {
                Chain.RegisterPseudocode[DstRegister] = Util::String::Format("%s ^ %s", DstCode->c_str(), SrcCode->c_str());
              }
              else
              {
                Chain.RegisterPseudocode[DstRegister] = Util::String::Format("%s ^ %s", DstCode->c_str(), ParamName);
              }

              Chain.Checklist.Xor3 = true;
            }

            // Save instruction range info
            Chain.Ranges.push_back({ InstructionOffset, Instruction.length });
          }
        }
      }
      // ROR / ROL
      else if ((Instruction.mnemonic == ZYDIS_MNEMONIC_ROR || Instruction.mnemonic == ZYDIS_MNEMONIC_ROL))
      {
        // New chain starting from ROR / ROL begins:
        if (!DstChained)
        {
          std::size_t ChainIndex = CreateChain(DstRegister);
          DecryptionChain& Chain = Chains[ChainIndex];
          Chain.Extracted.IsX32 = X32Mode;

          bool Right = (Instruction.mnemonic == ZYDIS_MNEMONIC_ROR);
          std::string RotVar = Right ? "_rotr64" : "_rotl64";
          RotVar = X32Mode ? (Right ? "_rotr" : "_rotl") : RotVar;

          if (auto Op1 = Tracker.ResolveOperand(Operands[1]); Op1)
          {
            Chain.Extracted.IsRotateRight = Right;
            Chain.Extracted.Rotate = static_cast<std::uint8_t>(*Op1);
            Chain.Checklist.Rotate = true;
            Chain.RegisterPseudocode[DstRegister] = Util::String::Format("%s(%s, %d)", RotVar.c_str(), ParamName, *Op1);

            // Save instruction range info
            Chain.Ranges.push_back({ InstructionOffset, Instruction.length });
          }
          else
          {
            if (auto Code = Chain.GetPseudocode(SrcRegister); Code)
            {
              Chain.RegisterPseudocode[DstRegister] = Util::String::Format("%s(%s, %s)", RotVar.c_str(), ParamName, Code->c_str());
            }
            else
            {
              Chain.RegisterPseudocode[DstRegister] = Util::String::Format("%s(%s, %s)", RotVar.c_str(), ParamName, ParamName);
            }
          }
        }
        else if (DstChained)
        {
          std::size_t ChainIndex = *DstChained;
          DecryptionChain& Chain = Chains[ChainIndex];

          if (Chain.Checklist.Rotate)
          {
            Offset += Instruction.length;
            continue;
          }

          bool Right = (Instruction.mnemonic == ZYDIS_MNEMONIC_ROR);
          std::string RotVar = Right ? "_rotr64" : "_rotl64";
          RotVar = X32Mode ? (Right ? "_rotr" : "_rotl") : RotVar;

          if (auto DstCode = Chain.GetPseudocode(DstRegister); DstCode)
          {
            if (auto Op1 = Tracker.ResolveOperand(Operands[1]); Op1)
            {
              Chain.Extracted.IsRotateRight = Right;
              Chain.Extracted.Rotate = static_cast<std::uint8_t>(*Op1);
              Chain.Checklist.Rotate = true;
              Chain.RegisterPseudocode[DstRegister] = Util::String::Format("%s(%s, %d)", RotVar.c_str(), DstCode->c_str(), *Op1);

              // Save instruction range info
              Chain.Ranges.push_back({ InstructionOffset, Instruction.length });
            }
            else
            {
              if (auto SrcCode = Chain.GetPseudocode(SrcRegister); SrcCode)
              {
                Chain.RegisterPseudocode[DstRegister] = Util::String::Format("%s(%s, %s)", RotVar.c_str(), DstCode->c_str(), SrcCode->c_str());
              }
              else
              {
                Chain.RegisterPseudocode[DstRegister] = Util::String::Format("%s(%s ^ %s)", RotVar.c_str(), DstCode->c_str(), ParamName);
              }

              Chain.Checklist.Rotate = true;
            }
          }
        }
      }
      // SHL / SHR
      else if ((Instruction.mnemonic == ZYDIS_MNEMONIC_SHL || Instruction.mnemonic == ZYDIS_MNEMONIC_SHR))
      {
        // New chain starting from SHL / SHR begins:
        if (!DstChained)
        {
          std::size_t ChainIndex = CreateChain(DstRegister);
          DecryptionChain& Chain = Chains[ChainIndex];
          Chain.Extracted.IsX32 = X32Mode;

          bool Right = (Instruction.mnemonic == ZYDIS_MNEMONIC_SHR);
          std::string ShiftVar = Right ? ">>" : "<<";

          if (auto Op1 = Tracker.ResolveOperand(Operands[1]); Op1)
          {
            Chain.Extracted.IsShiftRight = Right;
            Chain.Extracted.Shift = static_cast<std::uint8_t>(*Op1);
            Chain.Checklist.Shift = true;
            Chain.RegisterPseudocode[DstRegister] = Util::String::Format("(%s %s %d)", ParamName, ShiftVar.c_str(), *Op1);

            // Save instruction range info
            Chain.Ranges.push_back({ InstructionOffset, Instruction.length });
          }
          else
          {
            if (auto Code = Chain.GetPseudocode(SrcRegister); Code)
            {
              Chain.RegisterPseudocode[DstRegister] = Util::String::Format("(%s %s %s)", ParamName, ShiftVar.c_str(), Code->c_str());
            }
            else
            {
              Chain.RegisterPseudocode[DstRegister] = Util::String::Format("(%s %s %s)", ParamName, ShiftVar.c_str(), ParamName);
            }
          }
        }
        else if (DstChained)
        {
          std::size_t ChainIndex = *DstChained;
          DecryptionChain& Chain = Chains[ChainIndex];

          if (Chain.Checklist.Shift)
          {
            Offset += Instruction.length;
            continue;
          }

          bool Right = (Instruction.mnemonic == ZYDIS_MNEMONIC_SHR);
          std::string ShiftVar = Right ? ">>" : "<<";

          if (auto DstCode = Chain.GetPseudocode(DstRegister); DstCode)
          {
            if (auto Op1 = Tracker.ResolveOperand(Operands[1]); Op1)
            {
              Chain.Extracted.IsShiftRight = Right;
              Chain.Extracted.Shift = static_cast<std::uint8_t>(*Op1);
              Chain.Checklist.Shift = true;
              Chain.RegisterPseudocode[DstRegister] = Util::String::Format("(%s %s %d)", DstCode->c_str(), ShiftVar.c_str(), *Op1);

              // Save instruction range info
              Chain.Ranges.push_back({ InstructionOffset, Instruction.length });
            }
            else
            {
              if (auto SrcCode = Chain.GetPseudocode(SrcRegister); SrcCode)
              {
                Chain.RegisterPseudocode[DstRegister] = Util::String::Format("(%s %s %s)", DstCode->c_str(), ShiftVar.c_str(), SrcCode->c_str());
              }
              else
              {
                Chain.RegisterPseudocode[DstRegister] = Util::String::Format("(%s %s %s)", DstCode->c_str(), ShiftVar.c_str(), ParamName);
              }

              Chain.Checklist.Shift = true;
            }
          }
        }
      }

      if (DstChained)
      {
        std::size_t ChainIndex = *DstChained;
        DecryptionChain& Chain = Chains[ChainIndex];

        // Check if we've extracted everything in the current chain
        if (!Chain.Completed && Chain.Checklist.IsAllExtracted() &&
          Chain.Extracted.Xor1 && Chain.Extracted.Xor2 &&
          Chain.Extracted.Rotate > 0 && Chain.Extracted.Shift > 0)
        {
          std::string Function =
            CodeGeneration::MakeFunction<XorT>(Chain.RegisterPseudocode[DstRegister]);

          Chain.Extracted.Pseudo.Code = Function;

          // Translates to:
          // std::uintNN <FunctionName>(std::uintNN <ParamName>)
          // {
          //   return <GeneratedPseudocodeHere>;
          // }

          Chain.Completed = true;
          CompletedChains.push_back(Chain);
        }
      }

      Offset += Instruction.length;
    }

    // Post extraction sorting etc.
    if (CompletedChains.size() > 0)
    {
      Result<std::vector<TslDecryption<XorT>>> Out;
      std::vector<TslDecryption<XorT>> ExtractedDecryptors;

      // Sort by order of appearance.
      // NOTE: To sort by order of completion, comment this out.
      std::sort(CompletedChains.begin(), CompletedChains.end(),
        [](const DecryptionChain& A, const DecryptionChain& B)
      {
        return A.ID < B.ID;
      });

      // All instruction ranges accross each completed chain
      std::vector<InstructionRange> InstructionRanges;

      for (const DecryptionChain& Chain : CompletedChains)
      {
        for (const auto& Range : Chain.Ranges)
        {
          InstructionRanges.push_back(Range);
        }

        ExtractedDecryptors.push_back(Chain.Extracted);
      }

      // Sort instruction ranges in ascending order (lowest first),
      // so that we can easily save the overall range covered by each completed chain.
      std::sort(InstructionRanges.begin(), InstructionRanges.end(),
        [](const InstructionRange& A, const InstructionRange& B)
      {
        return A.Offset < B.Offset;
      });

      // After sorting, we can index into the beginning and end of
      // the vector to grab the overall range coverage.
      const auto& LastRange = InstructionRanges.back();
      Out.Range.Offset = InstructionRanges[0].Offset;
      Out.Range.Size = (LastRange.Offset + LastRange.Size) - Out.Range.Offset;
      Out.Value = ExtractedDecryptors;

      return Out;
    }

    return std::nullopt;
  }

  template <Mode M>
  bool DumpAnalyzer::Analyze()
  {
    this->InFile.open(InFilePath, std::ios::binary);

    if (!this->InFile)
    {
      //std::cerr << "[!] Failed to open input file.\n";
      return false;
    }

    if constexpr (M == Mode::Regions)
    {
      this->InMetadata = this->_Read<MemoryDumper::Metadata>(0);

      std::uint64_t BaseAddress = this->InMetadata.BaseAddress;
      std::uint64_t RegionsSectionOffset = sizeof(MemoryDumper::Metadata);
      std::size_t RegionsSectionSize = this->InMetadata.RegionsSectionSize;
      std::size_t RegionSize = sizeof(pmm::Region);

      std::uint64_t EndOffset = RegionsSectionOffset + RegionsSectionSize;

      for (std::uint64_t Off = RegionsSectionOffset; Off < EndOffset; Off += RegionSize)
      {
        auto Region = this->_Read<pmm::Region>(Off);
        std::uint64_t AddressBegin = Region.AddressBegin;

        if (BaseAddress >= AddressBegin && BaseAddress < Region.AddressEnd)
        {
          this->InMetadata.BaseAddressInfo.Region = Region;
          this->InMetadata.BaseAddressInfo.RegionOffset = BaseAddress - AddressBegin;
        }

        this->InMemoryRegions.push_back(Region);
      }

      //std::cout << std::dec << "[?] Total regions loaded: " << this->InMemoryRegions.size() << std::hex << std::endl;
      this->InMetadata.DumpSectionOffset = RegionsSectionOffset + RegionsSectionSize;
    }
    else
    {
      this->AnalysisMode = Mode::Sparse;
    }

    this->ExtractAndSavePeHeaderAndSections();
    this->ExtractAndSaveFunctions();
    this->ExtractAndSaveFileVersion();
    return true;
  }

  bool DumpAnalyzer::Open(const std::string& FilePath)
  {
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&this->Decoder, this->MachineMode, this->StackWidth)))
    {
      //std::cerr << "[!] Failed to initialize decoder.\n";
      return false;
    }

    this->InFilePath = FilePath;
    return true;
  }

  DumpAnalyzer::DumpAnalyzer(const std::string& FilePath)
  {
    this->Open(FilePath);
  }

  DumpAnalyzer& DumpAnalyzer::operator=(const DumpAnalyzer& Other)
  {
    if (this == &Other)
    {
      return *this;
    }

    this->AnalysisMode = Other.AnalysisMode;
    this->InFilePath = Other.InFilePath;
    this->InMetadata = Other.InMetadata;
    this->InMemoryRegions = Other.InMemoryRegions;
    this->InPeHeader = Other.InPeHeader;
    this->InPeSections = Other.InPeSections;
    this->InFunctionOffsets = Other.InFunctionOffsets;
    this->Decoder = Other.Decoder;

    // Note: std::ifstream is not copyable, so InFile is not copied.
    return *this;
  }

  DumpAnalyzer::DumpAnalyzer(const DumpAnalyzer& Other) :
    AnalysisMode(Other.AnalysisMode),
    InFilePath(Other.InFilePath),
    InMetadata(Other.InMetadata),
    InMemoryRegions(Other.InMemoryRegions),
    InPeHeader(Other.InPeHeader),
    InPeSections(Other.InPeSections),
    InFunctionOffsets(Other.InFunctionOffsets),
    Decoder(Other.Decoder)
  {
    // Note: std::ifstream is not copyable, so InFile is not copied.
  }

  DumpAnalyzer::~DumpAnalyzer()
  {
    this->InFile.close();
  }

  // Explicit template instantiations.
  // Ugly ashell but whatever
  template std::optional<DumpAnalyzer::Result<std::vector<DumpAnalyzer::TslDecryption<std::uint32_t>>>>
    DumpAnalyzer::ExtractTslDecryptors<std::uint32_t>(std::uint64_t StartOffset, std::size_t Size) const;

  template std::optional<DumpAnalyzer::Result<std::vector<DumpAnalyzer::TslDecryption<std::uint64_t>>>>
    DumpAnalyzer::ExtractTslDecryptors<std::uint64_t>(std::uint64_t StartOffset, std::size_t Size) const;

  template std::optional<DumpAnalyzer::Result<std::vector<std::uint64_t>>>
    DumpAnalyzer::FindString<StringType::ASCII>(const std::string& Str, std::size_t MaxMatches) const;
  template std::optional<DumpAnalyzer::Result<std::vector<std::uint64_t>>>
    DumpAnalyzer::FindString<StringType::UTF16_LE>(const std::string& Str, std::size_t MaxMatches) const;

  template bool DumpAnalyzer::Analyze<Mode::Regions>();
  template bool DumpAnalyzer::Analyze<Mode::Sparse>();

} // !namespace COF
