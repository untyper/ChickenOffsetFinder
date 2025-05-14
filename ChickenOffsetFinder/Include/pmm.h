// Copyright (c) [2024] [Jovan J. E. Odassius]
//
// License: MIT (See the LICENSE file in the root directory)
// Github: https://github.com/untyper/process-memory-module

// TODO:
// - Add EPROCESS offsets for Winwodws 11.
// - Add method to attach by process name. For stealth purposes, the process should be acquired by enumerating the process list in EPROCESS.
// - Add method to change page protection e.g. set_page_protection(address, PAGE_READWRITE_EXECUTE)
// - Add pattern scanner (IDA style and C byte array style)
// - Adjust comments from snake_case to PascalCase
// - Test PE header and section extraction, see if theyre returned properly
// - Add method to retrieve version from process, either from PE header or EPROCESS.

#ifndef PMM_PROCESS_MEMORY_MODULE_H
#define PMM_PROCESS_MEMORY_MODULE_H

#include <hv.h>

#include <iostream>
#include <psapi.h>
#include <thread>
#include <chrono>
#include <string>
#include <unordered_map>
#include <vector>
#include <array>
#include <cstdint>
#include <functional>
#include <algorithm>
#include <optional>

#include <Windows.h>

namespace pmm
{

  enum class Error
  {
    Error, // Generic error

    // TODO: Define more error codes
  };

  template<typename T = bool>
  class Result
  {
  private:
    T Value = {};
    Error ErrorValue = {};
    bool HasValue = false;

  public:
    // Constructors
    inline static Result Success(const T& Val)
    {
      return { Val, Error{}, true };
    }

    inline static Result Failure(const Error& ErrorValue)
    {
      return { T{}, ErrorValue, false };
    }

    inline explicit operator bool() const
    {
      return this->HasValue;
    }

    inline bool operator!() const
    {
      return !this->HasValue;
    }

    // Value access — only valid if (result)
    inline const T& operator*() const
    {
      return this->Value;
    }

    inline const T* operator->() const
    {
      return &this->Value;
    }

    inline const T& GetValue() const
    {
      return this->Value;
    }

    inline const Error& GetError() const
    {
      return this->ErrorValue;
    }

    Result(const T& Value) :
      Value(Value), HasValue(true)
    {
    }

    Result(const Error& ErrorValue) :
      ErrorValue(ErrorValue)
    {
    }

    Result(const T& Value, const Error& ErrorValue, bool HasValue) :
      Value(Value), ErrorValue(ErrorValue), HasValue(HasValue)
    {
    }
  };

  class Process;

  namespace OsVersion
  {

    // Windows (10/11) versions represented by their respective build numbers.
    // These are required for our EPROCESS offsets. There could be a more dynamic way of retrieving the offsets,
    // (e.g. directly parsing kernel pdb or maybe even pattern matching) but for now this works just fine for the intended use case.
    enum : std::uint64_t
    {
      Windows_10_1507                  = 10240,
      Windows_10_1511                  = 10586,
      Windows_10_1607                  = 14393,
      Windows_10_1703                  = 15063,
      Windows_10_1709                  = 16299,
      Windows_10_1803                  = 17134,
      Windows_10_1809                  = 17763,
      Windows_10_1903                  = 18362,
      Windows_10_1909                  = 18363,
      Windows_10_2004                  = 19041,
      Windows_10_20h2                  = 19042,
      Windows_10_21h1                  = 19043,
      Windows_10_21h2                  = 19044,
      Windows_10_22h2                  = 19045
    };

  } // namespace OsVersion

  // Internal use only (detail).
  class pmm_
  {
  protected:
    // Struct representing a page table entry (PTE)
    // Declarations: PTE
    struct PTE
    {
      ULONGLONG                        Valid : 1;
      ULONGLONG                        Write : 1;
      ULONGLONG                        Owner : 1;
      ULONGLONG                        WriteThrough : 1;
      ULONGLONG                        CacheDisable : 1;
      ULONGLONG                        Accessed : 1;
      ULONGLONG                        Dirty : 1;
      ULONGLONG                        LargePage : 1;
      ULONGLONG                        Global : 1;
      ULONGLONG                        CopyOnWrite : 1;
      ULONGLONG                        Prototype : 1;
      ULONGLONG                        Reserved0 : 1;
      ULONGLONG                        PageFrameNumber : 40;
      ULONGLONG                        SoftwareWsIndex : 11;
      ULONGLONG                        NoExecute : 1;
    };

    // Declarations: MMVAD_SHORT, MMVAD_FLAGS, MMVAD_FLAGS1

    // Applicable to:
    // - Windows 10 (1507, 1511, 1607, 1703, 1709)
    struct MMVAD_FLAGS_1507
    {
      ULONG                            Padding1 : 3;       //0x0
      ULONG                            Protection : 5;     //0x0
      ULONG                            Padding2 : 7;       //0x0
      ULONG                            PrivateMemory : 1;  //0x0
    };

    // Applicable to:
    // - Windows 10 (1803, 1809)
    struct MMVAD_FLAGS_1803
    {
      ULONG                            Padding1 : 3;       //0x0
      ULONG                            Protection : 5;     //0x0
      ULONG                            Padding2 : 6;       //0x0
      ULONG                            PrivateMemory : 1;  //0x0
    };

    // Applicable to:
    // - Windows 10 (1903, 1909, 2004, 20H2, 21H1, 21H2, 22H2)
    struct MMVAD_FLAGS_1903
    {
      ULONG                            Padding1 : 7;       //0x0
      ULONG                            Protection : 5;     //0x0
      ULONG                            Padding2 : 6;       //0x0
      ULONG                            PageSize : 2;       //0x0
      ULONG                            PrivateMemory : 1;  //0x0
    };

    // Applicable to:
    // - All versions of windows 10/11 as of 2024.
    struct MMVAD_Flags1
    {
      ULONG                            Padding1 : 31;      //0x0
      ULONG                            MemCommit : 1;      //0x0
    };

    // Applicable to:
    // - All versions of windows 10/11 as of 2024.
    struct MMVAD_SHORT
    {
      // These pointers are used to store addresses from an external program.
      // Not for internal use.
      MMVAD_SHORT*                     LeftChild;          //0x0
      MMVAD_SHORT*                     RightChild;         //0x8
      ULONGLONG                        Parent;             //0x10
      ULONG                            StartingVpn;        //0x18
      ULONG                            EndingVpn;          //0x1c
      UCHAR                            StartingVpnHigh;    //0x20
      UCHAR                            EndingVpnHigh;      //0x21
      BYTE                             Padding[8];         //0x22
      //MMVAD_FLAGS                    vad_flags;          //0x30
      //MMVAD_FLAGS1                   vad_flags1;         //0x34
    };

    struct MMVAD_SHORT_1507 : MMVAD_SHORT
    {
      MMVAD_FLAGS_1507                 VadFlags;           //0x30
      MMVAD_Flags1                     VadFlags1;          //0x34
    };

    struct MMVAD_SHORT_1803 : MMVAD_SHORT
    {
      MMVAD_FLAGS_1803                 VadFlags;           //0x30
      MMVAD_Flags1                     VadFlags1;          //0x34
    };

    struct MMVAD_SHORT_1903 : MMVAD_SHORT
    {
      MMVAD_FLAGS_1903                 VadFlags;           //0x30
      MMVAD_Flags1                     VadFlags1;          //0x34
    };

    // Declarations: EPROCESSOffsets
    struct EPROCESSOffsets
    {
      std::uint64_t                    ActiveProcessLinks  = 0x00;
      std::uint64_t                    UniqueProcessId     = 0x00;
      std::uint64_t                    ImageFileName       = 0x00;
      std::uint64_t                    SectionBaseAddress  = 0x00;
      std::uint64_t                    VadRoot             = 0x00;
      std::uint64_t                    ExitStatus          = 0x00;
    };

    // The default IA32_PAT register value defined by the Intel manual.
    // Translates to:
    // 
    //  PA[0] = 0x06 (Write Back)
    //  PA[1] = 0x04 (Write Through)
    //  PA[2] = 0x07 (Uncacheable Minus)
    //  PA[3] = 0x00 (Uncacheable)
    //  PA[4] = 0x06 (Write Back)
    //  PA[5] = 0x04 (Write Through)
    //  PA[6] = 0x07 (Uncacheable Minus)
    //  PA[7] = 0x00 (Uncacheable)
    //
    // Most systems use this value by default at reset,
    // but certain programs (hypervisors, BIOS etc.) could reconfigure the entries.
    // Because of this, it's preferable to retrieve the actual value from the register directly.
    // This can be done by calling __readmsr(IA32_PAT) or hv::read_msr(IA32_PAT),
    // however currently no code in this library implements live PAT retrieval...
    //
    static constexpr std::uint64_t     IA32_PAT_DEFAULT    = 0x0007040600070406;
    static constexpr std::uint64_t     IA32_PAT            = 0x277;

    // Declarations: IA32_PAT_Register
    struct IA32PATRegister
    {
      // The raw 64-bit PAT register value
      std::uint64_t                    Flags               = IA32_PAT_DEFAULT;

      std::uint8_t                     GetEntry(std::uint8_t EffectiveIndex) const;

      IA32PATRegister(std::uint64_t Flags);
      IA32PATRegister() = default;
    };

    static Result<OSVERSIONINFOEX> GetWindowsVersion();

    // Only classes extending from this class
    // can use it's internal structures
    pmm_() = default;
    friend class Process;

  }; // !class pmm_

  // Declarations: Page
  struct Page
  {
    struct Size
    {
      enum : std::size_t
      {
        Small            = 0x1000,     // 4kb
        Large            = 0x200000,   // 2mb
        Huge             = 0x40000000  // 1gb
      };
    };

    struct Protection
    {
      // reactos.org/wiki/Techwiki:Ntoskrnl/MMVAD
      // MMVAD_FLAGS protection values:
      enum : std::uint8_t
      {
        NoAccess         = 0,
        ReadOnly         = 1,
        Execute          = 2,
        ExecuteRead      = 3,
        ReadWrite        = 4,
        WriteCopy        = 5,
        ExecuteReadWrite = 6,
        ExecuteWriteCopy = 7
      };
    };

    // IA32_PAT memory types as defined by the Intel manual
    struct MemoryType
    {
      enum : std::uint8_t
      {
        Uncacheable      = 0,          // UC:  Uncacheable
        WriteCombining   = 1,          // WC:  Write Combining
        Reserved2        = 2,          // Reserved
        Reserved3        = 3,          // Reserved
        WriteThrough     = 4,          // WT:  Write Through
        WriteProtected   = 5,          // WP:  Write Protected
        WriteBack        = 6,          // WB:  Write Back (default on many systems)
        UncacheableMinus = 7           // UC-: Uncacheable Minus
      };
    };

    std::uint64_t                      Address             = 0x00;
    std::uint64_t                      PhysicalAddress     = 0x00;

    std::uint64_t                      BaseAddress         = 0x00;
    std::uint64_t                      PhysicalBaseAddress = 0x00;

    std::size_t                        Size                = 0x00;
    std::uint8_t                       Protection          = 0x00;
    std::uint8_t                       MemoryType          = 0x00;
    bool                               Committed           = false;
  }; // !struct Page

  // Declarations: Region
  struct Region
  {
    std::uint64_t                      AddressBegin        = 0x00;
    std::uint64_t                      AddressEnd          = 0x00;
    std::uint64_t                      Protection          = 0x00;
    bool                               PrivateMemory       = false;
    bool                               InitiallyCommitted  = false;
  };  // !struct Region

  namespace PE
  {
    // Declarations: Header
    struct Header
    {
      std::string                      Name;
      std::uint64_t                    Offset              = 0x00;
      std::uint64_t                    Size                = 0x00;
    }; // !struct Header

    // Declarations: Section
    struct Section
    {
      std::string                      Name;
      std::uint64_t                    Offset              = 0x00;
      std::uint64_t                    Size                = 0x00;

      const std::string&               GetName() const;
      std::uint64_t                    GetOffset() const;
      std::size_t                      GetSize() const;

                                       Section() = default;
                                       Section(const std::string& Name, std::uint64_t Offset, std::uint64_t Size);
    }; // !struct Section

    // Declarations: Section
    class Sections
    {
      std::vector<Section>             SectionsList;
    public:
      const std::vector<Section>&      GetAll() const;
      Result<Section>                  GetSection(const std::string& Name) const;

                                       Sections() = default;
                                       Sections(const std::vector<Section>& SectionsParam);
    }; // !struct Sections
  } // !namespace PE

  // Declarations: Import_Address_Table
  class ImportAddressTable
  {
  public:
    struct Function
    {
      std::string                      Name;
      std::uint64_t                    Address             = 0x00;
      std::uint64_t                    AddressOfAddress    = 0x00;
    };

  private:
    mutable std::unordered_map<std::string, Function> Functions;

  public:
    std::size_t                        GetSize() const;
    void                               AddFunction(const Function& Function);
    Function                           GetFunction(const std::string& Name) const;

    ImportAddressTable() = default;
  }; // !class ImportAddressTable

  // Declarations: Module
  struct Module
  {
    std::string                        Name;
    mutable ImportAddressTable         IAT;
  }; // !struct Module

  // Declarations: Process
  class Process : public pmm_
  {
  private:
    EPROCESSOffsets                    EprocessOffsets;
    std::uint64_t                      WindowsVersion      = 0x00;
    std::uint64_t                      EprocessAddress     = 0x00;
    std::uint64_t                      Cr3                 = 0x00;
    std::uint64_t                      BaseAddress         = 0x00;
    std::uint32_t                      ProcessId           = 0x00;
    std::uint64_t                      ExitStatus          = 0x00;

    mutable std::unordered_map<std::string, Module> ImportedModules;
    PE::Header                         PeHeader;
    PE::Sections                       PeSections;

    Result<bool>                       GetPePreliminaries(std::uint64_t* PeOffset, IMAGE_NT_HEADERS* NtHeaders) const;
    Result<bool>                       ExtractPeSections();

    // IAT and imported functions
    void                               AddModule(const Module& Module);
    void                               AddImportedFunctions(const Module& Module, IMAGE_IMPORT_DESCRIPTOR ImportDescriptor);
    void                               AddImportedModules(IMAGE_DATA_DIRECTORY DataDirectory);
    Result<bool>                       ExtractImportData();

    // EPROCESS retrieval
    Result<std::uint64_t>              GetNtosDriverBaseAddress() const;
    Result<std::uint64_t>              GetSystemEprocessAddress() const;
    Result<std::uint64_t>              GetEprocessAddressFromPid() const;
    Result<EPROCESSOffsets>            InitEprocessOffsets();

    Result<std::uint64_t>              GetExitStatus() const;
    Result<std::uint64_t>              GetSectionBaseAddress() const;

    // Internal page functions
    std::uint64_t                      GetPageShift(std::size_t Size) const;
    std::uint8_t                       GetPageProtection(const PTE* Pte) const;
    std::uint8_t                       GetPatIndex(std::size_t Size, const PTE* Pte) const;
    bool                               IsPageCommitted(const PTE* Pte) const;
    Page                               GetPageInternal(std::uint64_t VirtualAddress, std::size_t Size, const PTE* Pte) const;
    template<typename Handler>
    void                               ForEachPageInternal(std::uint64_t AddressBegin, std::uint64_t AddressEnd, Handler& handler,
                                         const std::function<bool(const Page&)>& Filter) const;

    // Memory regions from process VAD tree
    template <typename MMVAD_SHORT_T>
    void                               TraverseVadTree(std::uint64_t VadRootAddress, std::vector<Region>* MemoryRegions,
                                         const std::function<bool(const Region&)>& Filter) const;
    void                               GetRegionsInternal(std::uint64_t VadRootAddress, std::vector<Region>* MemoryRegions,
                                         const std::function<bool(const Region&)>& Filter) const;

    // Helper to read string from virtual/physical memory
    std::string                        ReadStringInternal(std::uint64_t Address, bool IsPhysical = false) const;

  public:
    // Read memory
    std::string                        ReadString(std::uint64_t Address) const;
    std::string                        ReadStringPhysical(std::uint64_t Address) const;
    std::size_t                        Read(std::uint64_t Address, void* Buffer, std::size_t Size) const;
    std::size_t                        ReadPhysical(std::uint64_t Address, void* Buffer, std::size_t Size) const;
    template<typename T> T             Read(std::uint64_t Address) const;
    template<typename T> T             ReadPhysical(std::uint64_t Address) const;

    // Write memory
    std::size_t                        Write(std::uint64_t Address, void* Buffer, std::size_t Size) const;
    template<typename T>
    std::size_t                        Write(std::uint64_t Address, const T& Value) const;
    std::size_t                        WritePhysical(std::uint64_t Address, void* Buffer, std::size_t Size) const;
    template<typename T>
    std::size_t                        WritePhysical(std::uint64_t Address, const T& Value) const;

    std::uint64_t                      GetOsVersion() const;
    std::uint32_t                      GetProcessId() const;
    Result<bool>                       IsRunning() const;
    std::uint64_t                      GetBaseAddress() const;
    const PE::Header&                  GetPeHeader() const;
    const PE::Sections&                GetPeSections() const;
    const Module&                      GetModule(const std::string& Name) const;
    const auto&                        GetModules() const;

    // Page and region enumeration
    Result<Page>                       GetPage(std::uint64_t Address) const;
    std::vector<Page>                  GetPages(std::uint64_t AddressBegin, std::uint64_t AddressEnd, const std::function<bool(const Page&)>& Filter = nullptr) const;
    std::vector<Page>                  GetPages(const Region& RegionObj, const std::function<bool(const Page&)>& Filter = nullptr) const;
    void                               ForEachPage(std::uint64_t AddressBegin, std::uint64_t AddressEnd, const std::function<bool(const Page&)>& Callback) const;
    void                               ForEachPage(const Region& RegionObj, const std::function<bool(const Page&)>& Callback) const;
    Result<std::vector<Region>>        GetRegions(const std::function<bool(const Region&)>& Filter = nullptr) const;

    // Initialization
    Result<std::uint32_t>              Attach(std::uint32_t ProcessId = 0x00);

    Result<std::uint32_t>              GetProcessIdByWindow(HWND WindowHandle);
    Result<std::uint32_t>              AttachByWindowName(const std::string& WindowClass = "", const std::string& WindowTitle = "");
    Result<std::uint32_t>              AttachByWindow(HWND WindowHandle);

    void                               WaitClose();

                                       Process(std::uint32_t ProcessId);
                                       Process() = default;
  }; // !class Process

  // Helper for choosing correct EPROCESS offsets
  inline Result<OSVERSIONINFOEX> pmm_::GetWindowsVersion()
  {
    OSVERSIONINFOEX OsVersion{};
    OsVersion.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

    HINSTANCE NtdllDll = LoadLibrary(TEXT("ntdll.dll"));

    if (NtdllDll == NULL)
    {
      return Error::Error;
    }

    auto RtlGetVersion = reinterpret_cast<NTSTATUS(WINAPI*)(PRTL_OSVERSIONINFOW)>(
      GetProcAddress(NtdllDll, "RtlGetVersion"));

    if (RtlGetVersion == NULL)
    {
      FreeLibrary(NtdllDll);
      return Error::Error;
    }

    RtlGetVersion(reinterpret_cast<PRTL_OSVERSIONINFOW>(&OsVersion));
    FreeLibrary(NtdllDll);

    return OsVersion;
  }

  // Definitions: IA32PATRegister
  // Returns the 8-bit memory type for the PAT entry at the given effective index (0-7).
  inline std::uint8_t pmm_::IA32PATRegister::GetEntry(std::uint8_t EffectiveIndex) const
  {
    return (this->Flags >> (EffectiveIndex * 8)) & 0xFF;
  }

  inline pmm_::IA32PATRegister::IA32PATRegister(std::uint64_t Flags)
    : Flags(Flags)
  {
  }

  inline PE::Section::Section(const std::string& Name, std::uint64_t Offset, std::uint64_t Size)
    : Name(Name), Offset(Offset), Size(Size)
  {
  }

  inline const std::string& PE::Section::GetName() const
  {
    return this->Name;
  }

  inline std::uint64_t PE::Section::GetOffset() const
  {
    return this->Offset;
  }

  inline std::size_t PE::Section::GetSize() const
  {
    return static_cast<std::size_t>(this->Size);
  }

  inline PE::Sections::Sections(const std::vector<PE::Section>& SectionsParam)
    : SectionsList(SectionsParam)
  {
  }

  inline const std::vector<PE::Section>& PE::Sections::GetAll() const
  {
    return this->SectionsList;
  }

  inline Result<PE::Section> PE::Sections::GetSection(const std::string& Name) const
  {
    for (const auto& SectionItem : this->SectionsList)
    {
      if (SectionItem.GetName() == Name)
      {
        return SectionItem;
      }
    }

    return Error::Error;
  }

  // Definitions: ImportAddressTable
  inline std::size_t ImportAddressTable::GetSize() const
  {
    return this->Functions.size();
  }

  inline void ImportAddressTable::AddFunction(const Function& Function)
  {
    this->Functions[Function.Name] = Function;
  }

  inline ImportAddressTable::Function ImportAddressTable::GetFunction(const std::string& Name) const
  {
    return this->Functions[Name];
  }

  inline Result<bool> Process::GetPePreliminaries(std::uint64_t* PeOffset, IMAGE_NT_HEADERS* NtHeaders) const
  {
    // Read DOS header from the base address of the process
    IMAGE_DOS_HEADER DosHeader = this->Read<IMAGE_DOS_HEADER>(this->BaseAddress);

    if (DosHeader.e_magic != IMAGE_DOS_SIGNATURE)
    {
      return Error::Error;
    }

    // Compute the PE header offset and verify the signature
    *PeOffset = this->BaseAddress + DosHeader.e_lfanew;
    *NtHeaders = this->Read<IMAGE_NT_HEADERS>(*PeOffset);

    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
      return Error::Error;
    }

    return true;
  }

  // New helper function to extract PE header and section info from the process memory.
  inline Result<bool> Process::ExtractPeSections()
  {
    std::uint64_t PeOffset = 0;
    IMAGE_NT_HEADERS NtHeaders;

    if (const auto& Out = GetPePreliminaries(&PeOffset, &NtHeaders); !Out)
    {
      //return result.get_error();
      return Out;
    }

    // Read the IMAGE_FILE_HEADER and determine where the section table begins
    IMAGE_FILE_HEADER FileHeader = this->Read<IMAGE_FILE_HEADER>(PeOffset + sizeof(std::uint32_t));
    std::uint64_t SectionTableOffset = PeOffset + sizeof(std::uint32_t) + sizeof(IMAGE_FILE_HEADER) + FileHeader.SizeOfOptionalHeader;
    std::uint64_t ExpectedSectionTableSize = FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);

    // Store a pseudo-section for the header
    this->PeHeader = PE::Header{ ".header", 0, SectionTableOffset + ExpectedSectionTableSize };

    // Parse each section header
    std::vector<PE::Section> Sections;

    for (int i = 0; i < FileHeader.NumberOfSections; ++i)
    {
      std::uint64_t SectionOffset = SectionTableOffset + i * sizeof(IMAGE_SECTION_HEADER);
      IMAGE_SECTION_HEADER SectionHeader = this->Read<IMAGE_SECTION_HEADER>(SectionOffset);

      std::string Name(reinterpret_cast<char*>(SectionHeader.Name), 8);
      Name = Name.c_str(); // Remove trailing nulls

      if (Name.empty())
      {
        Name = ".section" + std::to_string(i + 1);
      }

      // Use the VirtualAddress and VirtualSize from the section header
      Sections.push_back(PE::Section(Name, SectionHeader.VirtualAddress, SectionHeader.Misc.VirtualSize));
    }

    // Sort sections in ascending order based on the offset (VirtualAddress)
    std::sort(Sections.begin(), Sections.end(), [](const PE::Section& a, const PE::Section& b)
    {
      return a.Offset < b.Offset;
    });

    this->PeSections = PE::Sections(Sections);
    return true;
  }

  // Definitions: Process
  inline void Process::AddModule(const Module& Module)
  {
    this->ImportedModules[Module.Name] = Module;
  }

  inline void Process::AddImportedFunctions(const Module& Module, IMAGE_IMPORT_DESCRIPTOR ImportDescriptor)
  {
    // Iterate over all functions imported by module
    for (int next = 0;; next += sizeof(IMAGE_THUNK_DATA))
    {
      std::uint64_t AddressOfOriginalFirstThunk = this->BaseAddress + ImportDescriptor.OriginalFirstThunk + next;
      std::uint64_t AddressOfFirstThunk = this->BaseAddress + ImportDescriptor.FirstThunk + next;

      IMAGE_THUNK_DATA OriginalFirstThunk = this->Read<IMAGE_THUNK_DATA>(AddressOfOriginalFirstThunk);
      IMAGE_THUNK_DATA FirstThunk = this->Read<IMAGE_THUNK_DATA>(AddressOfFirstThunk);

      // Reached end of function imports for this module, go to next module
      if (OriginalFirstThunk.u1.Function == 0)
      {
        break;
      }

      // We only care about named imports so skip ordinal imports
      if (OriginalFirstThunk.u1.Ordinal & IMAGE_ORDINAL_FLAG)
      {
        continue;
      }

      ImportAddressTable::Function FunctionObj;
      FunctionObj.Name = this->ReadString(this->BaseAddress + OriginalFirstThunk.u1.AddressOfData + offsetof(struct _IMAGE_IMPORT_BY_NAME, Name));
      FunctionObj.Address = FirstThunk.u1.Function;
      FunctionObj.AddressOfAddress = AddressOfFirstThunk; // + offsetof(struct _IMAGE_THUNK_DATA64, u1.Function);

      Module.IAT.AddFunction(FunctionObj);
    }
  }

  inline void Process::AddImportedModules(IMAGE_DATA_DIRECTORY DataDirectory)
  {
    // Iterate over all imported modules
    for (int next = 0;; next += sizeof(IMAGE_IMPORT_DESCRIPTOR))
    {
      IMAGE_IMPORT_DESCRIPTOR ImportDescriptor = this->Read<IMAGE_IMPORT_DESCRIPTOR>(this->BaseAddress + DataDirectory.VirtualAddress + next);

      if (ImportDescriptor.Characteristics == 0)
      {
        break;
      }

      // Didnt find ILT or IAT so skip to next module
      if (!ImportDescriptor.OriginalFirstThunk || !ImportDescriptor.FirstThunk)
      {
        continue;
      }

      // Save module (name)
      Module ModuleObj;
      ModuleObj.Name = this->ReadString(this->BaseAddress + ImportDescriptor.Name);

      this->AddImportedFunctions(ModuleObj, ImportDescriptor);
      this->AddModule(ModuleObj);
    }
  }

  inline Result<bool> Process::ExtractImportData()
  {
    std::uint64_t PeOffset = 0;
    IMAGE_NT_HEADERS NtHeaders;

    if (const auto& Out = GetPePreliminaries(&PeOffset, &NtHeaders); !Out)
    {
      //return result.get_error();
      return Out;
    }

    // Get the optional header from NT Headers
    IMAGE_OPTIONAL_HEADER OptionalHeader = NtHeaders.OptionalHeader;

    if (OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
    {
      return Error::Error;
    }

    IMAGE_DATA_DIRECTORY DataDirectory = OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    this->AddImportedModules(DataDirectory);

    return true; // Assume success
  }

  inline Result<std::uint64_t> Process::GetNtosDriverBaseAddress() const
  {
    std::uint64_t DriverBaseAddressList[1024];
    DWORD NumBytes = 0;

    if (EnumDeviceDrivers(reinterpret_cast<LPVOID*>(DriverBaseAddressList),
      sizeof(DriverBaseAddressList), &NumBytes))
    {
      return DriverBaseAddressList[0];
    }

    return Error::Error;
  }

  inline Result<std::uint64_t> Process::GetSystemEprocessAddress() const
  {
    HMODULE NtosBaseAddress = LoadLibrary(TEXT("ntoskrnl.exe"));

    if (!NtosBaseAddress)
    {
      return Error::Error;
    }

    std::uint64_t PsInitialSystemProcessAddress = (std::uint64_t)GetProcAddress(NtosBaseAddress, "PsInitialSystemProcess");

    if (!PsInitialSystemProcessAddress)
    {
      return Error::Error;
    }

    std::uint64_t NtosDriverBaseAddress = 0;

    if (const auto& Out = this->GetNtosDriverBaseAddress(); !Out)
    {
      return Error::Error;
    }
    else
    {
      NtosDriverBaseAddress = *Out;
    }

    std::uint64_t SystemEprocessAddress =
      this->Read<std::uint64_t>((PsInitialSystemProcessAddress - (std::uint64_t)NtosBaseAddress) + NtosDriverBaseAddress);

    if (!SystemEprocessAddress)
    {
      return Error::Error;
    }

    FreeLibrary(NtosBaseAddress);
    return SystemEprocessAddress;
  }

  inline Result<std::uint64_t> Process::GetEprocessAddressFromPid() const
  {
    std::uint64_t SystemEprocessAddress = 0;

    if (const auto& Out = this->GetSystemEprocessAddress(); !Out)
    {
      return Error::Error;
    }
    else
    {
      SystemEprocessAddress = *Out;
    }

    std::uint64_t EprocessAddress = SystemEprocessAddress; // We begin iterating from system eprocess until we find our eprocess
    LIST_ENTRY ActiveProcessLinks = this->Read<LIST_ENTRY>(SystemEprocessAddress + this->EprocessOffsets.ActiveProcessLinks);

    while (true)
    {
      EprocessAddress = (std::uint64_t)ActiveProcessLinks.Flink - this->EprocessOffsets.ActiveProcessLinks;
      std::uint32_t TempProcessId = this->Read<std::uint32_t>(EprocessAddress + this->EprocessOffsets.UniqueProcessId);

      // Found what we're looking for, return
      if (this->ProcessId == TempProcessId)
      {
        return EprocessAddress;
      }

      ActiveProcessLinks = this->Read<LIST_ENTRY>(EprocessAddress + this->EprocessOffsets.ActiveProcessLinks);

      if (EprocessAddress == (std::uint64_t)ActiveProcessLinks.Flink - this->EprocessOffsets.ActiveProcessLinks)
      {
        break;
      }
    }

    // Process not found in ActiveProcessLinks
    return Error::Error;
  }

  inline Result<pmm_::EPROCESSOffsets> Process::InitEprocessOffsets()
  {
    EPROCESSOffsets& Offsets = this->EprocessOffsets;

    switch (this->WindowsVersion)
    {
      case OsVersion::Windows_10_22h2:
      case OsVersion::Windows_10_21h2:
      case OsVersion::Windows_10_21h1:
      case OsVersion::Windows_10_20h2:
      case OsVersion::Windows_10_2004:
      {
        Offsets.UniqueProcessId =      0x440;
        Offsets.ActiveProcessLinks =   0x448;
        Offsets.SectionBaseAddress =   0x520;
        Offsets.ImageFileName =        0x5a8;
        Offsets.ExitStatus =           0x7d4;
        Offsets.VadRoot =              0x7d8;
        break;
      }
      case OsVersion::Windows_10_1909:
      case OsVersion::Windows_10_1903:
      {
        Offsets.UniqueProcessId =      0x2e8;
        Offsets.ActiveProcessLinks =   0x2f0;
        Offsets.SectionBaseAddress =   0x3c8;
        Offsets.ImageFileName =        0x450;
        Offsets.ExitStatus =           0x654;
        Offsets.VadRoot =              0x658;
        break;
      }
      case OsVersion::Windows_10_1809:
      case OsVersion::Windows_10_1803:
      case OsVersion::Windows_10_1709:
      case OsVersion::Windows_10_1703:
      {
        Offsets.UniqueProcessId =      0x2e0;
        Offsets.ActiveProcessLinks =   0x2e8;
        Offsets.SectionBaseAddress =   0x3c0;
        Offsets.ImageFileName =        0x450;
        Offsets.ExitStatus =           0x624;
        Offsets.VadRoot =              0x628;
        break;
      }
      case OsVersion::Windows_10_1607:
      {
        Offsets.UniqueProcessId =      0x2e8;
        Offsets.ActiveProcessLinks =   0x2f0;
        Offsets.SectionBaseAddress =   0x3c0;
        Offsets.ImageFileName =        0x450;
        Offsets.ExitStatus =           0x61c;
        Offsets.VadRoot =              0x620;
        break;
      }
      case OsVersion::Windows_10_1511:
      {
        Offsets.UniqueProcessId =      0x2e8;
        Offsets.ActiveProcessLinks =   0x2f0;
        Offsets.SectionBaseAddress =   0x3c0;
        Offsets.ImageFileName =        0x450;
        Offsets.ExitStatus =           0x60c;
        Offsets.VadRoot =              0x610;
        break;
      }
      case OsVersion::Windows_10_1507:
      {
        Offsets.UniqueProcessId =      0x2e8;
        Offsets.ActiveProcessLinks =   0x2f0;
        Offsets.SectionBaseAddress =   0x3c0;
        Offsets.ImageFileName =        0x448;
        Offsets.ExitStatus =           0x604;
        Offsets.VadRoot =              0x608;
        break;
      }
      default: return Error::Error; // Unsupported Windows version
    }

    return Offsets;
  }

  inline Result<std::uint64_t> Process::GetExitStatus() const
  {
    auto ExitStatusValue =
      this->Read<LONG>(this->EprocessAddress + EprocessOffsets.ExitStatus);

    if (!ExitStatusValue)
    {
      return Error::Error;
    }

    return ExitStatusValue;
  }

  inline Result<std::uint64_t> Process::GetSectionBaseAddress() const
  {
    auto SectionBaseAddressValue =
      this->Read<std::uint64_t>(this->EprocessAddress + EprocessOffsets.SectionBaseAddress);

    if (!SectionBaseAddressValue)
    {
      return Error::Error;
    }

    return SectionBaseAddressValue;
  }

  inline std::uint64_t Process::GetPageShift(std::size_t Size) const
  {
    switch (Size)
    {
      case Page::Size::Huge: return 30;
      case Page::Size::Large: return 21;
      case Page::Size::Small: return 12;
    }

    return 12; // Default
  }

  inline std::uint8_t Process::GetPageProtection(const PTE* Pte) const
  {
    if (!Pte->Valid)
    {
      return Page::Protection::NoAccess;
    }

    if (Pte->NoExecute)
    {
      return Pte->Write ?
        (Pte->Owner ? Page::Protection::ReadWrite : Page::Protection::WriteCopy) :
        (Pte->Owner ? Page::Protection::ReadOnly : Page::Protection::NoAccess);
    }

    return Pte->Write ?
      (Pte->Owner ? Page::Protection::ExecuteReadWrite : Page::Protection::ExecuteWriteCopy) :
      (Pte->Owner ? Page::Protection::ExecuteRead : Page::Protection::Execute);
  }

  inline std::uint8_t Process::GetPatIndex(std::size_t Size, const PTE* Pte) const
  {
    // For 4KB pages, the PAT bit is stored in the same field as "large_page" or at bit 7 of the entry.
    // For 2MB or 1GB pages, the PAT bit is stored at bit 12 of the entry.

    // Compute the effective PAT index:
    // index = (cache_disable << 2) | (write_through << 1) | (pat_bit)

    std::uint64_t Raw = *(reinterpret_cast<const std::uint64_t*>(Pte));
    std::uint8_t PatBit = 0;

    if (Size == Page::Size::Small)
    {
      PatBit = Pte->LargePage ? 1 : 0;
      // pat_bit = (raw >> 7) & 1
    }
    else // 2mb and 1gb pages
    {
      PatBit = (Raw >> 12) & 1;
    }

    std::uint8_t PatIndex =
      ((Pte->CacheDisable ? 1 : 0) << 2) |
      ((Pte->WriteThrough ? 1 : 0) << 1) |
      PatBit;

    return PatIndex;
  }

  inline bool Process::IsPageCommitted(const PTE* Pte) const
  {
    return Pte->Valid || Pte->Prototype;
  }

  inline Page Process::GetPageInternal(std::uint64_t VirtualAddress, std::size_t Size, const PTE* Pte) const
  {
    Page PageObj;
    IA32PATRegister Pat;

    std::uint64_t PageShift = this->GetPageShift(Size);
    std::uint8_t MemoryTypeIndex = this->GetPatIndex(Size, Pte);

    PageObj.PhysicalBaseAddress = (Pte->PageFrameNumber << PageShift);
    PageObj.PhysicalAddress = PageObj.PhysicalBaseAddress + (VirtualAddress & (Size - 1));
    PageObj.BaseAddress = VirtualAddress & ~(Size - 1);
    PageObj.Address = VirtualAddress;
    PageObj.Size = Size;
    PageObj.Protection = this->GetPageProtection(Pte);
    PageObj.MemoryType = Pat.GetEntry(MemoryTypeIndex);
    PageObj.Committed = this->IsPageCommitted(Pte);

    return PageObj;
  }

  template<typename Handler>
  inline void Process::ForEachPageInternal(std::uint64_t AddressBegin, std::uint64_t AddressEnd, Handler& handler,
    const std::function<bool(const Page&)>& Filter) const
  {
    std::uint64_t CurrentAddress = AddressBegin;

    while (CurrentAddress < AddressEnd)
    {
      Page PageObj;

      if (const auto& Out = this->GetPage(CurrentAddress); !Out)
      {
        // Error, skip to next address range.
        CurrentAddress += 1ULL << 12;
        continue;
      }
      else
      {
        PageObj = *Out;
      }

      // If the page is not present or doesn't pass through the filter,
      // move to the next address range. First check might be pointless.
      if (PageObj.Size == 0 || (Filter && !Filter(PageObj)))
      {
        CurrentAddress += 1ULL << 12;
        continue;
      }

      // If handler is callable (like a callback)
      if constexpr (std::is_invocable_v<Handler, const Page&>)
      {
        // If the callable returns bool, break on false.
        if constexpr (std::is_same_v<std::invoke_result_t<Handler, const Page&>, bool>)
        {
          if (!handler(PageObj))
          {
            break;
          }
        }
        else
        {
          // Otherwise, just call it.
          handler(PageObj);
        }
      }
      // If handler is a std::vector<Page>
      else if constexpr (std::is_same_v<std::decay_t<Handler>, std::vector<Page>>)
      {
        handler.push_back(PageObj);
      }

      // Increment to the next page based on the page's size.
      CurrentAddress = PageObj.BaseAddress + PageObj.Size;
    }
  }

  template <typename MMVAD_SHORT_T>
  inline void Process::TraverseVadTree(std::uint64_t VadRootAddress, std::vector<Region>* MemoryRegions, const std::function<bool(const Region&)>& Filter) const
  {
    auto Node = this->Read<MMVAD_SHORT_T>(VadRootAddress);
    this->GetRegionsInternal(reinterpret_cast<std::uint64_t>(Node.LeftChild), MemoryRegions, Filter);

    // In-order traversal
    Region RegionObj;
    RegionObj.AddressBegin = (static_cast<std::uint64_t>(Node.StartingVpn) << 12) | (static_cast<std::uint64_t>(Node.StartingVpnHigh) << 44);
    RegionObj.AddressEnd = ((static_cast<std::uint64_t>(Node.EndingVpn + 1) << 12) | (static_cast<std::uint64_t>(Node.EndingVpnHigh) << 44)) - 1;
    RegionObj.Protection = Node.VadFlags.Protection;
    RegionObj.PrivateMemory = Node.VadFlags.PrivateMemory;
    RegionObj.InitiallyCommitted = Node.VadFlags1.MemCommit;

    if (!Filter || Filter(RegionObj))
    {
      MemoryRegions->push_back(RegionObj);
    }

    this->GetRegionsInternal(reinterpret_cast<std::uint64_t>(Node.RightChild), MemoryRegions, Filter);
  }

  inline void Process::GetRegionsInternal(std::uint64_t VadRootAddress, std::vector<Region>* MemoryRegions, const std::function<bool(const Region&)>& Filter) const
  {
    if (!VadRootAddress)
    {
      return;
    }

    if (this->WindowsVersion >= OsVersion::Windows_10_1903 && this->WindowsVersion <= OsVersion::Windows_10_22h2)
    {
      this->TraverseVadTree<MMVAD_SHORT_1903>(VadRootAddress, MemoryRegions, Filter);
    }

    else if (this->WindowsVersion >= OsVersion::Windows_10_1803 && this->WindowsVersion <= OsVersion::Windows_10_1809)
    {
      this->TraverseVadTree<MMVAD_SHORT_1803>(VadRootAddress, MemoryRegions, Filter);
    }

    else if (this->WindowsVersion >= OsVersion::Windows_10_1507 && this->WindowsVersion <= OsVersion::Windows_10_1709)
    {
      this->TraverseVadTree<MMVAD_SHORT_1507>(VadRootAddress, MemoryRegions, Filter);
    }
  }

  inline std::string Process::ReadStringInternal(std::uint64_t Address, bool IsPhysical) const
  {
    std::string Buffer;

    for (int i = 0;; i++)
    {
      char Character;

      if (IsPhysical)
      {
        this->ReadPhysical(Address + i, &Character, sizeof(char));
      }
      else
      {
        this->Read(Address + i, &Character, sizeof(char));
      }

      if (Character == '\0') // null-terminator, end of string
      {
        return Buffer;
      }

      Buffer.push_back(Character);
    }

    return Buffer;
  }

  inline std::string Process::ReadString(std::uint64_t Address) const
  {
    return this->ReadStringInternal(Address);
  }

  inline std::string Process::ReadStringPhysical(std::uint64_t Address) const
  {
    return this->ReadStringInternal(Address, true);
  }

  inline std::size_t Process::Read(std::uint64_t Address, void* Buffer, std::size_t Size) const
  {
    return hv::read_virt_mem(this->Cr3, Buffer, reinterpret_cast<void*>(Address), Size);
  }

  template<typename T>
  inline T Process::Read(std::uint64_t Address) const
  {
    T Buffer{};
    this->Read(Address, &Buffer, sizeof(T));
    return Buffer;
  }

  inline std::size_t Process::ReadPhysical(std::uint64_t Address, void* Buffer, std::size_t Size) const
  {
    return hv::read_phys_mem(Buffer, Address, Size);
  }

  template<typename T>
  inline T Process::ReadPhysical(std::uint64_t Address) const
  {
    T Buffer{};
    this->ReadPhysical(Address, &Buffer, sizeof(T));
    return Buffer;
  }

  inline std::size_t Process::Write(std::uint64_t Address, void* Buffer, std::size_t Size) const
  {
    return hv::write_virt_mem(this->Cr3, reinterpret_cast<void*>(Address), Buffer, Size);
  }

  template<typename T>
  inline std::size_t Process::Write(std::uint64_t Address, const T& Value) const
  {
    return this->Write(Address, &Value, sizeof(T));
  }

  inline std::size_t Process::WritePhysical(std::uint64_t Address, void* Buffer, std::size_t Size) const
  {
    return hv::write_phys_mem(Address, Buffer, Size);
  }

  template<typename T>
  inline std::size_t Process::WritePhysical(std::uint64_t Address, const T& Value) const
  {
    return this->WritePhysical(Address, &Value, sizeof(T));
  }

  inline std::uint64_t Process::GetOsVersion() const
  {
    return this->WindowsVersion;
  }

  inline std::uint32_t Process::GetProcessId() const
  {
    return this->ProcessId;
  }

  inline Result<bool> Process::IsRunning() const
  {
    if (const auto& Out = this->GetExitStatus(); !Out)
    {
      return Out.GetError();
    }
    else
    {
      return (this->ExitStatus == *Out);
    }
  }

  inline std::uint64_t Process::GetBaseAddress() const
  {
    return this->BaseAddress;
  }

  inline const PE::Header& Process::GetPeHeader() const
  {
    return this->PeHeader;
  }

  inline const PE::Sections& Process::GetPeSections() const
  {
    return this->PeSections;
  }

  inline const Module& Process::GetModule(const std::string& Name) const
  {
    return this->ImportedModules[Name];
  }

  inline const auto& Process::GetModules() const
  {
    return this->ImportedModules;
  }

  inline Result<Page> Process::GetPage(std::uint64_t Address) const
  {
    Page PageObj;
    std::uint64_t VirtualAddress = Address;

    std::uint64_t PfnShift = 12;
    std::uint64_t IndexMask = 0x1FF;

    std::uint64_t PtIndex = (VirtualAddress >> this->GetPageShift(Page::Size::Small)) & IndexMask;
    std::uint64_t PdIndex = (VirtualAddress >> this->GetPageShift(Page::Size::Large)) & IndexMask;
    std::uint64_t PdptIndex = (VirtualAddress >> this->GetPageShift(Page::Size::Huge)) & IndexMask;
    std::uint64_t Pml4Index = (VirtualAddress >> 39) & IndexMask;

    std::uint64_t Pml4EntryAddress = this->Cr3 + Pml4Index * sizeof(PTE);
    PTE Pml4Entry = this->ReadPhysical<PTE>(Pml4EntryAddress);

    // Not present
    if (!Pml4Entry.Valid)
    {
      return Error::Error;
    }

    std::uint64_t PdptBase = Pml4Entry.PageFrameNumber << PfnShift;
    std::uint64_t PdptEntryAddress = PdptBase + PdptIndex * sizeof(PTE);
    PTE PdptEntry = this->ReadPhysical<PTE>(PdptEntryAddress);

    // Not present
    if (!PdptEntry.Valid)
    {
      return Error::Error;
    }

    // 1GB huge page
    if (PdptEntry.LargePage)
    {
      return this->GetPageInternal(VirtualAddress, Page::Size::Huge, &PdptEntry);
    }

    std::uint64_t PdBase = PdptEntry.PageFrameNumber << PfnShift;
    std::uint64_t PdEntryAddress = PdBase + PdIndex * sizeof(PTE);
    PTE PdEntry = this->ReadPhysical<PTE>(PdEntryAddress);

    // Not present
    if (!PdEntry.Valid)
    {
      return Error::Error;
    }

    // 2MB large page
    if (PdEntry.LargePage)
    {
      return this->GetPageInternal(VirtualAddress, Page::Size::Large, &PdEntry);
    }

    std::uint64_t PtBase = PdEntry.PageFrameNumber << PfnShift;
    std::uint64_t PtEntryAddress = PtBase + PtIndex * sizeof(PTE);
    PTE PtEntry = this->ReadPhysical<PTE>(PtEntryAddress);

    // Not present
    if (!PtEntry.Valid)
    {
      return Error::Error;
    }

    // 4KB page
    return this->GetPageInternal(VirtualAddress, Page::Size::Small, &PtEntry);
  }

  // Return false in the filter callback to filter out specific pages
  // based on the conditions defined in the filter callback.
  inline std::vector<Page> Process::GetPages(std::uint64_t AddressBegin, std::uint64_t AddressEnd, const std::function<bool(const Page&)>& Filter) const
  {
    std::vector<Page> PageList;
    this->ForEachPageInternal(AddressBegin, AddressEnd, PageList, Filter);
    return PageList;
  }

  inline std::vector<Page> Process::GetPages(const Region& RegionObj, const std::function<bool(const Page&)>& Filter) const
  {
    return this->GetPages(RegionObj.AddressBegin, RegionObj.AddressEnd, Filter);
  }

  inline void Process::ForEachPage(std::uint64_t AddressBegin, std::uint64_t AddressEnd, const std::function<bool(const Page&)>& Callback) const
  {
    // To iterate through the entire virtual address space:
    // virtual_ddress < (1ULL << 48)

    this->ForEachPageInternal(AddressBegin, AddressEnd, Callback, nullptr);
  }

  inline void Process::ForEachPage(const Region& RegionObj, const std::function<bool(const Page&)>& Callback) const
  {
    this->ForEachPageInternal(RegionObj.AddressBegin, RegionObj.AddressEnd, Callback, nullptr);
  }

  // Return false in the filter callback to filter out specific regions
  // based on the conditions defined in the filter callback.
  inline Result<std::vector<Region>> Process::GetRegions(const std::function<bool(const Region&)>& Filter) const
  {
    std::vector<Region> MemoryRegions;
    std::uint64_t VadRootAddress = this->Read<std::uint64_t>(this->EprocessAddress + this->EprocessOffsets.VadRoot);

    if (!VadRootAddress)
    {
      return Error::Error;
    }

    this->GetRegionsInternal(VadRootAddress, &MemoryRegions, Filter);

    // Sort in ascending order from lowest virtual address first
    std::sort(MemoryRegions.begin(), MemoryRegions.end(), [](const auto& A, const auto& B)
    {
      return A.AddressBegin < B.AddressBegin;
    });

    return MemoryRegions;
  }

  inline Result<std::uint32_t> Process::Attach(std::uint32_t ProcessId)
  {
    if (!hv::is_hv_running())
    {
      return Error::Error; // Hypervisor not running
    }

    this->ProcessId = ProcessId;

    // Save windows version, we need it cached because multiple functions will use it.
    if (const auto& Out = GetWindowsVersion(); !Out)
    {
      return Out.GetError();
    }
    else
    {
      this->WindowsVersion = Out->dwBuildNumber;
    }

    if (const auto& Out = this->InitEprocessOffsets(); !Out)
    {
      return Out.GetError();
    }

    if (const auto& Out = this->GetEprocessAddressFromPid(); !Out)
    {
      return Out.GetError();
    }
    else
    {
      this->EprocessAddress = *Out;
    }

    if (!(this->Cr3 = hv::query_process_cr3(this->ProcessId)))
    {
      return Error::Error;
    }

    if (const auto& Out = this->GetSectionBaseAddress(); !Out)
    {
      return Out.GetError();
    }
    else
    {
      this->BaseAddress = *Out;
    }

    // Set exit status of program while its running
    // so we can determine when the program exits by comparing the two exit statuses in a loop
    // there may be a better way of doing this...
    if (const auto& Out = this->GetExitStatus(); !Out)
    {
      return Out.GetError();
    }
    else
    {
      this->ExitStatus = *Out;
    }

    if (const auto& Out = this->ExtractPeSections(); !Out)
    {
      return Out.GetError();
    }

    // Grab imported module names and function addresses from Import_Address_Table tables
    if (const auto& Out = this->ExtractImportData(); !Out)
    {
      return Out.GetError();
    }

    // Initialization went well, attaching success!
    return ProcessId;
  }

  inline Result<std::uint32_t> Process::GetProcessIdByWindow(HWND WindowHandle)
  {
    std::uint32_t ProcessId = 0;
    std::uint64_t ThreadProcessId = GetWindowThreadProcessId(WindowHandle, (DWORD*)(&ProcessId));

    if (!ThreadProcessId)
    {
      return Error::Error;
    }

    if (!ProcessId)
    {
      return Error::Error;
    }

    return ProcessId;
  }

  // Window title must be unique
  inline Result<std::uint32_t> Process::AttachByWindowName(const std::string& WindowClass, const std::string& WindowTitle)
  {
    if (WindowClass.empty() && WindowTitle.empty())
    {
      return Error::Error;
    }

    LPCSTR FindWindowClass = WindowClass.empty() ? nullptr : WindowClass.data();
    LPCSTR FindWindowTitle = WindowTitle.empty() ? nullptr : WindowTitle.data();
    HWND WindowHandle = nullptr;

    // Wait for programs window class to match, store handle when found
    while (!(WindowHandle = FindWindowA(FindWindowClass, FindWindowTitle)))
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(128));
    }

    std::uint32_t ProcessId = 0;

    if (const auto& Out = this->GetProcessIdByWindow(WindowHandle); !Out)
    {
      return Out.GetError();
    }
    else
    {
      ProcessId = *Out;
    }

    return this->Attach(ProcessId);
  }

  inline Result<std::uint32_t> Process::AttachByWindow(HWND WindowHandle)
  {
    std::uint32_t ProcessId = 0;

    if (const auto& Out = this->GetProcessIdByWindow(WindowHandle); !Out)
    {
      return Out.GetError();
    }
    else
    {
      ProcessId = *Out;
    }

    return this->Attach(ProcessId);
  }

  // Interrupts current thread to wait until process has closed
  inline void Process::WaitClose()
  {
    // Wait for process to close before cleaning up and exiting
    while (this->IsRunning())
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(128));
    }
  }

  inline Process::Process(std::uint32_t ProcessId)
  {
    this->Attach(ProcessId);
  }

} // namespace pmm

#endif // PMM_PROCESS_MEMORY_MODULE_H
