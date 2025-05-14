#include "Logger.h"
#include "OffsetFinder.h"
#include "SearchCriteria.h"
#include "AssemblyParser.h"

#include "nlohmann/json.hpp"

#include <iostream>
#include <fstream>
#include <unordered_map>
#include <string>
#include <vector>
#include <functional>
#include <optional>
#include <cstdint>
#include <cstddef>
#include <iterator>
#include <iomanip>

namespace COF
{
  bool SearchHandler::Call(OffsetFinder* Finder, TSearchRegion& Function, TSearchFor& ToFind) const
  {
    return this->Function(Finder, Function, ToFind);
  }

  std::optional<std::uint64_t> OffsetFinder::SetFunctionBase(TSearchRegion& Function)
  {
    COF_LOG("[>] Setting function base (ID: %s)", Function.RegionID.c_str());

    if (Function.Anchors.empty())
    {
      COF_LOG("[!] The function anchors (array) has not been defined!");
      return std::nullopt;
    }

    std::size_t FunctionSize = Function.RegionRange.Size + Function.RegionRange.SizeVariation;

    if (!FunctionSize)
    {
      // For now, the function size must be defined by the user.
      // TODO: If user has not set a size, scan until first end marker (RET, etc.)
      COF_LOG("[!] Function 'Size' has not been defined (ID: %s)!", Function.RegionID.c_str());
      return std::nullopt;
    }

    // Each found anchor's offset will be added to this list.
    // This list will then be used to verify that the anchors
    // actually belong to the current function address space.
    std::vector<std::uint64_t> AnchorOffsets;
    std::size_t AnchorsFound = 0;
    std::uint64_t FoundFunctionBase = 0;

    auto ResetTrackers = [&]()
    {
      AnchorsFound = 0;
      FoundFunctionBase = 0;
      AnchorOffsets.clear();
    };

    // Called when anchor is found
    auto AnchorFound = [&](std::uint64_t FunctionBase,
      std::uint64_t AnchorOffset)
    {
      ++AnchorsFound;
      FoundFunctionBase = FunctionBase;
      AnchorOffsets.push_back(AnchorOffset);
    };

    auto AllAnchorsFound = [&]()
      -> bool
    {
      if (AnchorsFound == Function.Anchors.size())
      {
        // All anchors found,
        // return indicator to break from loop.
        return true;
      }

      // Reset for next try
      ResetTrackers();
      return false;
    };

    // We must first find string offsets so we can later
    // match the instructions that reference said string offsets.
    // We keep track of the Anchors (Type: String) index
    // seo we can pull the offsets at the indexes in our second loop.
    std::unordered_map<std::size_t, std::uint64_t> StringRefOffsets;

    // First loop. Index loop, applicable only to string anchors for now.
    for (std::size_t I = 0; I < Function.Anchors.size(); ++I)
    {
      const auto& Anchor = Function.Anchors[I];

      if (Anchor.Type == SearchCriteria::AnchorType::String)
      {
        // UTF-16LE search
        auto StringMatches = this->Analyzer.FindString<
          COF::DumpAnalyzer::StringType::UTF16_LE>(Anchor.String, Anchor.Index + 1);

        if (!StringMatches)
        {
          COF_LOG("[!] No anchor (string) matches found!");
          return std::nullopt;
        }

        StringRefOffsets[I] = (*StringMatches->Value)[Anchor.Index];
      }
    }

    // Second loop. Iterates over all extracted function offsets
    // to match against the specified anchors.
    // The function whose address space contains all defined anchors
    // is the function we're looking for.

    // TODO:
    //  Currently we're parsing all CALL instructions for our list of functions,
    //  so its possible we're missing some functions.
    //  We should probably also parse the .PDATA section for functions.

    auto& FunctionBases = this->Analyzer.GetFunctions();

    for (auto It = FunctionBases.begin(); It != FunctionBases.end(); ++It)
    {
      std::uint64_t FunctionBase = *It;
      auto NextIt = std::next(It);

      for (std::size_t I = 0; I < Function.Anchors.size(); ++I)
      {
        const auto& Anchor = Function.Anchors[I];

        if (Anchor.Type == SearchCriteria::AnchorType::String)
        {
          std::uint64_t StringRef = StringRefOffsets[I];

          auto Found = this->Analyzer.FindRipRelativeReference(FunctionBase, FunctionSize, StringRef,
            [](ZydisDecodedInstruction* Instruction, ZydisDecodedOperand* Operands) -> bool
          {
            // Only allow LEA instructions through to
            // narrow down scan to string references.
            // This might need updating later...
            if (Instruction->mnemonic == ZYDIS_MNEMONIC_LEA &&
              Instruction->operand_count >= 2)
            {
              return true;
            }

            return false;
          });

          if (!Found)
          {
            break;
          }

          std::uint64_t AnchorOffset = Found->Range.Offset;
          AnchorFound(FunctionBase, AnchorOffset);

          //Function.AnchorInstructionBase = *InstructionBase->Value;
          //COF_LOG("[+] Found instruction at offset: 0x%016llX", *InstructionBase->Value);
        }
        else if (Anchor.Type == SearchCriteria::AnchorType::Pattern)
        {
          auto Found =
            this->Analyzer.FindPattern(FunctionBase, FunctionSize, Anchor.Pattern);

          if (!Found)
          {
            break;
          }

          std::uint64_t AnchorOffset = Found->Range.Offset;
          AnchorFound(FunctionBase, AnchorOffset);
        }
        else if (Anchor.Type == SearchCriteria::AnchorType::PatternSubsequence)
        {
          auto Found = this->Analyzer.FindIdaPatternSubsequence(FunctionBase, FunctionSize, Anchor.PatternSubsequence);

          if (!Found)
          {
            break;
          }

          std::uint64_t AnchorOffset = Found->Range.Offset;
          AnchorFound(FunctionBase, AnchorOffset);
        }
        else if (Anchor.Type == SearchCriteria::AnchorType::InstructionSubsequence)
        {
          std::vector<AssemblyParser::ParsedInstruction> ParsedInstructions;

          for (const auto& AsmText : Anchor.InstructionSubsequence)
          {
            auto Instruction = COF::AssemblyParser::ParseInstruction(AsmText);

            if (!Instruction)
            {
              COF_LOG("[!] Parsing instruction (%s) in subsequence failed!", AsmText.c_str());

              // Return instead of break here because
              // we have a malformed instruction that should be fixed.
              return std::nullopt;
            }

            ParsedInstructions.push_back(*Instruction);
          }

          auto Found = this->Analyzer.FindInstructionSubsequence(FunctionBase, FunctionSize, ParsedInstructions);

          if (!Found)
          {
            break;
          }

          std::uint64_t AnchorOffset = Found->Range.Offset;
          AnchorFound(FunctionBase, AnchorOffset);
        }
      }

      if (!AllAnchorsFound())
      {
        continue;
      }

      std::size_t VerifiedAnchors = 0;

      for (const auto& AnchorOffset : AnchorOffsets)
      {
        if (NextIt != FunctionBases.end())
        {
          std::uint64_t NextFunctionBase = *NextIt;

          if (AnchorOffset <= FunctionBase || AnchorOffset >= NextFunctionBase)
          {
            break;
          }

          COF_LOG("[?] Verified that anchor (0x%X) is within function boundaries: [Begin: 0x%X, End: 0x%X]",
            AnchorOffset, FunctionBase, FunctionBase + FunctionSize);

          ++VerifiedAnchors;
        }
      }

      if (VerifiedAnchors == AnchorOffsets.size())
      {
        // Anchor boundaries verified, finally exit loop
        break;
      }

      // Anchor out of function boundaries,
      // reset and retry with next FunctionBase.
      ResetTrackers();
    }

    if (FoundFunctionBase)
    {
      // We got correct function base, save it and return
      COF_LOG("[+] Function base has been set: 0x%X", FoundFunctionBase);
      return (Function.RegionRange.Offset = FoundFunctionBase);
    }

    COF_LOG("[!] Failed to set function base!");
    return std::nullopt;
  }

  // Actually this only saves the .text section,
  // since it's currently the only section we need...
  bool OffsetFinder::SavePESections()
  {
    auto Sections = this->Analyzer.GetPeSections();

    if (!Sections)
    {
      COF_LOG("[!] Failed to fetch PE sections!");
      return false;
    }

    auto TextSection = Sections->GetSection(".text");

    if (!TextSection)
    {
      COF_LOG("[!] Text section missing or unreadable!");
      return false;
    }

    this->Sections.Text = *TextSection;
    return true; // Saving sections success!
  }

  const COF::MemoryDumper& OffsetFinder::GetDumper() const
  {
    return this->Dumper;
  }

  const COF::DumpAnalyzer& OffsetFinder::GetAnalyzer() const
  {
    return this->Analyzer;
  }

  const std::vector<TSearchRegion>& OffsetFinder::GetSearchRegions() const
  {
    return this->SearchRegions;
  }

  std::vector<TSearchRegion>& OffsetFinder::GetSearchRegions()
  {
    return this->SearchRegions;
  }

  JSON& OffsetFinder::JSON_GetSearchRegions()
  {
    return this->JSON_SearchRegions;
  }

  void OffsetFinder::JSON_UpdateSearchRange(const TRange& Range, TSearchRegion& Region, TSearchFor& ToFind)
  {
    // Option isnt enabled, we dont wanna update
    if (!this->ShouldSyncSearchConfig)
    {
      return;
    }

    JSON& RegionsJson = this->JSON_SearchRegions;

    for (auto& RegionJson : RegionsJson)
    {
      if (Region.RegionID != RegionJson.at("RegionID").get<std::string>())
      {
        continue;
      }

      auto& SearchFor = RegionJson["SearchFor"];

      for (auto& Find : SearchFor)
      {
        if (ToFind.SearchID != Find.at("SearchID").get<std::string>())
        {
          continue;
        }

        Find["SearchRange"]["Offset"] = Range.Offset;
        Find["SearchRange"]["Size"] = Range.Size;

        break; // Already found
      }

      break; // Already found
    }
  }

  void OffsetFinder::AddFind(const TFound& FoundItem)
  {
    this->FoundList.push_back(FoundItem);
  }

  void OffsetFinder::HandleExpectedFinds(TSearchRegion& Region)
  {
    // Pass search targets to the defined search handlers.
    // All finds will (should) be added to FoundList by the handlers.
    for (auto& ToFind : Region.SearchFor)
    {
      if (!this->SearchHandlers[ToFind.SearchType](this, Region, ToFind))
      {
        // Probably failed search query,
        // move to next search item in list.
        continue;
      }
    }
  }

  void OffsetFinder::Find(std::vector<TSearchRegion>& Regions, bool ShouldSyncSearchConfig)
  {
    for (auto& Region : Regions)
    {
      // The main finder loop directly handles
      // only regions marked AccessType::Normal.
      if (Region.AccessType != SearchCriteria::AccessType::Normal)
      {
        continue;
      }

      if (!this->RegionHandler(this, Region))
      {
        // Probably failed pre- configuration of Region,
        // move to next region in list.
        continue;
      }

      this->HandleExpectedFinds(Region);
    }

    this->ShouldSyncSearchConfig = ShouldSyncSearchConfig;
  }

  void OffsetFinder::Find(const std::string& FilePath, bool ShouldSyncSearchConfig)
  {
    COF_LOG("[>] Reading search configuration (%s)...", FilePath.c_str());

    JSON& Regions = this->JSON_SearchRegions;
    auto ParsedSearchConfig = Util::JSON_ParseFile(FilePath);

    if (!ParsedSearchConfig)
    {
      COF_LOG("[!] Failed to parse search configuration file (%s)!", FilePath.c_str());
      return;
    }

    Regions = *ParsedSearchConfig;

    // Helper to avoid retyping code
    auto SetRange = [](TRange& CppRange, const JSON& Range)
    {
      if (Range.contains("Offset") && !Range.at("Offset").is_null())
      {
        CppRange.Offset = Range.at("Offset").get<std::uint64_t>();
      }

      if (Range.contains("OffsetVariation") && !Range.at("OffsetVariation").is_null())
      {
        CppRange.OffsetVariation = Range.at("OffsetVariation").get<std::uint64_t>();
      }

      if (Range.contains("Size") && !Range.at("Size").is_null())
      {
        CppRange.Size = Range.at("Size").get<std::size_t>();
      }

      if (Range.contains("SizeVariation") && !Range.at("SizeVariation").is_null())
      {
        CppRange.SizeVariation = Range.at("SizeVariation").get<std::size_t>();
      }
    };

    try
    {
      // TODO:
      //  Use classic for loop instead so that we can display an index
      //  to make debugging easier.

      // NOTE:
      //  All optional properties are checked for null.
      //  We allow to set a property to null
      //  to explicitly show that we want to omit said property.

      // Construct COF C++ objects from JSON
      for (const auto& Region : Regions)
      {
        TSearchRegion CppRegion;

        CppRegion.RegionID = Region.at("RegionID").get<std::string>();
        std::string RegionType = Region.at("RegionType").get<std::string>();

        if (!SearchCriteria::RegionTypes.count(RegionType))
        {
          COF_LOG("[!] Invalid 'RegionType' specified (%s)! Skipping...", RegionType.c_str());
          continue;
        }

        CppRegion.RegionType = SearchCriteria::RegionTypes[RegionType];

        // By default CppRegion.AccessType defaults to AccessType::Normal
        if (Region.contains("AccessType") && !Region.at("AccessType").is_null())
        {
          std::string AccessType = Region.at("AccessType").get<std::string>();

          if (!SearchCriteria::AccessTypes.count(AccessType))
          {
            // Unlike with RegionType, it may be unnecessary
            // to be strict and skip here. We could also just treat an
            // invalid value as AccessType::Normal and continue our loop.
            COF_LOG("[!] Invalid 'AccessType' specified (%s)! Skipping...", AccessType.c_str());
            continue;
          }

          CppRegion.AccessType = SearchCriteria::AccessTypes[AccessType];
        }

        if (Region.contains("RegionRange") && !Region.at("RegionRange").is_null())
        {
          SetRange(CppRegion.RegionRange, Region["RegionRange"]);
        }

        if (Region.contains("Anchors") && !Region.at("Anchors").is_null())
        {
          const auto& Anchors = Region["Anchors"];

          for (const auto& Anchor : Anchors)
          {
            TAnchor CppAnchor;
            std::string Type = Anchor.at("Type").get<std::string>();

            if (!SearchCriteria::AnchorTypes.count(Type))
            {
              COF_LOG("[!] Invalid 'AnchorType' specified (%s)! Skipping...", Type.c_str());
              continue;
            }

            SearchCriteria::AnchorType CppType =
              SearchCriteria::AnchorTypes[Type];

            if (CppType == SearchCriteria::AnchorType::String)
            {
              CppAnchor.String = Anchor.at("Value").get<std::string>();

              // NOTE:
              //  Index is currently only supported for 'String' anchors.
              // TODO:
              //  We should probably extend this to work with other anchor types too.
              if (Anchor.contains("Index") && !Anchor.at("Index").is_null())
              {
                CppAnchor.Index = Anchor.at("Index").get<std::size_t>();
              }
            }
            else if (CppType == SearchCriteria::AnchorType::Pattern)
            {
              CppAnchor.Pattern = Anchor.at("Value").get<std::string>();
            }
            else if (CppType == SearchCriteria::AnchorType::PatternSubsequence)
            {
              CppAnchor.PatternSubsequence =
                Anchor.at("Value").get<std::vector<std::string>>();
            }
            else if (CppType == SearchCriteria::AnchorType::InstructionSubsequence)
            {
              CppAnchor.InstructionSubsequence =
                Anchor.at("Value").get<std::vector<std::string>>();
            }

            CppAnchor.Type = CppType;
            CppRegion.Anchors.push_back(CppAnchor);
          }
        }

        std::vector<TSearchFor> CppSearchFor;
        const auto& SearchFor = Region["SearchFor"];

        for (const auto& SearchTarget : SearchFor)
        {
          TSearchFor CppSearchTarget;
          CppSearchTarget.SearchID = SearchTarget.at("SearchID").get<std::string>();
          std::string SearchType = SearchTarget.at("SearchType").get<std::string>();

          if (!SearchCriteria::SearchTypes.count(SearchType))
          {
            COF_LOG("[!] Invalid 'SearchType' specified (%s)! Skipping...", SearchType.c_str());
            continue;
          }

          CppSearchTarget.SearchType = SearchCriteria::SearchTypes[SearchType];

          if (SearchTarget.contains("Group") && !SearchTarget.at("Group").is_null())
          {
            TGroup CppGroup;
            const auto& Group = SearchTarget["Group"];

            CppGroup.ID = Group.at("ID").get<std::string>();

            if (Group.contains("Index") && !Group.at("Index").is_null())
            {
              CppGroup.Index = Group.at("Index").get<std::size_t>();
            }

            CppSearchTarget.Group = CppGroup;
          }


          if (SearchTarget.contains("SearchRange") && !SearchTarget.at("SearchRange").is_null())
          {
            SetRange(CppSearchTarget.SearchRange, SearchTarget["SearchRange"]);
          }

          if (SearchTarget.contains("MatcherMode") && !SearchTarget.at("MatcherMode").is_null())
          {
            std::string MatcherMode = SearchTarget.at("MatcherMode").get<std::string>();
            
            if (!SearchCriteria::MatcherModes.count(MatcherMode))
            {
              COF_LOG("[!] Invalid 'MatcherMode' specified (%s)! Skipping...", MatcherMode.c_str());
              continue;
            }

            CppSearchTarget.MatcherMode = SearchCriteria::MatcherModes[MatcherMode];
          }

          if (SearchTarget.contains("Matchers") && !SearchTarget.at("Matchers").is_null())
          {
            const auto& Matchers = SearchTarget["Matchers"];

            for (const auto& Matcher : Matchers)
            {
              TMatcher CppMatcher;
              std::string Type = Matcher.at("Type").get<std::string>();

              if (!SearchCriteria::MatcherTypes.count(Type))
              {
                COF_LOG("[!] Invalid 'MatcherType' specified (%s)! Skipping...", Type.c_str());
                continue;
              }

              CppMatcher.Type = SearchCriteria::MatcherTypes[Type];

              if (CppMatcher.Type == SearchCriteria::MatcherType::Pattern)
              {
                CppMatcher.Pattern = Matcher.at("Value").get<std::string>();
              }
              else if (CppMatcher.Type == SearchCriteria::MatcherType::PatternSubsequence)
              {
                CppMatcher.PatternSubsequence = Matcher.at("Value").get<std::vector<std::string>>();
              }
              else if (CppMatcher.Type == SearchCriteria::MatcherType::InstructionSubsequence)
              {
                CppMatcher.InstructionSubsequence = Matcher.at("Value").get<std::vector<std::string>>();
              }

              if (Matcher.contains("Offset") && !Matcher.at("Offset").is_null())
              {
                CppMatcher.Offset = Matcher.at("Offset").get<std::uint64_t>();
              }

              if (Matcher.contains("Index") && !Matcher.at("Index").is_null())
              {
                CppMatcher.Index = Matcher.at("Index").get<std::size_t>();
              }

              CppSearchTarget.Matchers.push_back(CppMatcher);
            }
          }

          if (CppSearchTarget.SearchType == SearchCriteria::SearchType::XReference)
          {
            TNextRegion CppNextRegion;

            if (!SearchTarget.contains("NextRegion") || SearchTarget.at("NextRegion").is_null())
            {
              COF_LOG("[!] An X-Reference type must specify property 'NextRegion'! Skipping...");
              continue;
            }

            const auto& NextRegion = SearchTarget["NextRegion"];
            CppNextRegion.ID = NextRegion.at("ID").get<std::string>();

            CppSearchTarget.NextRegion = CppNextRegion;
          }

          // Print optional (XReference finds dont need a Print).
          // Finds that dont define a 'Print' wont be printed to a file post-extraction.
          if (SearchTarget.contains("Print") && !SearchTarget.at("Print").is_null())
          {
            TPrint CppPrint;
            const auto& Print = SearchTarget["Print"];

            CppPrint.Name = Print.at("Name").get<std::string>();
            const auto& PrintGroup = Print["Group"];

            CppPrint.Group.ID = PrintGroup.at("ID").get<std::string>();

            if (PrintGroup.contains("Index") && !PrintGroup.at("Index").is_null())
            {
              CppPrint.Group.Index = PrintGroup.at("Index").get<std::size_t>();
            }

            CppSearchTarget.Print = CppPrint;
          }

          CppSearchFor.push_back(CppSearchTarget);
        }

        CppRegion.SearchFor = CppSearchFor;
        this->SearchRegions.push_back(CppRegion);
      }
    }
    catch (nlohmann::json::type_error& E)
    {
      COF_LOG("[!] JSON type error: %s", E.what());
      return;
    }

    this->SearchConfigPath = FilePath;
    this->Find(this->SearchRegions, ShouldSyncSearchConfig);
  }

  // ProfileName really shouldnt be passed through this function but whataver
  void OffsetFinder::Print(
    const std::function<void(OffsetFinder*, const std::vector<TFound>&, const std::string&, const std::string&, const std::string&)>& PrintHandler,
    const std::string& PrintConfigPath, const std::string& OffsetsPath, const std::string& ProfileName)
  {
    PrintHandler(this, this->FoundList, PrintConfigPath, OffsetsPath, ProfileName);
  }

  // Recommended but optional to call this function after Find().
  // This will keep the search configuration's offsets updated and keep close
  // to any potential offset/size/alignment changes due to binary updates.
  bool OffsetFinder::SyncSearchConfig() const
  {
    // Option not enabled, dont update file
    if (!this->ShouldSyncSearchConfig)
    {
      return false;
    }

    std::ofstream SearchConfigFile(this->SearchConfigPath);

    if (!SearchConfigFile.is_open())
    {
      COF_LOG("[!] Failed to open search configuration (%s) for updating!", this->SearchConfigPath.c_str());
      return false;
    }

    // Serialize the JSON into already existing search configuration file.
    // std::setw(2) makes it pretty-printed with 2-space indentation
    SearchConfigFile << std::setw(2) << this->JSON_SearchRegions;

    COF_LOG("[+] Updated search configuration (%s) successfully!", this->SearchConfigPath.c_str());
    return true;
  }

  void OffsetFinder::UseSearchHandlers(std::vector<SearchHandler> SearchHandlers)
  {
    for (auto& Handler : SearchHandlers)
    {
      this->SearchHandlers[Handler.Type] = Handler.Function;
    }
  }

  void OffsetFinder::UseRegionHandler(const std::function<bool(OffsetFinder*, TSearchRegion&)>& RegionHandler)
  {
    // Region handler is called prior to search handlers
    this->RegionHandler = RegionHandler;
  }

  bool OffsetFinder::Init(const std::string& FilePath)
  {
    COF_LOG("[>] Opening memory dump (file): %s", FilePath.c_str());

    if (!this->Analyzer.Open(FilePath))
    {
      COF_LOG("[!] Failed to open memory dump!");
      return false; // Failed to open dump file
    }

    if (!this->Analyzer.Analyze<COF::Mode::Regions>())
    {
      COF_LOG("[!] Analysis failed!");
      return false; // Analysis failed forsome reason
    }

    COF_LOG("[?] Total memory regions loaded: %d", this->Analyzer.GetMemoryRegions().size());
    return this->SavePESections();
  }

  bool OffsetFinder::Init(std::uint32_t PID, const std::string& FilePath)
  {
    COF_LOG("[>] Attaching to target process (PID): %d", PID);

    if (!this->Dumper.Attach(PID))
    {
      COF_LOG("[!] Failed to attach!");
      return false; // Failed to attach to process intended for dumping
    }

    std::size_t RegionsDumped = this->Dumper.Dump<COF::Mode::Regions>(FilePath);

    if (!RegionsDumped)
    {
      COF_LOG("[!] Dumping memory regions failed!");
      return false; // Failed to dump process memory (regions)
    }

    COF_LOG("[>] Successfully dumped (%d) memory regions to file: %s",
      RegionsDumped, FilePath.c_str());

    return this->Init(FilePath);
  }

  OffsetFinder::OffsetFinder(const std::string& FilePath)
  {
    this->Init(FilePath);
  }

  OffsetFinder::OffsetFinder(std::uint32_t PID, const std::string& FilePath)
  {
    this->Init(PID, FilePath);
  }
} // !namespace COF