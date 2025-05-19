#ifndef COF_OFFSET_FINDER_H
#define COF_OFFSET_FINDER_H

#include "MemoryDumper.h"
#include "DumpAnalyzer.h"
#include "SearchCriteria.h"

#include "nlohmann/json.hpp"

#include <set>
#include <cstdint>
#include <functional>
#include <any>
#include <unordered_map>
#include <string>
#include <vector>
#include <optional>
#include <cstddef>

#ifndef COF_PROFILES_FILENAME
#define COF_PROFILES_FILENAME "Profiles.cof.json"
#endif

namespace COF
{
  using JSON = nlohmann::ordered_json;

  struct TRange;
  struct TSearchFor;
  struct TSearchRegion;
  class OffsetFinder;

  struct SearchHandler
  {
    SearchCriteria::SearchType Type = {};
    std::function<bool(OffsetFinder*, TSearchRegion&, TSearchFor&)> Function;

    bool Call(OffsetFinder*, TSearchRegion&, TSearchFor&) const;
  };

  // TODO:
  //  Rename and move all T<StructName> structs
  //  to their own meaningful namespace to stop them
  //  from polluting the global COF namespace.

  struct TGroup
  {
    std::string ID;
    std::optional<std::size_t> Index;
  };

  struct TRange
  {
    std::uint64_t Offset = 0;
    std::size_t Size = 0;

    // Variation to take into account
    // potential changes across updates.
    std::uint64_t OffsetVariation = 0;
    std::size_t SizeVariation = 0;
  };

  struct TMatcher
  {
    SearchCriteria::MatcherType Type = {};

    // For semantic reasons we define a member for each type.
    // Probably better to define getters instead to save a few bytes?
    std::string Pattern;
    std::vector<std::string> PatternSubsequence;
    std::vector<std::string> InstructionSequence;
    std::vector<std::string> InstructionSubsequence;

    // This decides from which index in the subsequence list we match our target.
    // E.g. If we specify Index = 2 and item at Index 2 has
    // offset 0xBEEF we start matching our target at 0xBEEF.
    // By default we match from the very first item in the subsequence list (Index = 0)
    // which is standard for all pattern matching.
    std::size_t Index = 0;

    // Offset from start of the matched pattern or
    // from the Index of item in subsequence list.
    // By default match the very start of the pattern.
    std::uint64_t Offset = 0;
  };

  // Next region to handle in reference chain.
  // Currently only works with XReference finds.
  struct TNextRegion
  {
    std::string ID;
  };

  struct TPrintGroup
  {
    std::string ID;
    std::size_t Index = 0;
  };

  struct TPrint
  {
    std::string Name;
    TPrintGroup Group;
  };

  struct TSearchFor
  {
    std::string SearchID;
    SearchCriteria::SearchType SearchType = {};

    SearchCriteria::MatcherMode MatcherMode = {};
    std::vector<TMatcher> Matchers;
    TRange SearchRange;

    // Next region to handle after the current SearchTarget.
    // For now its only applicable to SearchType::XReference,
    // as its not very useful for other types.
    std::optional<TNextRegion> NextRegion;

    // Mandatory for printing.
    // Not needed for Finds that wont be printed (e.g. XReference)
    std::optional<TPrint> Print;

    // Successfully handled finds.
    // Currently only useful for handling Grouped finds,
    // but the usage can easily be extended for debugging purposes.
    bool Handled = false;
    std::optional<TGroup> Group;
  };

  // Used in Printer.h
  struct TFound
  {
    TSearchFor Match; // Needle that produced the match
    std::any Value;   // Value extracted from match in handler
  };

  // Anchor we use to actually locate the general address space of a region,
  // from which we can then attempt to find the base of the region.
  // A single region can have multiple anchors.
  struct TAnchor
  {
    SearchCriteria::AnchorType Type = {};

    // For semantic reasons we define a member for each type.
    // Probably better to define getters instead to save a few bytes?
    std::string String;
    std::string Pattern;
    std::vector<std::string> PatternSubsequence;
    std::vector<std::string> InstructionSubsequence;
    std::vector<std::string> InstructionSequence;

    // There could be multiple anchor matches,
    // this chooses which match to use.
    // Currently only 'String' is supported.
    std::size_t Index = 0;
  };

  struct TSearchRegion
  {
    std::string RegionID;
    SearchCriteria::RegionType RegionType = {};
    SearchCriteria::AccessType AccessType = {};

    TRange RegionRange;
    std::vector<TAnchor> Anchors;
    std::vector<TSearchFor> SearchFor;
  };

  class OffsetFinder
  {
    struct
    {
      DumpAnalyzer::PeSection Text;
    } Sections;

    MemoryDumper Dumper;
    DumpAnalyzer Analyzer;

    JSON JSON_PrintConfig;
    JSON JSON_SearchRegions;
    std::vector<TSearchRegion> SearchRegions;
    std::vector<TFound> FoundList;
    std::string SearchConfigPath;
    bool ShouldSyncSearchConfig = false;

    std::function<bool(OffsetFinder*, TSearchRegion&)> RegionHandler;
    std::unordered_map<SearchCriteria::SearchType,
      std::function<bool(OffsetFinder*, TSearchRegion&, TSearchFor&)>> SearchHandlers;

    bool SavePESections();

  public:
    // These are used by SearchHandlers
    const MemoryDumper& GetDumper() const;
    const DumpAnalyzer& GetAnalyzer() const;

    const std::vector<TSearchRegion>& GetSearchRegions() const;
    std::vector<TSearchRegion>& GetSearchRegions();

    JSON& JSON_GetSearchRegions();
    void JSON_SyncSearchRange(const TRange& Range, TSearchRegion& Region, TSearchFor& ToFind);

    void AddFind(const TFound& FoundItem);
    std::optional<std::uint64_t> SetFunctionBase(TSearchRegion& Function);
    void HandleExpectedFinds(TSearchRegion& Region);

    // These are used for initialization, running and printing
    // of the OffsetFinder instance.
    void Find(std::vector<TSearchRegion>& Regions, bool ShouldSyncSearchConfig = false);
    void Find(const std::string& FilePath, bool ShouldSyncSearchConfig = false);
    void Print(const std::function<void(OffsetFinder*, const std::vector<TFound>&,
      const std::string&, const std::string&, const std::string&)>& PrintHandler,
      const std::string& PrintConfigPath, const std::string& OffsetsPath, const std::string& ProfileName);
    bool SyncSearchConfig() const;

    void UseSearchHandlers(std::vector<SearchHandler> SearchHandlers);
    void UseRegionHandler(const std::function<bool(OffsetFinder*, TSearchRegion&)>& RegionHandler);

    bool Init(const std::string& FilePath);
    bool Init(std::uint32_t PID, const std::string& FilePath);

    OffsetFinder(const std::string& FilePath);
    OffsetFinder(std::uint32_t PID, const std::string& FilePath);
    OffsetFinder() = default;
  };
} // !namespace COF

#endif // !COF_OFFSET_FINDER_H