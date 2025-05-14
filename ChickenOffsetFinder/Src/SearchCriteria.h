#ifndef COF_SEARCH_CRITERIA_H
#define COF_SEARCH_CRITERIA_H

#include "Util.h"

#include <string>
#include <unordered_map>
#include <utility>

// Defines the criteria to search by (region, access, etc.)
// and related stuff.
namespace COF
{
  namespace SearchCriteria
  {
    enum class RegionType
    {
      Unknown,
      Section,
      Function,
    };

    enum class RegionID
    {
      Unknown,
      Section_Text, // .Text section
    };

    enum class AccessType
    {
      Normal,
      XReference,
    };

    enum class SearchType
    {
      Unknown,
      Immediate,
      Displacement,
      Reference,
      XReference,
      TslDecryptor32,
      TslDecryptor64,
    };

    enum class MatcherMode
    {
      None,  // Some search items dont define matchers
      First, // True if first matches
      All    // True only if all match
    };

    enum class MatcherType
    {
      None,
      Pattern,
      PatternSubsequence,
      InstructionSubsequence
    };

    enum class AnchorType
    {
      None,
      String,
      Pattern,
      PatternSubsequence,
      InstructionSubsequence
    };

    // String maps for the enum types above,
    // so we can deal with the JSON search configuration file.

    inline std::unordered_map<std::string, RegionType> RegionTypes =
    {
      { "Section", RegionType::Section },
      { "Function", RegionType::Function }
    };

    // All other regions are defined by the user in the search configuration file.
    // This map will only be used in a internal contexts.
    inline std::unordered_map<std::string, RegionID> RegionIDs =
    {
      { "Section_Text", RegionID::Section_Text }
    };

    // AccessTypes defines how a region in the scanlist is accessed/handled.
    // For example AccessType::XReference means the region can only be
    // handled indirectly through an XReference handler, unlike AccessType::Normal
    // which is handled directly by the main find loop (no indirections).
    inline std::unordered_map<std::string, AccessType> AccessTypes =
    {
      { "Normal", AccessType::Normal },
      { "XReference", AccessType::XReference }
    };

    inline std::unordered_map<std::string, SearchType> SearchTypes =
    {
      { "Immediate", SearchType::Immediate },
      { "Displacement", SearchType::Displacement },
      { "Reference", SearchType::Reference },
      { "XReference", SearchType::XReference },
      { "TslDecryptor32", SearchType::TslDecryptor32 },
      { "TslDecryptor64", SearchType::TslDecryptor64 }
    };

    inline std::unordered_map<std::string, MatcherMode> MatcherModes =
    {
      { "First", MatcherMode::First },
      { "All", MatcherMode::All },
    };

    inline std::unordered_map<std::string, MatcherType> MatcherTypes =
    {
      { "Pattern", MatcherType::Pattern },
      { "PatternSubsequence", MatcherType::PatternSubsequence },
      { "InstructionSubsequence", MatcherType::InstructionSubsequence }
    };

    inline std::unordered_map<std::string, AnchorType> AnchorTypes =
    {
      { "String", AnchorType::String },
      { "Pattern", AnchorType::Pattern },
      { "PatternSubsequence", AnchorType::PatternSubsequence },
      { "InstructionSubsequence", AnchorType::InstructionSubsequence }
    };

    template <typename EnumType>
    std::string ToString(const std::unordered_map<std::string, EnumType>& Map, EnumType Value)
    {
      for (const auto& [Key, Val] : Map)
      {
        if (Val == Value)
        {
          return Key;
        }
      }

      return {}; // Maybe log error instead?
    }
  } // !namespace SearchCriteria
} // !namespace COF

#endif // !COF_SEARCH_CRITERIA_H