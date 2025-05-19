#include "SearchHandlers.h"
#include "SearchCriteria.h"
#include "Logger.h"
#include "Util.h"
#include "OffsetFinder.h"

#include <unordered_map>
#include <iostream>
#include <sstream>
#include <string>
#include <fstream>
#include <vector>
#include <optional>
#include <algorithm>
#include <cstdint>

namespace COF
{
  namespace SearchHandlers
  {
    namespace Detail
    {
      // Call for each Region to dynamically set the Base.
      // This is useful for when you dynamically decide the Base based
      // on the results of OffsetFinder::Analyzer.
      // You don't need to call this if you have already explicitly defined
      // a base in the TSearchRegion list above.
      bool SetBase(OffsetFinder* Finder, TSearchRegion& Region)
      {
        switch (Region.RegionType)
        {
          case SearchCriteria::RegionType::Function:
          {
            if (!Finder->SetFunctionBase(Region))
            {
              return false; // Need this to break from loop in OffsetFinder::Find
            }
            break;
          }
          case SearchCriteria::RegionType::Section:
          {
            auto& Sections = Finder->GetAnalyzer().GetPeSections();

            if (!Sections)
            {
              return false;
            }

            if (SearchCriteria::RegionIDs[Region.RegionID] ==
              SearchCriteria::RegionID::Section_Text)
            {
              auto Section = Sections->GetSection(".text");

              if (!Section)
              {
                return false;
              }

              Region.RegionRange.Offset = Section->GetOffset();
              Region.RegionRange.Size = Section->GetSize();
            }

            break;
          }
        }

        return true;
      }

      TRange SetBoundaries(const TSearchRegion& Region, const TSearchFor& ToFind)
      {
        std::size_t FunctionSize = Region.RegionRange.Size;
        std::size_t FunctionSizeVariation = Region.RegionRange.SizeVariation;

        std::size_t ToFindSize = ToFind.SearchRange.Size;
        std::size_t ToFindSizeVariation = ToFind.SearchRange.SizeVariation;
        std::uint64_t ToFindOffsetVariation = ToFind.SearchRange.OffsetVariation;

        std::uint64_t OffsetLow = ToFind.SearchRange.Offset;
        std::size_t SizeHigh = ToFindOffsetVariation + ToFindSize + ToFindSizeVariation;

        // Only substract variation if variation is smaller than the actual offset,
        // unless you want to deal with unsigned integer wraparound issues.
        if (OffsetLow >= ToFindOffsetVariation)
        {
          OffsetLow -= ToFindOffsetVariation;
        }

        // Set search range to size of region if not explicitly set
        if (ToFindSize <= ToFindSizeVariation)
        {
          std::size_t Variation = 0;

          if (!ToFindSizeVariation)
          {
            Variation = FunctionSizeVariation;
          }

          SizeHigh = FunctionSize + Variation;
          //COF_LOG("[?] Search range was too small, readjusted to region size instead.");
        }

        // Truncate search range to (max) region end.
        // Maybe better to log error when the size is out of bounds?
        if (OffsetLow + SizeHigh > FunctionSize + FunctionSizeVariation)
        {
          SizeHigh = (FunctionSize + FunctionSizeVariation) - OffsetLow;
          //COF_LOG("[?] Search range was out of region bounds, truncated.");
        }

        return { OffsetLow, SizeHigh, 0, 0 };
      }
    }

    // This is meant to run pre- any search handlers, for each region.
    // We use this pre- operation to prepare the Region for the search.
    bool RegionHandler(OffsetFinder* Finder, TSearchRegion& Region)
    {
      // Call for each Region to dynamically set the Base address.
      if (!Detail::SetBase(Finder, Region))
      {
        return false;
      }

      return true;
    }

    // SearchType::Immediate
    bool ImmediateHandler(OffsetFinder* Finder, TSearchRegion& Region, TSearchFor& ToFind)
    {
      TRange MatcherCoverage;

      auto Extracted = Detail::ValueExtractingHandler<std::uint64_t>
        (Finder, Region, ToFind, &MatcherCoverage, [&](std::uint64_t StartOffset, std::size_t Size)
      {
        return Finder->GetAnalyzer().ExtractImmediate(StartOffset, Size);
      });

      if (!Extracted)
      {
        COF_LOG("[!] Unable to find immediate value (ID: %s)!", ToFind.SearchID.c_str());
        return false;
      }

      COF_LOG("[+] Found immediate value (ID: %s): %d", ToFind.SearchID.c_str(), *Extracted->Value);

      std::uint64_t OffsetFromFunctionBase = MatcherCoverage.Offset - Region.RegionRange.Offset;
      Finder->JSON_SyncSearchRange({ OffsetFromFunctionBase, MatcherCoverage.Size }, Region, ToFind);

      // Handlers should add the extracted value(s) to the FoundList for later printing/logging.
      Finder->AddFind({ ToFind, *Extracted->Value });
      return true;
    }

    // SearchType::Displacement
    bool DisplacementHandler(OffsetFinder* Finder, TSearchRegion& Region, TSearchFor& ToFind)
    {
      TRange MatcherCoverage;

      auto Extracted = Detail::ValueExtractingHandler<std::uint32_t>
        (Finder, Region, ToFind, &MatcherCoverage, [&](std::uint64_t StartOffset, std::size_t Size)
      {
        return Finder->GetAnalyzer().ExtractDisplacement(StartOffset, Size);
      });

      if (!Extracted)
      {
        COF_LOG("[!] Unable to find displacement value (ID: %s)!", ToFind.SearchID.c_str());
        return false;
      }

      COF_LOG("[+] Found displacement value (ID: %s): %d", ToFind.SearchID.c_str(), *Extracted->Value);

      std::uint64_t OffsetFromFunctionBase = MatcherCoverage.Offset - Region.RegionRange.Offset;
      Finder->JSON_SyncSearchRange({ OffsetFromFunctionBase, MatcherCoverage.Size }, Region, ToFind);

      // Handlers should add the extracted value(s) to the FoundList for later printing/logging.
      Finder->AddFind({ ToFind, *Extracted->Value });
      return true;
    }

    // SearchType::Reference (RIP-relative value)
    bool ReferenceHandler(OffsetFinder* Finder, TSearchRegion& Region, TSearchFor& ToFind)
    {
      TRange MatcherCoverage;

      auto Extracted = Detail::ValueExtractingHandler<std::uint64_t>
        (Finder, Region, ToFind, &MatcherCoverage, [&](std::uint64_t StartOffset, std::size_t Size)
      {
        return Finder->GetAnalyzer().ResolveRipRelativeOffset(StartOffset, Size);
      });

      if (!Extracted)
      {
        COF_LOG("[!] Unable to resolve RIP-relative value (ID: %s)!", ToFind.SearchID.c_str());
        return false;
      }

      COF_LOG("[+] Resolved RIP-relative value (ID: %s): 0x%X", ToFind.SearchID.c_str(), *Extracted->Value);

      std::uint64_t OffsetFromFunctionBase = MatcherCoverage.Offset - Region.RegionRange.Offset;
      Finder->JSON_SyncSearchRange({ OffsetFromFunctionBase, MatcherCoverage.Size }, Region, ToFind);

      // Handlers should add the extracted value(s) to the FoundList for later printing/logging.
      Finder->AddFind({ ToFind, *Extracted->Value });
      return true;
    }

    // SearchType::XReference
    bool XReferenceHandler(OffsetFinder* Finder, TSearchRegion& Region, TSearchFor& ToFind)
    {
      TRange MatcherCoverage;

      auto Extracted = Detail::ValueExtractingHandler<std::uint64_t>
        (Finder, Region, ToFind, &MatcherCoverage, [&](std::uint64_t StartOffset, std::size_t Size)
      {
        return Finder->GetAnalyzer().ResolveRipRelativeOffset(StartOffset, Size);
      });

      if (!Extracted)
      {
        COF_LOG("[!] Unable to resolve X-Reference offset (ID: %s)!", ToFind.SearchID.c_str());
        return false;
      }

      COF_LOG("[+] Resolved X-Reference offset (ID: %s): 0x%X", ToFind.SearchID.c_str(), *Extracted->Value);
      bool XReferenceHandled = false;

      // Go to reagion/function in the offset and handle its list of SearchFor...
      for (auto& SearchRegion : Finder->GetSearchRegions())
      {
        // NOTE:
        //  We should't have to check if NextRegion has a value
        //  because if we've already reached this point then it must.
        //  We can therefore safely dereference the std::optional.
        if (SearchRegion.RegionID == ToFind.NextRegion->ID)
        {
          if (SearchRegion.AccessType != SearchCriteria::AccessType::XReference)
          {
            COF_LOG("[!] Found matching region but AccessType is not 'XReference'! Skipping...");
            continue;
          }

          // Set base address of XReferenced region,
          // then handle the regions finds next.
          SearchRegion.RegionRange.Offset = *Extracted->Value;
          Finder->HandleExpectedFinds(SearchRegion);

          XReferenceHandled = true;
          break; // We only wanna handle XReferenced region.
        }
      }

      //Finder->AddFind({ ToFind, *Extracted->Value });
      std::uint64_t OffsetFromFunctionBase = MatcherCoverage.Offset - Region.RegionRange.Offset;
      Finder->JSON_SyncSearchRange({ OffsetFromFunctionBase, MatcherCoverage.Size }, Region, ToFind);

      if (!XReferenceHandled)
      {
        COF_LOG("[!] Failed to handle XReference!");
        return false;
      }

      return true;
    }

    // SearchType::TslDecryptor32
    bool TslDecryptorHandler32(OffsetFinder* Finder, TSearchRegion& Region, TSearchFor& ToFind)
    {
      // Ignore finds that have already been handled prior,
      // e.g. from groups.
      if (ToFind.Handled)
      {
        return false;
      }

      // First set scan boundaries. We don't want to overshoot our region
      // address space and scan somewhere else.
      TRange Range = Detail::SetBoundaries(Region, ToFind);
      const TRange& RegionRange = Region.RegionRange;
      auto DecryptorsOpt = Finder->GetAnalyzer().ExtractTslDecryptors<std::uint32_t>(RegionRange.Offset + Range.Offset, Range.Size);

      if (!DecryptorsOpt)
      {
        COF_LOG("[!] Unable to find TslDecryptor32 function(s) (ID: %s)!", ToFind.SearchID.c_str());
        return false;
      }

      auto Decryptors = *DecryptorsOpt->Value;
      std::vector<TSearchFor> GroupedFinds;

      // Generic workflow to handle intermingled Decryptor instructions
      // from separate chains/operations:

      // On occurence of first group member, fetch all group members
      // to handle them here.
      if (ToFind.Group)
      {
        for (auto& Region : Finder->GetSearchRegions())
        {
          for (auto& Find : Region.SearchFor)
          {
            const auto& Group = Find.Group;

            if (Group && Group->ID == ToFind.Group->ID)
            {
              if (Find.SearchType != ToFind.SearchType)
              {
                COF_LOG("[!] Grouped finds must be of same type (Type: %s)! Skipping...",
                  SearchCriteria::ToString(SearchCriteria::SearchTypes, ToFind.SearchType).c_str());

                // Mark as handled or handle later? Dilemma.
                // Find.Handled = true;
                continue;
              }

              GroupedFinds.push_back(Find);

              // Mark group member as handled to exclude it
              // from future handling sice we're already handling it here now.
              Find.Handled = true;
            }
          }
        }

        // We are strict here, to encourage updating offsets/patterns when needed.
        // TODO?:
        //  We could however, for flexibility, still allow the workflow
        //  to continue if we find more than the amount we are looking for.
        if (Decryptors.size() < GroupedFinds.size())
        {
          COF_LOG("[!] Identified group (ID: TslDecryptor32, Type: %s) but too few Decryptors were extracted (%d < %d)!",
            SearchCriteria::ToString(SearchCriteria::SearchTypes, ToFind.SearchType).c_str(),
            Decryptors.size(), GroupedFinds.size());
          return false;
        }
        else if (Decryptors.size() > GroupedFinds.size())
        {
          COF_LOG("[!] Identified group (ID: TslDecryptor32, Type: %s) but too many Decryptors were extracted (%d > %d)!",
            SearchCriteria::ToString(SearchCriteria::SearchTypes, ToFind.SearchType).c_str(),
            Decryptors.size(), GroupedFinds.size());
          return false;
        }

        COF_LOG("[+] Found TslDecryptor32 functions:");

        for (const auto& Find : GroupedFinds)
        {
          // TODO: Check if index within range ( Decryptor.size() > Index)
          const auto& Decryptor = Decryptors[*Find.Group->Index];

          COF_LOG("  [?] %s: %s", Find.SearchID.c_str(), Decryptor.ToString().c_str());
          Finder->AddFind({ Find, Decryptor });
        }

        return true;
      }

      COF_LOG("[+] Found TslDecryptor32 function:");
      COF_LOG("  [?] %s: %s", ToFind.SearchID.c_str(), Decryptors[0].ToString().c_str());

      std::uint64_t OffsetFromFunctionBase = DecryptorsOpt->Range.Offset - RegionRange.Offset;
      Finder->JSON_SyncSearchRange({ OffsetFromFunctionBase, DecryptorsOpt->Range.Size }, Region, ToFind);

      // Handlers should add the extracted value(s) to the FoundList for later printing/logging.
      Finder->AddFind({ ToFind, Decryptors[0] });
      return (ToFind.Handled = true);
    }

    // SearchType::TslDecryptor64
    bool TslDecryptorHandler64(OffsetFinder* Finder, TSearchRegion& Region, TSearchFor& ToFind)
    {
      // First set scan boundaries. We don't want to overshoot our region
      // address space and scan somewhere else.
      TRange Range = Detail::SetBoundaries(Region, ToFind);
      const TRange& RegionRange = Region.RegionRange;
      auto DecryptorsOpt = Finder->GetAnalyzer().ExtractTslDecryptors<std::uint64_t>(RegionRange.Offset + Range.Offset, Range.Size);

      if (!DecryptorsOpt)
      {
        COF_LOG("[!] Unable to find TslDecryptor64 function(s) (ID: %s)!", ToFind.SearchID.c_str());
        return false;
      }

      // NOTE:
      //  We are not expecting intermingled Decryptor instructions
      //  for the 64-bit version, for now (13.04.2025).
      //  We can therefore simply extract the first entry returned.

      auto Decryptors = *DecryptorsOpt->Value;

      COF_LOG("[+] Found TslDecryptor64 function:");
      COF_LOG("  [?] %s: %s", ToFind.SearchID.c_str(), Decryptors[0].ToString().c_str());

      std::uint64_t OffsetFromFunctionBase = DecryptorsOpt->Range.Offset - RegionRange.Offset;
      Finder->JSON_SyncSearchRange({ OffsetFromFunctionBase, DecryptorsOpt->Range.Size }, Region, ToFind);

      // Handlers should add the extracted value(s) to the FoundList for later printing/logging.
      Finder->AddFind({ ToFind, Decryptors[0] });
      return true;
    }
  } // !namespace SearchHandlers
} // !namespace COF