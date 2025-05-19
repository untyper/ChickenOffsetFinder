#ifndef COF_SEARCH_HANDLERS
#define COF_SEARCH_HANDLERS

#include "Logger.h"
#include "OffsetFinder.h"
#include "AssemblyParser.h"

#include <functional>
#include <optional>
#include <cstdint>
#include <limits>
#include <vector>
#include <string>
#include <cstddef>

namespace COF
{
  namespace SearchHandlers
  {
    namespace Detail
    {
      bool SetBase(OffsetFinder* Finder, TSearchRegion& Region);
      TRange SetBoundaries(const TSearchRegion& Region, const TSearchFor& ToFind);

      // Generic central value extractor for simple values (displacement, immediate, reference etc.).
      // TODO: MatcherCoverage should be returned with the return statement
      template <typename T = DumpAnalyzer::Result<std::uint64_t>>
      inline std::optional<DumpAnalyzer::Result<T>>
        ValueExtractingHandler(OffsetFinder* Finder, const TSearchRegion& Region, TSearchFor& ToFind, TRange* MatcherCoverage,
          std::function<std::optional<DumpAnalyzer::Result<T>>(std::uint64_t, std::size_t)> Extractor)
      {
        // First set scan boundaries. We don't want to overshoot our region
        // address space and scan somewhere else.
        TRange Range = Detail::SetBoundaries(Region, ToFind);
        const TRange& RegionRange = Region.RegionRange;
        std::size_t NumMatchers = ToFind.Matchers.size();

        std::vector<TRange> MatcherCoverageUpdating;
        std::vector<std::uint64_t> InstructionOffsetsVerifying;
        std::uint64_t InstructionOffset = 0;
        std::size_t SuccessfulMatches = 0;
        std::size_t ToMatch = 0;

        // Maybe too pedantic here? Whatever
        if (ToFind.MatcherMode != SearchCriteria::MatcherMode::None)
        {
         if (NumMatchers == 0)
         {
           COF_LOG("[!] 'Matchers' must contain a matcher in modes other than 'None'!");
           return std::nullopt;
         }
        }

        if (ToFind.MatcherMode == SearchCriteria::MatcherMode::First)
        {
          ToMatch = 1;
        }
        else if (ToFind.MatcherMode == SearchCriteria::MatcherMode::All)
        {
          ToMatch = NumMatchers;
        }

        for (const auto& Matcher : ToFind.Matchers)
        {
          COF_LOG("[>] Locating target instruction with '%s'",
            SearchCriteria::ToString(SearchCriteria::MatcherTypes, Matcher.Type).c_str());

          // Helper to avoid code repeat
          auto PostMatching = [&](std::uint64_t MatchOffset, std::size_t MatchSize)
          {
            MatcherCoverageUpdating.push_back({ MatchOffset, MatchSize });
            InstructionOffset = MatchOffset + Matcher.Offset;
            InstructionOffsetsVerifying.push_back(InstructionOffset);
            ++SuccessfulMatches;
          };

          if (Matcher.Type == SearchCriteria::MatcherType::Pattern)
          {
            if (auto Found = Finder->GetAnalyzer()
              .FindPattern(RegionRange.Offset + Range.Offset, Range.Size, Matcher.Pattern); Found)
            {              
              PostMatching(Found->Range.Offset, Found->Range.Size);
            }
          }
          else if (Matcher.Type == SearchCriteria::MatcherType::PatternSubsequence)
          {
            if (auto Found = Finder->GetAnalyzer()
              .FindPatternSubsequence(RegionRange.Offset + Range.Offset, Range.Size, Matcher.PatternSubsequence); Found)
            {
              const auto& SubsequenceRange = (*Found->Value)[Matcher.Index];
              PostMatching(SubsequenceRange.Offset, SubsequenceRange.Size);
            }
          }
          else if (Matcher.Type == SearchCriteria::MatcherType::InstructionSequence)
          {
            std::vector<AssemblyParser::ParsedInstruction> ParsedInstructions;

            for (const auto& AsmText : Matcher.InstructionSequence)
            {
              auto Instruction = COF::AssemblyParser::ParseInstruction(AsmText);

              if (!Instruction)
              {
                COF_LOG("[!] Parsing instruction (%s) in sequence failed!", AsmText.c_str());
                return std::nullopt;
              }

              ParsedInstructions.push_back(*Instruction);
            }

            if (ParsedInstructions.empty())
            {
              COF_LOG("[!] No sequence instructions were parsed!");
              return std::nullopt;
            }

            if (auto Found = Finder->GetAnalyzer()
              .FindInstructionSequence(RegionRange.Offset + Range.Offset, Range.Size, ParsedInstructions); Found)
            {
              const auto& SequenceRange = (*Found->Value)[Matcher.Index];
              PostMatching(SequenceRange.Offset, SequenceRange.Size);
            }
          }
          else if (Matcher.Type == SearchCriteria::MatcherType::InstructionSubsequence)
          {
            std::vector<AssemblyParser::ParsedInstruction> ParsedInstructions;

            for (const auto& AsmText : Matcher.InstructionSubsequence)
            {
              auto Instruction = COF::AssemblyParser::ParseInstruction(AsmText);

              if (!Instruction)
              {
                COF_LOG("[!] Parsing instruction (%s) in subsequence failed!", AsmText.c_str());
                return std::nullopt;
              }

              ParsedInstructions.push_back(*Instruction);
            }

            if (ParsedInstructions.empty())
            {
              COF_LOG("[!] No subsequence instructions were parsed!");
              return std::nullopt;
            }

            if (auto Found = Finder->GetAnalyzer()
              .FindInstructionSubsequence(RegionRange.Offset + Range.Offset, Range.Size, ParsedInstructions); Found)
            {
              const auto& SubsequenceRange = (*Found->Value)[Matcher.Index];
              PostMatching(SubsequenceRange.Offset, SubsequenceRange.Size);
            }
          }

          // +1 to compensate for different starting points
          // between Size (1...) and Index (0)
          if ((ToMatch == SuccessfulMatches))
          {
            break;
          }
        }

        if (ToFind.MatcherMode != SearchCriteria::MatcherMode::None)
        {
          if (SuccessfulMatches < ToMatch)
          {
            COF_LOG("[!] Failed to match instruction with matcher(s) (Mode: %s)!",
              SearchCriteria::ToString(SearchCriteria::MatcherModes, ToFind.MatcherMode).c_str());

            return std::nullopt;
          }

          bool Differs = false;

          for (const auto& Offset : InstructionOffsetsVerifying)
          {
            if (InstructionOffset != Offset)
            {
              COF_LOG("[!] All matchers succeeded but instruction offsets differ!");
              Differs = true;
              break;
            }
          }

          // This only exists for logging/debugging purposes.
          // We should return in the above loop if the below is removed.

          // TODO:
          //  To this extent we probably should also define
          //  an ID member for 'Matcher' so we know exactly which matcher went wrong.
          //  For now we can simply use the order of appearance (Index) for that purpose.
          if (Differs)
          {
            // Print out each offset to help identify any problems
            for (std::size_t I = 0; I < InstructionOffsetsVerifying.size(); ++I)
            {
              const auto& Offset = InstructionOffsetsVerifying[I];
              COF_LOG("  [?] %d: 0x%llX", I, Offset);
            }

            return std::nullopt;
          }

          // Get lowest matcher-begin offset and
          // highest match-end offset (e.g. end of pattern).
          // These will be used to properly update our items search range,
          // so that it gracefully covers all of our matchers.
          std::uint64_t LowestOffset = std::numeric_limits<std::uint64_t>::max();
          std::uint64_t HighestOffset = 0;

          for (const auto& RawRange : MatcherCoverageUpdating)
          {
            std::uint64_t Offset = RawRange.Offset;
            std::uint64_t OffsetPlusSize = Offset + RawRange.Size;

            if (Offset < LowestOffset)
            {
              LowestOffset = Offset;
            }

            if (OffsetPlusSize > HighestOffset)
            {
              HighestOffset = OffsetPlusSize;
            }
          }

          MatcherCoverage->Offset = LowestOffset;
          MatcherCoverage->Size = HighestOffset - LowestOffset;
        }

        std::optional<COF::DumpAnalyzer::Result<T>> Extracted;

        // Use SearchRange alone to extract the value.
        //if (!InstructionOffset)
        if (ToFind.MatcherMode == SearchCriteria::MatcherMode::None)
        {
          COF_LOG("[?] Extracting (ID: %s) without matcher. Using 'SearchRange' only",
            ToFind.SearchID.c_str());

          if (auto FoundTarget = Extractor(RegionRange.Offset + Range.Offset, Range.Size); FoundTarget)
          {
            Extracted = *FoundTarget;
          }
        }
        else
        {
          // Instruction base is known from matchers above,
          // so just extract the first target value from it.
          if (auto FoundTarget = Extractor(InstructionOffset, Range.Size); FoundTarget)
          {
            Extracted = *FoundTarget;
          }
        }

        return Extracted;
      }
    }

    bool RegionHandler(OffsetFinder* Finder, TSearchRegion& Region);
    bool ImmediateHandler(OffsetFinder* Finder, TSearchRegion& Region, TSearchFor& ToFind);
    bool DisplacementHandler(OffsetFinder* Finder, TSearchRegion& Region, TSearchFor& ToFind);
    bool ReferenceHandler(OffsetFinder* Finder, TSearchRegion& Region, TSearchFor& ToFind);
    bool XReferenceHandler(OffsetFinder* Finder, TSearchRegion& Region, TSearchFor& ToFind);
    bool TslDecryptorHandler32(OffsetFinder* Finder, TSearchRegion& Region, TSearchFor& ToFind);
    bool TslDecryptorHandler64(OffsetFinder* Finder, TSearchRegion& Region, TSearchFor& ToFind);
  } // !namespace SearchHandlers
}

#endif // !COF_SEARCH_HANDLERS