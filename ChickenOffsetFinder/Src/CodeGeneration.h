#ifndef COF_CODE_GENERATION
#define COF_CODE_GENERATION

#include "Util.h"
#include "DumpAnalyzer.h"

#include <cstdint>
#include <string>
#include <vector>
#include <regex>
#include <algorithm>
//#include <iostream>
#include <cstddef>
#include <type_traits>

namespace COF
{
  namespace CodeGeneration
  {
    // Placeholders
    inline constexpr const char* FunctionName = "<FunctioName>";
    inline constexpr const char* ParamName = "<ParamName>";
    inline constexpr const char* VarPrefix = "<V>";

    // Replaces duplicate _rotNN with variables for efficiency and readability,
    // and also adds a return statement (TODO: indentation).
    inline std::string MakeFunctionBody(const std::string& RetWidth, const std::string& RawPseudocode
    /* , std::uint16_t Indentation */)
    {
      const std::string RotatePrefix = "_rot";
      std::vector<std::string> Occurrences;
      std::vector<std::string> UniqueMatches;

      // 1) Scan for each rotor call with balanced parentheses
      std::size_t I = 0;

      while (I < RawPseudocode.size())
      {
        // Find next "_rot"
        auto P = RawPseudocode.find(RotatePrefix, I);

        if (P == std::string::npos)
        {
          break;
        }

        // Must have at least one more char for direction
        if (P + 4 >= RawPseudocode.size())
        {
          break;
        }

        char Dir = RawPseudocode[P + 4];

        if (Dir != 'r' && Dir != 'l')
        {
          I = P + 1;
          continue;
        }

        // Optional "64"
        std::size_t Cur = P + 5;
        bool Has64 = false;

        if (Cur + 1 < RawPseudocode.size() &&
          RawPseudocode[Cur] == '6' && RawPseudocode[Cur + 1] == '4')
        {
          Has64 = true;
          Cur += 2;
        }

        // Next must be '('
        if (Cur >= RawPseudocode.size() || RawPseudocode[Cur] != '(')
        {
          I = P + 1;
          continue;
        }

        // Walk forward to find matching ')'
        int Depth = 1;
        std::size_t Start = P;
        Cur++; // Move past the first '('

        while (Cur < RawPseudocode.size() && Depth > 0)
        {
          if (RawPseudocode[Cur] == '(')
          {
            Depth++;
          }
          else if (RawPseudocode[Cur] == ')')
          {
            Depth--;
          }

          Cur++;
        }

        if (Depth != 0)
        {
          break; // Mismatched parentheses
        }

        // Capture the entire call
        std::string Match = RawPseudocode.substr(Start, Cur - Start);
        Occurrences.push_back(Match);

        if (std::find(UniqueMatches.begin(),
          UniqueMatches.end(),
          Match) == UniqueMatches.end())
        {
          UniqueMatches.push_back(Match);
        }

        I = Cur;
      }

      if (Occurrences.empty())
      {
        return RawPseudocode; // Nothing to do
      }

      // 2) Build the Vn declarations
      std::string DeclarationBlock;

      for (size_t i = 0; i < UniqueMatches.size(); ++i)
      {
        DeclarationBlock += Util::String::Format("  %s %s%d = %s;\n",
          RetWidth.c_str(), VarPrefix, i + 1, UniqueMatches[i].c_str());

        //DeclarationBlock += "  " + RetWidth + " " + VarPrefix +
        //  std::to_string(i + 1) +
        //  " = " +
        //  UniqueMatches[i] +
        //  ";\n";
      }

      // 3) Replace each occurrence in turn with the correct Vn
      std::string Body = RawPseudocode;
      std::size_t SearchPos = 0;

      for (const auto& Occ : Occurrences)
      {
        // Find the next literal Occ starting from SearchPos
        auto Pos = Body.find(Occ, SearchPos);

        if (Pos == std::string::npos)
        {
          break;
        }

        // Figure out which V index this is
        auto It2 = std::find(UniqueMatches.begin(), UniqueMatches.end(), Occ);
        size_t Index = std::distance(UniqueMatches.begin(), It2);

        std::string VarName = VarPrefix + std::to_string(Index + 1);
        Body.replace(Pos, Occ.length(), VarName);
        SearchPos = Pos + VarName.length();
      }

      //return DeclarationBlock + "  return " + Body + ";";
      return Util::String::Format("%s  return %s;", DeclarationBlock.c_str(), Body.c_str());
    }

    inline std::string AddFunctionScope(const std::string& RetWidth, const std::string& ProcessedBody)
    {
      return Util::String::Format("%s %s(%s %s)\n{\n%s\n}",
        RetWidth.c_str(), FunctionName, RetWidth.c_str(), ParamName,
        ProcessedBody.c_str());
    }

    template <typename T = std::uint64_t>
    inline std::string MakeFunction(const std::string& RawPseudocode)
    {
      std::string Width = "std::uint64_t";

      if constexpr (std::is_same_v<T, std::uint32_t>)
      {
        Width = "std::uint32_t";
      }

      std::string ProcessedBody = MakeFunctionBody(Width, RawPseudocode);
      std::string Function = AddFunctionScope(Width, ProcessedBody);

      return Function;
    }
  } // !namespace CodeGeneration
} // !namespace COF

#endif // !COF_CODE_GENERATION