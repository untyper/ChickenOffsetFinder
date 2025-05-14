// Very basic assembly parser for instruction matching purposes.
// NOTE: Does not parse memory operand segment and encoding data (e.g. fs:, gs:, etc...)

#include "AssemblyParser.h"
#include "Util.h"

#include <Zydis/Zydis.h>

#include <iostream>
#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <cstddef>
#include <sstream>
#include <algorithm>
#include <mutex>
#include <cctype>
#include <unordered_map>
#include <utility>
#include <any>

namespace COF
{
  namespace AssemblyParser
  {
    std::optional<ZydisMnemonic> ParseMnemonic(const std::string& MnemonicString)
    {
      static std::unordered_map<std::string, ZydisMnemonic> MnemonicMap;
      static std::once_flag InitFlag;

      // Only call once per program lifetime
      std::call_once(InitFlag, []()
      {
        for (int I = 0; I < ZYDIS_MNEMONIC_MAX_VALUE; ++I)
        {
          // Build mnemonic string to ZydisMnemonic hashmap
          auto Value = static_cast<ZydisMnemonic>(I);

          if (Value == ZYDIS_MNEMONIC_INVALID)
          {
            continue;
          }

          auto Name = ZydisMnemonicGetString(Value);
          MnemonicMap.emplace(Util::String::ToUpper(Name), Value);
        }
      });

      auto Key = Util::String::ToUpper(MnemonicString);
      auto It = MnemonicMap.find(Key);

      if (It != MnemonicMap.end())
      {
        return It->second;
      }

      return std::nullopt;
    }

    std::optional<ZydisRegister> ParseRegister(const std::string& RegisterString)
    {
      static std::unordered_map<std::string, ZydisRegister> RegisterMap;
      static std::once_flag InitFlag;

      // Only call once per program lifetime
      std::call_once(InitFlag, []()
      {
        // Build register string to ZydisRegister hashmap
        for (int I = 0; I < ZYDIS_REGISTER_MAX_VALUE; ++I)
        {
          auto Value = static_cast<ZydisRegister>(I);

          if (Value == ZYDIS_REGISTER_NONE)
          {
            continue;
          }

          auto Name = ZydisRegisterGetString(Value);
          RegisterMap.emplace(Util::String::ToUpper(Name), Value);
        }
      });

      auto Key = Util::String::ToUpper(RegisterString);
      auto It = RegisterMap.find(Key);

      if (It != RegisterMap.end())
      {
        return It->second;
      }

      return std::nullopt;
    }

    bool IsRegister(const std::string& PotentialRegister)
    {
      return ParseRegister(PotentialRegister).has_value();
    }

    std::optional<MemoryOperand> ParseMemoryOperand(const std::string& MemoryOperandString)
    {
      std::string Trimmed = Util::String::Trim(MemoryOperandString);

      if (Trimmed.size() < 2
        || Trimmed.front() != '['
        || Trimmed.back() != ']')
      {
        return std::nullopt;
      }

      std::string Content = Trimmed.substr(1, Trimmed.size() - 2);
      MemoryOperand Op;

      // Split into signed tokens (+ or -)
      std::vector<std::pair<char, std::string>> Tokens;
      char Sign = '+';
      std::size_t Start = 0;

      for (std::size_t I = 0; I < Content.size(); ++I)
      {
        if (Content[I] == '+' || Content[I] == '-')
        {
          Tokens.emplace_back(Sign, Content.substr(Start, I - Start));
          Sign = Content[I];
          Start = I + 1;
        }
      }
      // last token
      Tokens.emplace_back(Sign, Content.substr(Start));

      // Parse each chunk, honoring '?' as wildcard
      for (auto& P : Tokens)
      {
        char        TokSign = P.first;
        std::string Tok = Util::String::Trim(P.second);

        if (Tok.empty() || Tok == "?")
        {
          // Wildcard: do not set Base, Index, Scale or Disp
          continue;
        }

        auto Star = Tok.find('*');
        if (Star != std::string::npos)
        {
          // Index*Scale
          std::string RegStr = Util::String::Trim(Tok.substr(0, Star));
          std::string ScaleStr = Util::String::Trim(Tok.substr(Star + 1));

          if (RegStr != "?")
          {
            Op.Index = ParseRegister(RegStr);
          }

          if (ScaleStr != "?")
          {
            Op.Scale = static_cast<uint8_t>(std::stoull(ScaleStr, nullptr, 0));
          }
        }
        else if (IsRegister(Tok))
        {
          // Pure register token
          auto R = ParseRegister(Tok);

          if (!Op.Base)
          {
            Op.Base = R;
          }
          else
          {
            Op.Index = R;
          }
        }
        else
        {
          // Signed displacement
          // Tok cannot be "?" here (we skipped it), so safe to parse
          int64_t Val = std::stoll(Tok, nullptr, 0);

          if (TokSign == '-')
          {
            Val = -Val;
          }

          if (Op.Disp)
          {
            Op.Disp = *Op.Disp + Val;
          }
          else
          {
            Op.Disp = Val;
          }
        }
      }

      return Op;
    }

    std::optional<ParsedInstruction> ParseInstruction(const std::string& InstructionString)
    {
      auto Parts = Util::String::Split(InstructionString, ',');

      if (Parts.empty())
      {
        return std::nullopt;
      }

      // Extract mnemonic (allow '?' as wildcard)
      std::string FirstToken = Util::String::Trim(Parts[0]);
      auto SpacePos = FirstToken.find(' ');
      std::string MnStr;

      if (SpacePos == std::string::npos)
      {
        MnStr = FirstToken;
        Parts.erase(Parts.begin());
      }
      else
      {
        MnStr = FirstToken.substr(0, SpacePos);
        Parts[0] = FirstToken.substr(SpacePos + 1);
      }

      MnStr = Util::String::Trim(MnStr);
      ParsedInstruction Instr;

      if (MnStr != "?")
      {
        auto OptMn = ParseMnemonic(MnStr);

        if (!OptMn)
        {
          // Invalid mnemonic
          return std::nullopt;
        }

        Instr.Mnemonic = *OptMn;
      }
      else
      {
        // Wildcard mnemonic -> leave Instr.Mnemonic empty
        Instr.Mnemonic = std::nullopt;
      }

      // Parse each operand (allow '?' as wildcard)
      for (auto& Raw : Parts)
      {
        std::string T = Util::String::Trim(Raw);
        std::optional<ParsedOperand> OutOp;

        if (T == "?")
        {
          // Wildcard operand OutOp stays empty
        }
        else if (T.front() == '[' && T.back() == ']')
        {
          // Memory operand (may itself contain '?' inside)
          auto MemOp = ParseMemoryOperand(T);

          if (MemOp)
          {
            ParsedOperand P;
            P.Mem = *MemOp;
            OutOp = P;
          }
          else
          {
            // Malformed memory, treat as wildcard
          }
        }
        else if (IsRegister(T))
        {
          // Register operand
          ParsedOperand P;
          P.Reg = *ParseRegister(T);
          OutOp = P;
        }
        else
        {
          // Immediate operand
          // (T != "?" here, so safe to parse)
          ParsedOperand P;
          P.Imm = std::stoull(T, nullptr, 0);
          OutOp = P;
        }

        Instr.Operands.push_back(OutOp);
      }

      return Instr;
    }
  } // !namespace AssemblyParser
} // !namespace COF