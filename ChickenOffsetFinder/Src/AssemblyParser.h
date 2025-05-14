#ifndef COF_ASSEMBLY_PARSER
#define COF_ASSEMBLY_PARSER

#include "DumpAnalyzer.h"

#include <Zydis/Zydis.h>

#include <string>
#include <vector>
#include <optional>

namespace COF
{
  namespace AssemblyParser
  {
    // Semantic aliases
    using MemoryOperand = DumpAnalyzer::MemoryOperand;
    using ParsedOperand = DumpAnalyzer::MatchOperand;
    using ParsedInstruction = DumpAnalyzer::MatchInstruction;

    std::optional<ZydisMnemonic> ParseMnemonic(const std::string& MnemonicString);
    std::optional<ZydisRegister> ParseRegister(const std::string& RegisterString);
    bool IsRegister(const std::string& PotentialRegister);
    std::optional<MemoryOperand> ParseMemoryOperand(const std::string& MemoryOperandString);
    std::optional<ParsedInstruction> ParseInstruction(const std::string& InstructionString);
  } // !namespace AssemblyParser
} // !namespace COF

#endif // !COF_ASSEMBLY_PARSER