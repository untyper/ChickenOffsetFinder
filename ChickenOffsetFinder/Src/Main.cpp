#define _WINSOCKAPI_

#include "DumpAnalyzer.h"
#include "OffsetFinder.h"
#include "SearchHandlers.h"
#include "Printer.h"
#include "AssemblyParser.h"
#include "Util.h"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>
#include <Zydis/Zydis.h>

#include "nlohmann/json.hpp"
#include <Windows.h>

#include <iostream>
#include <sstream>
#include <optional>
#include <string>
#include <cstdint>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <unordered_map>
#include <vector>

// Helpers: usage + filename generators
static void PrintUsage()
{
  std::cerr
    << '\n' << COF_NAME << " v" << COF_VERSION << '\n'
    << "Copyright(C) " << COF_LICENSE_YEAR << " " << COF_AUTHOR << "\n\n"
    << "Usage:      COF <command> [<flags...>]\n\n"
    << "Commands:\n"
    << "  find      Finds and prints offsets based on the proceeding flags.\n\n"
    << "  Flags:\n"
    << "    -pid      <PID>            Process ID of executable to dump and search.\n"
    << "    -file     <DumpFile>       Filename of previously dumped executable.\n"
    << "                               If used alongside -pid, then this will refer to\n"
    << "                               the newly dumped memory from the specified PID.\n"
    << "    -out      <OutOffsetsFile> File to which found offsets will be printed.\n"
    << "    -sync                      Synchronizes the match ranges in the search configuration file\n"
    << "                               with the ranges at which the target offsets were found.\n"
    << "    -profile  <ProfileName>    Name of profile listed in the profile configuration file.\n"
    << "                               The search and print configuration files associated with the\n"
    << "                               specified profile will be used to search for and print offsets.\n"
    << "    -profiles <ProfilesConfig> Profiles configuration file. Default is " << COF_PROFILES_FILENAME << '\n'
    << "    -sc       <SearchConfig>   Search configuration file.\n"
    << "                               Matches and extracts offsets using patterns defined in this file.\n"
    << "    -pc       <PrintConfig>    Print configuration file.\n"
    << "                               Decides layout of extracted offsets in the printed file.\n\n"
    << "  Notes:\n"
    << "              -sc and -pc must be used together and cannot be used in conjunction with -profile.\n"
    << "              In other words, when -profile is used -sc and -pc must not be used.\n\n"
    << "              -sync updates the search configuration file with the latest ranges.\n"
    << "              It will not touch the match range variation fields.\n\n"
    << "Source:     https://github.com/untyper/ChickenOffsetFinder\n"
    << "License:    " << COF_LICENSE << '\n';
}

static std::string GenerateTimestampedFilename(const std::string& Prefix, const std::string& Extension)
{
  using namespace std::chrono;
  auto Now = system_clock::now();
  std::time_t TimeT = system_clock::to_time_t(Now);
  std::tm Gm{};
#if defined(_WIN32)
  gmtime_s(&Gm, &TimeT);
#else
  gmtime_r(&TimeT, &Gm);
#endif

  std::ostringstream Oss;
  Oss << Prefix
    << '_'
    << std::put_time(&Gm, "%Y%m%d_%H%M%S")
    << Extension;
  return Oss.str();
}

// Parse all "-flag value" pairs into a map
static std::unordered_map<std::string, std::string> ParseFlags(int ArgC, char* ArgV[])
{
  std::unordered_map<std::string, std::string> Flags;

  for (int I = 2; I < ArgC; ++I)
  {
    std::string Arg = ArgV[I];

    // Recognized valueless flags
    if (Arg == "-sync")
    {
      Flags[Arg] = "";
      continue;
    }

    // Recognized value flags
    if (Arg == "-pid" ||
        Arg == "-out" ||
        Arg == "-file" ||
        Arg == "-profile" ||
        Arg == "-profiles" ||
        Arg == "-sc" ||
        Arg == "-pc")
    {
      if (I + 1 >= ArgC)
      {
        std::cerr << "Error: Missing value for flag " << Arg << "\n";
        std::exit(EXIT_FAILURE);
      }
      Flags[Arg] = ArgV[++I];
      continue;
    }

    std::cerr << "Error: Unknown flag " << Arg << "\n";
    std::exit(EXIT_FAILURE);
  }

  return Flags;
}

// find command
struct FindOptions
{
  std::optional<std::uint32_t> PID; // Optional, if user passed -pid
  std::string InDumpFile;           // Either from -file or generated from PID
  std::string OutOffsetsFile;       // -out or timestamped default
  bool SyncSearchConfig = false;    // Whether to synchronize current search config file with found offsets
  bool ProfileMode = false;         // true if -profile was used
  std::string ProfileName;          // Profile name within Profiles configuration
  std::string ProfilesConfig;       // Custom profile file
  std::string SearchConfig;         // Search configuration file used to find offsets
  std::string PrintConfig;          // Print configuration file to decide how to print offsets to file
};

static FindOptions ParseFindOptions(const std::unordered_map<std::string, std::string>& Flags)
{
  FindOptions Opts;

  // Mutually exclusive: -profile vs. (-sc and -pc)
  bool HasProfile = Flags.count("-profile");
  bool HasSC = Flags.count("-sc");
  bool HasPC = Flags.count("-pc");

  if (HasProfile && (HasSC || HasPC))
  {
    std::cerr << "Error: -profile cannot be used with -sc/-pc\n";
    std::exit(EXIT_FAILURE);
  }
  if ((HasSC || HasPC) && HasProfile)
  {
    std::cerr << "Error: -sc/-pc cannot be used with -profile\n";
    std::exit(EXIT_FAILURE);
  }
  if (HasSC != HasPC)
  {
    std::cerr << "Error: Both -sc and -pc must be provided together\n";
    std::exit(EXIT_FAILURE);
  }
  if (!HasProfile && !HasSC)
  {
    std::cerr << "Error: Requires either -profile or both -sc and -pc\n";
    std::exit(EXIT_FAILURE);
  }

  // Optional PID
  if (Flags.count("-pid"))
  {
    Opts.PID = std::stoi(Flags.at("-pid"));
  }

  // Determine which dump-file to use
  if (Flags.count("-file"))
  {
    Opts.InDumpFile = Flags.at("-file");
  }
  else if (Opts.PID)
  {
    Opts.InDumpFile = GenerateTimestampedFilename(std::to_string(*Opts.PID), ".exe");
  }
  else
  {
    std::cerr << "Error: find command needs either -file or -pid\n";
    std::exit(EXIT_FAILURE);
  }

  // Profile vs. config mode
  Opts.ProfileMode = HasProfile;

  if (HasProfile)
  {
    Opts.ProfilesConfig = Flags.count("-profiles")
      ? Flags.at("-profiles")
      : COF_PROFILES_FILENAME;

    Opts.ProfileName = Flags.at("-profile");
    auto Profiles = COF::Util::JSON_ParseFile(Opts.ProfilesConfig);

    if (!Profiles)
    {
      std::cerr << "Error: Unable to parse '" << Opts.ProfilesConfig << "'\n";
      std::exit(EXIT_FAILURE);
    }

    if (!Profiles->contains(Opts.ProfileName) || !Profiles->at(Opts.ProfileName).is_object())
    {
      std::cerr << "Error: Profile '" << Opts.ProfileName << "' invalid or does not exist\n";
      std::exit(EXIT_FAILURE);
    }

    const auto& Profile = (*Profiles)[Opts.ProfileName];

    if (!Profile.contains("SearchConfig") || !Profile.contains("PrintConfig"))
    {
      std::cerr << "Error: Profile '" << Opts.ProfileName <<
        "' is missing either 'SearchConfig' or 'PrintConfig' key(s)\n";
      std::exit(EXIT_FAILURE);
    }

    if (!Profile.at("SearchConfig").is_string() || !Profile.at("PrintConfig").is_string())
    {
      std::cerr << "Error: Both 'SearchConfig' and 'PrintConfig' keys must be strings\n";
      std::exit(EXIT_FAILURE);
    }

    Opts.SearchConfig = Profile.at("SearchConfig").get<std::string>();
    Opts.PrintConfig = Profile.at("PrintConfig").get<std::string>();
  }
  else
  {
    Opts.SearchConfig = Flags.at("-sc");
    Opts.PrintConfig = Flags.at("-pc");
  }

  // Output offsets file
  if (!Flags.count("-out"))
  {
    std::string PartialFileName = "_Offsets.cof";
    std::string OffsetsFilePrefix;

    if (HasProfile)
    {
      OffsetsFilePrefix = Opts.ProfileName + PartialFileName;
    }
    // -file provided with or without -pid
    else if (Flags.count("-file"))
    {
      OffsetsFilePrefix = Opts.InDumpFile + PartialFileName;
    }
    // -pid provided alone
    else if (Flags.count("-pid"))
    {
      OffsetsFilePrefix = std::to_string(*Opts.PID) + PartialFileName;
    }

    Opts.OutOffsetsFile = GenerateTimestampedFilename(OffsetsFilePrefix, ".h");
  }
  else
  {
    Opts.OutOffsetsFile = Flags.at("-out");
  }

  // Whether to synchronize current search config file with found offsets
  Opts.SyncSearchConfig = Flags.count("-sync")
    ? true
    : false;

  return Opts;
}

static void HandleFind(const FindOptions& Opts)
{
  std::cout << '\n';

  try
  {
    COF::OffsetFinder Finder;

    if (Opts.PID)
    {
      Finder.Init(*Opts.PID, Opts.InDumpFile);
    }
    else
    {
      Finder.Init(Opts.InDumpFile);
    }

    Finder.UseRegionHandler(COF::SearchHandlers::RegionHandler);

    // Declare usage of user defined handlers before actually attempting to find!
    Finder.UseSearchHandlers({
      { COF::SearchCriteria::SearchType::Immediate, COF::SearchHandlers::ImmediateHandler },
      { COF::SearchCriteria::SearchType::Displacement, COF::SearchHandlers::DisplacementHandler },
      { COF::SearchCriteria::SearchType::Reference, COF::SearchHandlers::ReferenceHandler },
      { COF::SearchCriteria::SearchType::XReference, COF::SearchHandlers::XReferenceHandler },
      { COF::SearchCriteria::SearchType::TslDecryptor32, COF::SearchHandlers::TslDecryptorHandler32 },
      { COF::SearchCriteria::SearchType::TslDecryptor64, COF::SearchHandlers::TslDecryptorHandler64 },
    });

    Finder.Find(Opts.SearchConfig, Opts.SyncSearchConfig);
    Finder.SyncSearchConfig();
    Finder.Print(COF::Printer::PrintHandler, Opts.PrintConfig, Opts.OutOffsetsFile, Opts.ProfileName);
  }
  catch (const std::exception& E)
  {
    std::cerr << "[!] Error: " << E.what() << "\n";
  }
}

int main(int ArgC, char* ArgV[])
{
  if (ArgC < 2)
  {
    PrintUsage();
    return EXIT_FAILURE;
  }

  std::string Command = ArgV[1];
  auto Flags = ParseFlags(ArgC, ArgV);

  if (Command == "find")
  {
    auto Opts = ParseFindOptions(Flags);
    HandleFind(Opts);
  }
  else
  {
    PrintUsage();
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}