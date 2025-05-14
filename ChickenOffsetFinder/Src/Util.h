#ifndef COF_UTIL
#define COF_UTIL

#include "nlohmann/json.hpp"

#include <Windows.h>
#pragma comment(lib, "Version.lib")

#include <string>
#include <sstream>
#include <optional>
#include <cstdarg>
#include <cstdio>
#include <iomanip>
#include <ctime>
#include <cctype>
#include <vector>
#include <algorithm>
#include <cstddef>
#include <fstream>
#include <iterator>

namespace COF
{
  using JSON = nlohmann::ordered_json;

  namespace Util
  {
    namespace String
    {
      inline std::vector<std::string> Split(const std::string& String, char Delim)
      {
        std::vector<std::string> Tokens;
        std::istringstream Iss(String);
        std::string Item;

        while (std::getline(Iss, Item, Delim))
        {
          Tokens.push_back(Item);
        }

        return Tokens;
      }

      inline std::string Join(const std::vector<std::string>& Tokens, char Delim)
      {
        std::ostringstream Oss;

        for (size_t i = 0; i < Tokens.size(); ++i)
        {
          Oss << Tokens[i];

          if (i + 1 < Tokens.size())
          {
            Oss << Delim;
          }
        }

        return Oss.str();
      }

      inline std::string Trim(const std::string& String)
      {
        size_t Start = String.find_first_not_of(" \t");
        size_t End = String.find_last_not_of(" \t");

        if (Start == std::string::npos
          || End == std::string::npos)
        {
          return "";
        }

        return String.substr(Start, End - Start + 1);
      }

      inline std::string ToUpper(const std::string& String)
      {
        std::string Out = String;
        std::transform(
          Out.begin(),
          Out.end(),
          Out.begin(),
          [](unsigned char C) { return std::toupper(C); }
        );

        return Out;
      }

      // Mutates existing string
      inline void ReplaceAll(std::string& String, const std::string& From, const std::string& To)
      {
        if (From.empty())
        {
          return; // Avoid infinite loop
        }

        std::size_t Pos = 0;

        while ((Pos = String.find(From, Pos)) != std::string::npos)
        {
          String.replace(Pos, From.length(), To);
          Pos += To.length(); // Advance past the replacement
        }
      }

      inline std::string Format(const char* Format, ...)
      {
        va_list Args1;
        va_start(Args1, Format);

        va_list Args2;
        va_copy(Args2, Args1);

        int Size = std::vsnprintf(nullptr, 0, Format, Args1);
        va_end(Args1);

        if (Size < 0)
        {
          return {};
        }

        std::string Result(Size, '\0');
        std::vsnprintf(&Result[0], Size + 1, Format, Args2);
        va_end(Args2);

        return Result;
      }
    } // !namespace String

    // Not used for now but probably useful for logging at some point.
    inline std::optional<std::string> GetFileVersion(const std::string& FilePath)
    {
      DWORD Handle = 0;
      DWORD Size = GetFileVersionInfoSizeA(FilePath.c_str(), &Handle);

      if (Size == 0)
      {
        return std::nullopt;
      }

      std::vector<BYTE> VersionData(Size);

      if (!GetFileVersionInfoA(FilePath.c_str(), Handle, Size, VersionData.data()))
      {
        return std::nullopt;
      }

      VS_FIXEDFILEINFO* FileInfo = nullptr;
      UINT Length = 0;

      if (!VerQueryValueA(VersionData.data(), "\\", reinterpret_cast<LPVOID*>(&FileInfo), &Length))
      {
        return std::nullopt;
      }

      if (FileInfo)
      {
        DWORD Major = HIWORD(FileInfo->dwFileVersionMS);
        DWORD Minor = LOWORD(FileInfo->dwFileVersionMS);
        DWORD Build = HIWORD(FileInfo->dwFileVersionLS);
        DWORD Revision = LOWORD(FileInfo->dwFileVersionLS);

        std::string Version =
          std::to_string(Major) + "." +
          std::to_string(Minor) + "." +
          std::to_string(Build) + "." +
          std::to_string(Revision);

        return Version;
      }

      return std::nullopt;
    }

    inline std::string GetCurrentDate()
    {
      std::time_t Now = std::time(nullptr);
      std::tm LocalTime{};
      localtime_s(&LocalTime, &Now);

      std::ostringstream String;

      String << std::setw(2) << std::setfill('0') << LocalTime.tm_mday << "."
        << std::setw(2) << std::setfill('0') << (LocalTime.tm_mon + 1) << "."
        << (1900 + LocalTime.tm_year);

      return String.str();
    }

    inline std::optional<JSON> JSON_ParseFile(const std::string& FilePath)
    {
      JSON Parsed;

      // Open file and parse into a json object
      try
      {
        // Slurp the entire file into a string
        std::ifstream File(FilePath);

        if (!File.is_open())
        {
          return std::nullopt;
        }

        std::string Content = {
          std::istreambuf_iterator<char>(File),
          std::istreambuf_iterator<char>()
        };

        // Parse with ignore_comments=true
        Parsed = JSON::parse(
          Content,          // The input
          nullptr,          // No callback
          true,             // allow_exceptions
          true              // ignore_comments
        );
      }
      catch (JSON::parse_error& E)
      {
        (void)E; // Silence warning for now
        return std::nullopt;
      }

      return Parsed;
    }
  } // !namespace Util
} // !namespace COF

#endif // !COF_UTIL