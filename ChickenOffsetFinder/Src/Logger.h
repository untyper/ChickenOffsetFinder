#ifndef COF_LOGGER_H
#define COF_LOGGER_H

// Simple logger macro.
// Outputs to cout and to a log file

// Enable by defining COF_ENABLE_LOGGING
#ifdef COF_ENABLE_LOGGING

#ifndef COF_LOGGER_FILE_PATH
  #define COF_LOGGER_FILE_PATH "Log.cof.txt"
#endif // !COF_LOGGER_FILE_PATH

#include <iostream>
#include <fstream>
#include <stdarg.h>
#include <cstdio>

inline void WriteLog(const char* Format, ...)
{
  char Buffer[1024];
  va_list Args;
  va_start(Args, Format);
  std::vsnprintf(Buffer, sizeof(Buffer), Format, Args);
  va_end(Args);

  std::ofstream OutFile(COF_LOGGER_FILE_PATH, std::ios::app);

  if (OutFile)
  {
    OutFile << Buffer << '\n';
  }

  std::cout << Buffer << '\n';
}

#define COF_LOG(...) WriteLog(__VA_ARGS__)

#else
  // If logging is disabled, define as no-op
#define COF_LOG(...) ((void)0)
#endif

#endif // !COF_LOGGER_H