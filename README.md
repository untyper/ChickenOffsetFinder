# ChickenOffsetFinder
General purpose static offset finder for Windows programs (x64)

Dumps a programs memory and scans through the dump to find the defined target offsets.
This is an experimental project and is not intended for production use.

## Build
- Launch `.sln` file and build (Visual Studio 2022)

## Usage
```
Usage:      COF <command> [<flags...>]

Commands:
  find      Finds and prints offsets based on the proceeding flags.

  Flags:
    -pid      <PID>            Process ID of executable to dump and search.
    -file     <DumpFile>       Filename of previously dumped executable.
                               If used alongside -pid, then this will refer to
                               the newly dumped memory from the specified PID.
    -out      <OutOffsetsFile> File to which found offsets will be printed.
    -sync                      Synchronizes the match ranges in the search configuration file
                               with the ranges at which the target offsets were found.
    -profile  <ProfileName>    Name of profile listed in the profile configuration file.
                               The search and print configuration files associated with the
                               specified profile will be used to search for and print offsets.
    -profiles <ProfilesConfig> Profiles configuration file. Default is Profiles.cof.json
    -sc       <SearchConfig>   Search configuration file.
                               Matches and extracts offsets using patterns defined in this file.
    -pc       <PrintConfig>    Print configuration file.
                               Decides layout of extracted offsets in the printed file.

  Notes:
              -sc and -pc must be used together and cannot be used in conjunction with -profile.
              In other words, when -profile is used -sc and -pc must not be used.

              -sync updates the search configuration file with the latest ranges.
              It will not touch the match range variation fields.
```

## Documentation
### Search Configuration

The configuration file consists of an array of objects, each defining a distinct search region within a binary.

```js
[
  {
    "RegionID": "Function_AllocateNameEntry", // Unique ID of region for internal implementation

    // "RegionType":
    //   "Function"
    //   "Section"
    "RegionType": "Function",

    // Defines the boundaries of the region. This is also used when locating the region with the anchor.
    "RegionRange": {
      "Size": 1628,  // Size of region
      "SizeVariation": 64 // Possible size variation between old and new versions of the binary
    },

    // Determines how this region is accessed by the main finder loop.
    // "AccessType":
    //   "Normal" -> Default. The region is accessed by the main finder loop.
    //   "XReference" -> the region is accessed by the XReference search handler.

    //  Consequently, if AccessType is "XReference", a search item must refer to this region by defining:
    //   "SearchType": "XReference"
    //   "NextRegion": {...}

    //  Read more about "NextRegion" below in the "SearchFor" array.
    "AccessType": "Normal",

    // List of search items to find offsets
    "SearchFor": [
      {
        "SearchID": "GNames", // Unique ID of search item for internal implementation

        // Type of search, determines the value/offset extracted.
        // "SearchType":
        //   "Immediate"
        //   "Displacement"
        //   "Reference"
        //   "XReference"
        //   "TslDecryptor32"
        //   "TslDecryptor64"
        "SearchType": "Reference",

        // Determines when an a value is considered a match.
        // "MatcherMode":
        //   "First" -> First matcher that matches the target constitutes a successful match
        //   "All" -> All matchers defined in the "Matchers" array must match the target to constitute a successful match
        "MatcherMode": "First",

        // List of matchers to locate/find/match the target offset/value
        "Matchers": [
          {
            "Type": "Pattern",
            "Value": "4? 89 ?? ?? ?? ?? ??    4? 8D ?? ?? ?? ?? ??    E8 ?? ?? ?? ??    E9 ?? ?? ?? ??"
          }
        ],
        "SearchRange": {
          "Offset": 1331,
          "OffsetVariation": 64,
          "Size": 24,
          "SizeVariation": 64
        },
        "Print": {
          "Group": {
            "ID": "EngineRuntime"
          },
          "Name": "GNames"
        }
      }
    ]
  }
]
```

### Print Configuration:
- TODO

### Profiles Configuration:
- TODO

## License
- MIT
