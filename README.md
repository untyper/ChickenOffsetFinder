# ChickenOffsetFinder
General purpose static offset finder for Windows programs (x64)

Dumps a programs memory and scans through the dump to find the defined target offsets.
This is an experimental project and is not intended for production use.

## Build
1. This project uses the hypervisor for memory reading operations, so make sure Intel Virtualization is enabled.
2. Build and run the `hv` driver. See the Dependencies section.
3. (Optional) This project already contains pre-built Zydis binaries however you can also build your own.
4. Launch `.sln` file and build (Visual Studio 2022)

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

This is the main configuration file that defines how and where target offsets/values are found.

```js
[
  {
    // Unique ID of region for internal implementation
    "RegionID": "Function_AllocateNameEntry",

    // "RegionType":
    //   "Function"
    //   "Section"
    "RegionType": "Function",

    // Defines the boundaries of the region. This is also used when locating the region with the anchor.
    "RegionRange": {
      "Size": 1628,       // Size of region
      "SizeVariation": 64 // Possible size variation between old and new versions of the binary
    },

    // Array of anchors. The offset finder iterates through each region
    // and tries to locate the anchors defined here within each region's boundaries.
    // The first region that contains ALL anchors within its boundaries (defined by RegionRange)
    // is selected as the target region at which offsets will be attempted to be located by Matchers.
    "Anchors": [
      // "Type":
      //   "String"
      //       Locate by string
      //   "Pattern"
      //       Locate by a string pattern (e.g. "D? AD ?? EE ??"), nibble wild cards are allowed.
      //   "PatternSubsequence"
      //       Locate by an array of string patterns. Gaps can exist between each string pattern in the array.
      //   "InstructionSequence"
      //       Locate by an array of basic ASM isntructions (e.g. "mov ?, [rip+?]").
      //       No gaps between each instruction.
      //   "InstructionSubsequence"
      //       Locate by an array of basic ASM isntructions.
      //       Gaps can exist between each instruction in the array.

      // Notes:
      //   The ASM instruction parser is very basic and only supports very basic instruction formats.
      //   The ASM instruction mnemonics should be defined inline with Zydis 4.x mappings.

      // Examples:
      {
        "Type": "String",
        "Value": "&APlantedTimeBombActor::OnBombIsDismantled"
      },
      {
        "Type": "Pattern",
        "Value": "D? AD ?? EE ??"
      },
      {
        "Type": "PatternSubsequence",
        "Value": [
          "D? AD ?? EE ??",
          "4? AE ?? EA ??",
          "48 AF 80 EB ??"
        ]
      },
      {
        "Type": "InstructionSequence",
        "Value": [
          "mov ?, ?",
          "lea ?, ?",
          "mov ?, [rip+?]"
        ]
      },
      {
        "Type": "InstructionSubsequence",
        "Value": [
          "call ?",
          "mov ?, 0x28",
          "jmp ?"
        ]
      }
    ],

    // "AccessType" (Determines how this region is accessed by the main finder loop):
    //   "Normal"
    //       Default. The region is accessed by the main finder loop.
    //   "XReference"
    //       The region is accessed by the XReference search handler.

    //  Consequently, if AccessType is "XReference", a search item must refer to this region by defining:
    //    "SearchType": "XReference"
    //    "NextRegion": {...}

    //  Read more about "NextRegion" below in the "SearchFor" array.
    "AccessType": "Normal",

    // List of search items. These define the type of offset/value to find and how to find them.
    "SearchFor": [
      {
        "SearchID": "GNames", // Unique ID of search item for internal implementation

        // "SearchType" (Type of search, determines the value/offset extracted):
        //   "Immediate"
        //   "Displacement"
        //   "Reference"
        //   "XReference"
        //   "TslDecryptor32"
        //   "TslDecryptor64"
        "SearchType": "Reference",

        // "MatcherMode" (Determines when a value is considered to be a match):
        //   "First"
        //       First matcher that matches the target constitutes a successful match
        //   "All"
        //       All matchers defined in the "Matchers" array must match the target to constitute a successful match
        "MatcherMode": "First",

        // List of matchers to locate the target offset/value within the region boundaries (defined by RegionRange) 
        "Matchers": [
          // "Type":
          //   "Pattern"
          //       Locate by a string pattern (e.g. "D? AD ?? EE ??"), nibble wild cards are allowed.
          //   "PatternSubsequence"
          //       Locate by an array of string patterns. Gaps can exist between each string pattern in the array.
          //   "InstructionSequence"
          //       Locate by an array of basic ASM isntructions (e.g. "mov ?, [rip+?]").
          //       No gaps between each instruction.
          //  "InstructionSubsequence"
          //       Locate by an array of basic ASM isntructions.
          //       Gaps can exist between each instruction in the array.

          // Notes:
          //   The ASM instruction parser is very basic and only supports very basic instruction formats.
          //   The ASM instruction mnemonics should be defined inline with Zydis 4.x mappings.
          //   Unlike Anchors, the matcher Type cannot be a String.

          // Examples:
          {
            "Type": "Pattern",
            "Value": "D? AD ?? EE ??"
          },
          {
            "Type": "PatternSubsequence",
            "Value": [
              "D? AD ?? EE ??",
              "4? AE ?? EA ??",
              "48 AF 80 EB ??"
            ]
          },
          {
            "Type": "InstructionSequence",
            "Value": [
              "mov ?, ?",
              "lea ?, ?",
              "mov ?, [rip+?]"
            ]
          },
          {
            "Type": "InstructionSubsequence",
            "Value": [
              "call ?",
              "mov ?, 0x28",
              "jmp ?"
            ]
          }
        ],

        // Search range within the region boundaries (defined by RegionRange)
        //  in which matchers are used to locate and extract the target value/offset.
        "SearchRange": {
          // Offset from base of region. If -sync flag is used, this will be updated to
          //  the offset at which our target value/offset was found.
          "Offset": 1331,

          // Size of search region (in bytes). This should be large enough to accomodate
          //  the size of the largest matcher in the Matchers array.
          "Size": 24,

          // Possible variation between binary updates
          "OffsetVariation": 64,
          "SizeVariation": 64
        },

        // If SearchType is XReference this refers to the next region (search items) to handle.
        // When an XReference offset has been found by the main finder loop,
        // it will be set as the base of the next region (XReferenced region).
        "NextRegion": {
          // ID of the next region to handle.
          // A region with this ID must already be defined, and it's AccessType must be XReference.
          "ID": "Function_AllocateNameEntry"
        },

        // "Print"
        //   Defines basic information on how to print the found offsets into a file.
        //   This information is required by the print configuration file.

        // Notes:
        //  "Print" should not be defined when SearchType is XReference,
        //  since XReferences in this file merely refer to a another region (also) defined in this file.

        "Print": {
          "Group": {
            // Group ID which is matched by it's equivalent within $STR / $VAR calls in the print configuration file.
            // This is crucial for printing the found offsets into the desired layout defined by the print configuration file.
            "ID": "EngineRuntime",

            // When there are multiple printables of the same group (ID), Index serves as the order of appearance
            //  within the print configurations code functions ($STR, $VAR).

            // The Index property is prioritized.
            // Any group members that don't define an Index are printed according to order of appearance in this file.
            "Index": 0
          },

          // The name/identifier of the variable/string printed to the final output file
          //  (e.g. uint64_t GNames = <FOUND_OFFSET>). This is currently only useful for $VAR.
          "Name": "GNames"
        }
      }
    ]
  }
]
```

### Print Configuration:

The print configuration file defines the layout of the final output (offsets) file.
It is for the most part self explanatory.

TODO: Document `Frame.Style` and `Frame.AlignContent`

```js
{
  "Head": {
    "ShowGeneratedByMessage": true,
    "UserNote": "Offsets are untested. Use at your own discretion.",
    
    "ShowProfile": true,
    "ShowBinaryVersion": true,
    "ShowDateGenerated": true
  },
  
  "Gap": 1, // Gap between Head and Body
  
  "Body": {
    "Gap": 1,  // Gap between each section

    "Sections": [
      {      
        "Header": {
          "Title": "EngineRuntime1",
          "Frame": {
            // "Style":
            //   "Borderless"
            //   "BorderBox"
            //   "BorderUp"
            //   "BorderDown"
            "Style": "BorderBox",

            // "AlignContent":
            //   "Left"
            //   "Center"
            //   "Right"
            "AlignContent": "Left",

            "BackgroundChar": null,
            "BorderChar": "-",
            "BorderWidth": 80,
            "Padding": 0
          }
        },
        
        "Gap": 1, // Gap between Header and Code
        
        "Code": [
          "$VAR(EngineRuntime,std::uint64_t,0x%llX)"
        ]
      },
      {      
        "Header": {
          "Title": "EngineRuntime2",
          "Frame": {
            "Style": "BorderBox",
            "AlignContent": "Left",
            "BackgroundChar": null,
            "BorderChar": "+",
            "BorderWidth": 80,
            "Padding": 0
          }
        },
        
        "Gap": 1, // Gap between Header and Code
        
        "Code": [
          "$STR(EngineRuntime,%s\n)"
        ]
      }
    ]
  }
}
```

### Profiles Configuration:

The profiles configuration file exists simply to semantically bind the search and print configuration files under an appropriate name.
This makes using the tool just slighly more convenient. See the Usage section above to know how to make use of this.

```js
{
  "UnrealEngineGame": {
    "SearchConfig": "Search.cof.json",
    "PrintConfig": "Print.cof.json"
  }
}
```

### Notes About Configuration Files:

This project uses `nlohmann/json` for configuration files. The project has explicitly configured it to ignore comments in the `.json` files.

## Dependencies
- https://github.com/nlohmann/json
- https://github.com/jonomango/hv
- https://github.com/zyantific/zydis (4.x)
- https://github.com/untyper/process-memory-module

## License
- MIT
