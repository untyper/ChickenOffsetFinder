# ChickenOffsetFinder

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

This documentation describes the structure and usage of a JSON-based search configuration for analyzing binary files. Each section specifies regions, anchors, matchers, and search parameters used to identify and extract specific offsets or references from binary data.

---

### Structure

### Top-Level Array

The configuration file consists of an array of objects, each defining a distinct search region within a binary.

---

### Region Object

Each `Region` object describes a specific area or functionality within the binary to be analyzed.

#### Fields:

* **RegionID** *(string)*: A unique identifier for the region.
* **RegionType** *(string)*: Type of the region (`Function`, `Section`).
* **RegionRange** *(object|null)*: Specifies the size of the region and its allowable variation.

  * **Size** *(integer)*: Exact size in bytes.
  * **SizeVariation** *(integer)*: Allowable variation in bytes.
* **Anchors** *(array|null)*: Optional references or patterns that identify the region.
* **SearchFor** *(array)*: Describes search actions within the region.

---

### Anchor Object

Defines a reference point to precisely identify regions.

#### Fields:

* **Type** *(string)*: Anchor type (`InstructionSequence`, `String`).
* **Value** *(string|array)*: Specific pattern or string value.
* **Index** *(integer, optional)*: Index of string anchor within the binary.

---

### SearchFor Object

Specifies what to search within a given region.

#### Fields:

* **SearchID** *(string)*: Unique identifier for this search.
* **SearchType** *(string)*: Type of search (`Immediate`, `Reference`, `Displacement`, `TslDecryptor32`, `TslDecryptor64`, `XReference`).
* **MatcherMode** *(string)*: Matching mode (`First`, etc.).
* **Matchers** *(array|null)*: Array of pattern matchers.
* **SearchRange** *(object)*: Specifies offset and size parameters.

  * **Offset** *(integer)*: Start offset within region.
  * **OffsetVariation** *(integer, optional)*: Allowable variation in offset.
  * **Size** *(integer, optional)*: Search size.
  * **SizeVariation** *(integer, optional)*: Allowable size variation.
* **Print** *(object)*: Output formatting instructions.

  * **Group** *(object)*: Categorization details.

    * **ID** *(string)*: Group identifier.
    * **Index** *(integer, optional)*: Sub-group index.
  * **Name** *(string)*: Name of the found element.
* **NextRegion** *(object, optional)*: Reference to the next search region by ID.

---

### Matcher Object

Specifies patterns to match within binary data.

#### Fields:

* **Type** *(string)*: Type of matcher (`Pattern`, `InstructionSequence`, `PatternSubsequence`).
* **Value** *(string|array)*: Specific byte patterns or instruction sequences.
* **Offset** *(integer, optional)*: Offset within the matched pattern.

---

### Examples

#### Example Region Definition:

```json
{
  "RegionID": "Function_Rename",
  "RegionType": "Function",
  "RegionRange": {
    "Size": 2742,
    "SizeVariation": 64
  },
  "Anchors": [
    {
      "Type": "String",
      "Value": "Cannot rename %s into Outer %s as it is not of type %s"
    }
  ],
  "SearchFor": [
    {
      "SearchID": "ClassPrivate",
      "SearchType": "Displacement",
      "MatcherMode": "First",
      "Matchers": [
        {
          "Type": "Pattern",
          "Value": "48 8B 49 ?? 48 33 CA"
        }
      ],
      "SearchRange": {
        "Offset": 111,
        "OffsetVariation": 32,
        "Size": 4,
        "SizeVariation": 32
      },
      "Print": {
        "Group": {
          "ID": "EngineOffsets.UObject"
        },
        "Name": "ClassPrivate"
      }
    }
  ]
}
```

#### Explanation:

* **RegionID**: "Function\_Rename"
* **Type**: Function region identified by the given string anchor.
* **SearchFor**: Searches for displacement identified by a specific byte pattern.

---

### Special Notes

* Patterns support wildcards (`??`) to match varying bytes.
This JSON structure provides powerful configuration flexibility for binary analysis tasks, enabling precise searches through complex binary data.


### Print Configuration:
- TODO

### Profiles Configuration:
- TODO

## License
- MIT
