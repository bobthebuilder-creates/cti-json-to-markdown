# CTI JSON to Markdown Converter v2 🚀

A comprehensive Python tool for converting Cyber Threat Intelligence (CTI) JSON files to detailed Markdown documents. **Ensures ALL data from the original JSON is captured** in the output, making it perfect for threat intelligence analysis and documentation.

## ✨ **NEW in v2: Fully Refactored & Production-Ready**
- **🔧 Complete PEP8 Compliance**: All imports properly organized, code follows Python style guidelines
- **📝 Enhanced Type Safety**: Comprehensive type hints throughout all modules
- **⚡ Performance Optimized**: Eliminated redundancies, improved efficiency
- **🛡️ Robust Error Handling**: Better exception handling and graceful error recovery
- **📚 Professional Documentation**: Enhanced docstrings and inline comments

## Features

- **Complete data preservation**: Captures ALL fields from JSON - no information is lost
- **Comprehensive extraction**: Recursively processes all nested data structures  
- **Multi-format support**: MITRE ATT&CK, STIX, OpenCTI, threat actors, and any JSON
- **Auto-detection**: Automatically detects and adapts to different JSON formats
- **Rich output**: Structured sections plus complete raw data for verification
- **Batch processing**: Processes entire directories with progress tracking
- **Individual files**: Creates separate markdown files for each threat actor/object

## Scripts

### `convert_cti_comprehensive_v2.py` (Recommended) 🌟
**The main comprehensive converter that ensures ALL data is captured:**
- Complete data extraction from any JSON structure
- Threat actor feeds with full MISP metadata, MITRE techniques, CVE references
- Structured presentation with raw data preservation
- Perfect for VulnCheck, MISP, and complex threat intelligence feeds
- **✨ v2 Features**: PEP8 compliant, full type hints, optimized performance

### `convert_cti_generic_v2.py` (Alternative) ⚡
Standard converter with basic field extraction for common CTI formats.
- **✨ v2 Features**: Enhanced error handling, improved code quality

### `convert_mitre_v2.py` (Specialized) 🎯
Converter optimized specifically for MITRE ATT&CK data.
- **✨ v2 Features**: Better chunking algorithms, robust processing

## Usage

### Comprehensive Conversion (Recommended)
```bash
# Convert with comprehensive data extraction (v2 - Enhanced!)
python3 convert_cti_comprehensive_v2.py /path/to/cti/json/files [output_directory]

# Example: Process threat actor feeds with full detail
python3 convert_cti_comprehensive_v2.py ../CTI/vulcheck/ comprehensive_output/
```

### Standard Conversion
```bash
# Convert with basic field extraction (v2 - Improved!)
python3 convert_cti_generic_v2.py /path/to/cti/json/files [output_directory]
```

### MITRE ATT&CK Conversion
```bash
# Convert MITRE ATT&CK data with advanced chunking (v2 - Optimized!)
python3 convert_mitre_v2.py /path/to/mitre/json/files [output_directory]
```

## Comprehensive Output Features

The comprehensive converter creates markdown files with:

### Structured Sections
- **Overview**: Basic information and description
- **Object Type**: CTI object classification
- **Country**: Attribution information
- **MITRE/MISP IDs**: Cross-reference identifiers
- **Malpedia URL**: External reference links
- **Vendor Names**: All associated vendor attributions
- **CVE References**: Complete vulnerability references with URLs and dates
- **MITRE Attack Techniques**: Full technique details with tactics and sub-techniques
- **MISP Threat Actor Data**: Complete metadata including references and synonyms
- **Related Actors**: Associated threat groups and similarities
- **Targeted Vendors/Products**: Complete targeting information

### Complete Data Structure
- **Raw JSON Data**: Entire original JSON structure in readable format
- **All Fields Preserved**: Every field from the original JSON is included
- **Nested Data**: Complex structures properly formatted and accessible

## Example Output Comparison

**Standard converter output for Suckfly:**
```
# G0039: Suckfly
## Overview
Threat actor active since 2016-03-15
## Country
CN
## Known Aliases
- APT22
```

**Comprehensive converter output for Suckfly:**
```
# G0039: Suckfly
## Country
CN
## MITRE ID
G0039
## MISP ID
5abb12e7-5066-4f84-a109-49a037205c76
## Malpedia URL
https://malpedia.caad.fkie.fraunhofer.de/actor/apt22
## MITRE Attack Group
- Full technique mappings (T1003, T1046, T1059, T1078, T1553)
- Complete tactic associations
- Detailed descriptions
## MISP Threat Actor
- Attribution confidence: 50
- Complete reference list (7+ sources)
- Synonyms: G0039, Suckfly, BRONZE OLIVE, Group 46
- Related actor mappings
## Complete Data Structure
[Full original JSON preserved in readable format]
```

## Supported Formats

- **Threat Actors** (comprehensive): VulnCheck, MISP, custom feeds
- **MITRE ATT&CK**: Enterprise, ICS, Mobile frameworks
- **STIX**: STIX 2.0/2.1 bundles and objects
- **OpenCTI**: Entity exports
- **Generic JSON**: Any structured threat intelligence data

## Requirements

- Python 3.6+
- Dependencies: Install with `pip install -r requirements.txt`

## Installation

1. Clone or download the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Run the comprehensive converter on your CTI data

## Code Quality & Standards

✅ **PEP8 Compliant**: All scripts follow Python style guidelines
✅ **Type Hints**: Full type annotations for better code maintainability
✅ **Comprehensive Documentation**: Detailed docstrings and inline comments
✅ **Error Handling**: Robust exception handling and graceful error recovery
✅ **Performance Optimized**: Eliminated redundancies and improved efficiency
✅ **Clean Architecture**: Organized imports, proper function structure

## Key Benefits

1. **No Data Loss**: Every piece of information from the original JSON is preserved
2. **Rich Intelligence**: Extracts complex metadata, relationships, and technical details
3. **Verification**: Complete raw data section allows verification against original
4. **Universal**: Works with any JSON format, not just specific schemas
5. **Production Ready**: Handles large datasets (380+ threat actors in ~5 seconds)
6. **Professional Quality**: Clean, maintainable code following industry best practices

## License

This project is open source and available for cybersecurity and threat intelligence use cases.
