# CTI JSON to Markdown Converter

A powerful Python tool for converting Cyber Threat Intelligence (CTI) JSON files to well-formatted Markdown documents. Supports multiple CTI formats including MITRE ATT&CK, STIX, OpenCTI, and custom threat intelligence data.

## Features

- **Multi-format support**: MITRE ATT&CK, STIX 2.x, OpenCTI, and generic JSON
- **Auto-detection**: Automatically detects and adapts to different JSON formats
- **Comprehensive extraction**: Extracts tactics, techniques, indicators, platforms, and metadata
- **Clean output**: Organized directory structure with detailed statistics
- **Batch processing**: Processes entire directories with progress tracking
- **Flexible**: Handles both standard and custom CTI data formats

## Scripts

### `convert_cti_generic.py` (Recommended)
Enhanced universal converter that supports multiple CTI formats:
- MITRE ATT&CK (full compatibility)
- STIX 2.x bundles and objects
- OpenCTI exports
- Generic threat intelligence JSON
- Custom formats with fallback processing

### `convert_mitre.py` (Legacy)
Original converter optimized specifically for MITRE ATT&CK data.

## Usage

### Basic Usage
```bash
# Convert with default output directory (cti_markdown_output/)
python convert_cti_generic.py /path/to/cti/json/files

# Convert with custom output directory
python convert_cti_generic.py /path/to/cti/json/files /path/to/output
```

### Examples
```bash
# Convert MITRE ATT&CK data
python convert_cti_generic.py ./mitre_attack_data

# Convert mixed CTI formats
python convert_cti_generic.py ./multi_source_cti ./converted_docs

# Convert STIX bundles
python convert_cti_generic.py ./stix_data ./stix_markdown
```

## Output Structure

The converter creates organized directory structures:
```
cti_markdown_output/
├── attack-pattern/          # MITRE techniques
├── malware/                 # Malware descriptions
├── intrusion-set/           # Threat actor groups  
├── campaign/                # Threat campaigns
├── indicator/               # IOCs and indicators
└── [other-categories]/      # Additional object types
```

## Supported Fields

The converter intelligently extracts and maps fields across formats:

- **Names/Titles**: `name`, `title`
- **Descriptions**: `description`, `summary`
- **Identifiers**: `id`, `external_id`, `mitre_id`
- **Classifications**: `type`, `labels`, `categories`
- **Technical Data**: `platforms`, `tactics`, `techniques`
- **Indicators**: `indicators`, `iocs`, `pattern`
- **Metadata**: `created`, `modified`, `confidence`
- **Relationships**: `external_references`, `aliases`

## Output Format

Each converted file includes:
- **Title with ID** (when available)
- **Overview/Description**
- **Object type and metadata**
- **Organized sections** (tactics, platforms, indicators, etc.)
- **External references**
- **Source attribution**

## Requirements
- Python 3.6+
- Required packages: `json`, `argparse`, `pathlib`, `tqdm`

## Installation
```bash
# Clone or download the scripts
# Install dependencies (if needed)
pip install tqdm
```

## Statistics Output

Both scripts provide detailed conversion statistics:
- File counts by category
- Processing performance metrics
- Top categories by volume
- Directory structure overview

## License
This project is provided as-is for cybersecurity and threat intelligence use cases.
