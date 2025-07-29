# CTI JSON to Markdown Converter Suite

A comprehensive Python toolkit for converting Cyber Threat Intelligence (CTI) JSON files to optimally-chunked Markdown documents designed for RAG (Retrieval-Augmented Generation) systems and LLM knowledge corpus integration.

## Overview

This suite provides multiple specialized converters to transform various CTI formats into RAG-optimized markdown documents with intelligent chunking, semantic boundary preservation, and enhanced retrievability for cybersecurity AI applications.

## Converters Available

### `convert_cti_generic.py` - Universal CTI Converter
**Recommended for most use cases**
- **Multi-format support**: MITRE ATT&CK, STIX 2.x, OpenCTI, VulnCheck threat actors, and generic JSON
- **Auto-detection**: Intelligently identifies and adapts to different CTI formats
- **Comprehensive extraction**: Tactics, techniques, indicators, platforms, attribution, and metadata
- **Smart categorization**: Organizes output by object type for optimal RAG retrieval

### `convert_cti_comprehensive.py` - Complete Data Preservation
**For maximum data retention**
- **All-data capture**: Preserves every field from the original JSON
- **Nested structure handling**: Maintains complex relationships and hierarchies
- **Raw data sections**: Includes complete original data structure for reference
- **Format-agnostic**: Works with any JSON structure, regardless of CTI standard

### `convert_mitre.py` - MITRE ATT&CK Specialist
**Optimized for MITRE frameworks**
- **MITRE-specific processing**: Deep understanding of ATT&CK taxonomy
- **Advanced chunking**: 800-token chunks with 22% overlap for attack chain preservation
- **Relationship preservation**: Maintains technique-to-tactic-to-mitigation mappings
- **ICS/Enterprise support**: Handles both Industrial Control Systems and Enterprise frameworks

### `test_script.py` - Validation Framework
**Quality assurance and testing**
- **Representative sampling**: Tests conversion on diverse file samples
- **Performance estimation**: Predicts processing time for full datasets
- **Token analysis**: Evaluates chunking effectiveness before full conversion
- **Quality validation**: Verifies output format and content accuracy

## RAG Optimization Features

### Intelligent Chunking Strategy
- **Optimal token sizing**: 800-token chunks ideal for embedding models
- **Semantic boundaries**: Preserves paragraph and section structure
- **Cybersecurity-aware overlap**: 22% overlap maintains attack chain relationships
- **Chunk metadata**: Headers with token counts and sequence information

### Enhanced Retrievability
- **Structured formatting**: Consistent markdown structure across all converters
- **Cross-reference preservation**: Maintains MITRE IDs, external references, and relationships
- **Metadata enrichment**: Temporal data, confidence scores, and attribution
- **Categorical organization**: Separates by object type for targeted retrieval

### LLM Integration Ready
- **Open WebUI compatible**: Optimized for popular RAG platforms
- **Vector database friendly**: Clean, consistent text for embedding generation
- **Context preservation**: Maintains technical accuracy while improving readability
- **Progressive disclosure**: Hierarchical information structure

## Usage Examples

### Quick Start - Universal Converter
```bash
# Convert mixed CTI formats (recommended)
python convert_cti_generic.py /path/to/cti/data

# With custom output directory
python convert_cti_generic.py /path/to/cti/data ./rag_corpus
```

### MITRE ATT&CK Conversion
```bash
# Test first (recommended)
python test_script.py /path/to/mitre/ics-attack/ --sample-size 20

# Convert full dataset with chunking
python convert_mitre.py /path/to/mitre/ics-attack/
```

### Complete Data Preservation
```bash
# Capture ALL JSON data for comprehensive analysis
python convert_cti_comprehensive.py /path/to/threat/data
```

### Threat Actor Intelligence
```bash
# Convert VulnCheck or similar threat actor feeds
python convert_cti_generic.py /path/to/threat/actors ./actor_corpus
```

## Output Structure

The converters create organized, RAG-optimized directory structures:

```
output_directory/
├── attack-pattern/          # MITRE techniques (T####)
│   ├── T0817-Drive-by-Compromise.md
│   └── T0818-Engineering-Workstation_chunk_1.md
├── course-of-action/        # MITRE mitigations (M####)
├── intrusion-set/          # Threat groups (G####)
├── malware/                # Software/tools (S####)
├── indicator/              # IOCs and indicators
├── threat-actor/           # Threat actor profiles
└── [additional-types]/     # Other CTI object types
```

## Supported CTI Formats

| Format | Detection | Key Features |
|--------|-----------|--------------|
| **MITRE ATT&CK** | Objects with `x_mitre_*` fields | Techniques, tactics, mitigations, groups |
| **STIX 2.x** | `type: "bundle"` or STIX objects | Indicators, malware, attack patterns |
| **OpenCTI** | `entity_type`, `standard_id` fields | Intelligence objects and relationships |
| **VulnCheck** | `threat_actor_name` field | Threat actor profiles and attribution |
| **Generic CTI** | Threat intel patterns | IOCs, TTPs, campaign data |
| **Custom JSON** | Fallback processing | Any structured threat data |

## RAG Integration Workflow

1. **Convert CTI data** using appropriate converter
2. **Upload markdown files** to RAG system (Open WebUI, LangChain, etc.)
3. **Configure embedding model** (recommend cybersecurity-specific models)
4. **Set chunking parameters** to match converter output (800 tokens, 22% overlap)
5. **Enable retrieval** for threat hunting and analysis workflows

## Performance Metrics

### Processing Speed
- **Generic converter**: ~100-200 files/second
- **MITRE converter**: ~200-500 files/second  
- **Comprehensive converter**: ~50-100 files/second (due to full data capture)

### Typical Datasets
- **MITRE ICS ATT&CK**: 1,651 files → ~8-15 seconds
- **Enterprise ATT&CK**: ~5,000 files → ~30-60 seconds
- **Mixed CTI feeds**: Variable based on complexity

### Chunking Statistics
- **Average chunks per large file**: 2-3 chunks
- **Files requiring chunking**: ~10-20% of typical datasets
- **Token distribution**: 200-800 tokens per chunk (optimal for RAG)

## Requirements

```bash
# Install required packages
pip install -r requirements.txt

# Or manually:
pip install tqdm
```

**System Requirements:**
- Python 3.6+ (for pathlib and f-strings)
- 4GB+ RAM for large datasets (Enterprise ATT&CK)
- SSD storage recommended for optimal I/O performance

## Advanced Features

### Testing and Validation
- **Smart sampling**: Representative file selection across directories
- **Performance prediction**: Estimates full dataset processing time
- **Quality assurance**: Validates output format and content accuracy
- **Token analysis**: Predicts chunking requirements and distribution

### Error Handling
- **Graceful degradation**: Continues processing on individual file errors
- **Detailed logging**: Progress bars with error counts and file tracking
- **Format detection**: Automatic fallback for unrecognized formats
- **Validation checks**: Ensures output quality and completeness

### Customization Options
- **Configurable chunking**: Adjustable token limits and overlap ratios
- **Output formatting**: Customizable markdown templates
- **Filtering options**: Process specific object types or directories
- **Metadata preservation**: Maintains original source attribution

## Use Cases

### Security Operations
- **Threat hunting**: Enrich analyst investigations with comprehensive CTI
- **Incident response**: Correlate findings with known attack patterns
- **Intelligence analysis**: Build searchable knowledge bases from multiple sources
- **Training materials**: Generate technique-specific learning content

### AI/ML Applications
- **RAG systems**: Power AI assistants with structured threat intelligence
- **Chatbots**: Enable natural language queries against CTI databases
- **Automated analysis**: Feed structured data into security ML pipelines
- **Research platforms**: Create comprehensive cybersecurity knowledge graphs

### Compliance and Reporting
- **Framework mapping**: Cross-reference controls with MITRE techniques
- **Risk assessment**: Correlate threats with organizational vulnerabilities
- **Executive briefings**: Generate executive-level threat summaries
- **Audit preparation**: Maintain comprehensive threat intelligence records

## Contributing

This toolkit is designed for practical cybersecurity applications. Contributions welcome for:

- **Additional CTI format support** (TAXII, YARA, custom feeds)
- **Enhanced chunking algorithms** (semantic segmentation, relationship-aware)
- **RAG system integrations** (vector databases, embedding optimizations)
- **Performance improvements** (parallel processing, memory optimization)
- **Quality enhancements** (validation, error recovery, format detection)

## License

Open source toolkit for cybersecurity and threat intelligence applications. Designed for security operations centers, threat intelligence teams, and cybersecurity researchers.

---

*Optimized for RAG systems, LLM knowledge integration, and cybersecurity AI applications*
