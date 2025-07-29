#!/usr/bin/env python3
"""
Comprehensive CTI JSON to Markdown Converter v3

Optimized version - eliminates redundancies and improves performance.
Full PEP8 compliance with enhanced efficiency and better field mapping.
"""

import argparse
import json
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from tqdm import tqdm


def clean_text(input_text: Union[str, Any]) -> str:
    """Clean and format text for markdown display."""
    if not input_text:
        return "Not specified"
    
    # Handle strings that start with ": " (common in security bulletins)
    text_str = str(input_text).strip()
    if text_str.startswith(': '):
        text_str = text_str[2:]  # Remove leading ": "
    
    return ' '.join(text_str.split()) if text_str else "Not specified"


def format_list_items(items: List[str], prefix: str = "-") -> str:
    """Format list items for markdown display with specified prefix."""
    if not items:
        return "Not specified"
    formatted_items = [f"{prefix} {clean_text(str(item))}" 
                      for item in items if item]
    return '\n'.join(formatted_items) if formatted_items else "Not specified"


def format_dict_as_markdown(data: Dict[str, Any], indent_level: int = 0) -> str:
    """Format dictionary data as readable markdown."""
    if not data:
        return "No data available"

    result = []
    indent = "  " * indent_level

    for key, value in data.items():
        if isinstance(value, dict):
            result.append(f"{indent}- **{key}:**")
            result.append(format_dict_as_markdown(value, indent_level + 1))
        elif isinstance(value, list) and value:
            result.append(f"{indent}- **{key}:**")
            for item in value:
                if isinstance(item, dict):
                    nested = format_dict_as_markdown(item, indent_level + 2)
                    result.append(f"{indent}  - {nested}")
                else:
                    result.append(f"{indent}  - {clean_text(str(item))}")
        else:
            result.append(f"{indent}- **{key}:** {clean_text(str(value))}")

    return '\n'.join(result)


def format_section_content(value: Any) -> str:
    """Unified formatting for all section types - eliminates redundancy."""
    if isinstance(value, list):
        return format_list_items(value)
    elif isinstance(value, dict):
        return format_dict_as_markdown(value)
    else:
        return clean_text(value)


def _extract_object_type(data: Dict[Any, Any]) -> str:
    """Extract and determine object type with better mapping."""
    # Check standard CTI type fields first
    obj_type = (data.get('type') or data.get('entity_type') or
                data.get('category') or data.get('threat_type', ''))
    
    if obj_type:
        return obj_type
    
    # Intelligent type detection based on data structure
    if 'title' in data and 'summary' in data and ('url' in data or 'cve' in data):
        return 'security-bulletin'
    
    if 'threat_actor_name' in data:
        return 'threat-actor'
    
    if 'x_mitre' in str(data):
        return 'mitre-object'
    
    if 'attack-pattern' in str(data) or 'technique' in str(data).lower():
        return 'attack-pattern'
    
    if 'indicators' in data or 'iocs' in data:
        return 'indicator'
    
    return 'cti-object'  # Better than 'unknown'


def _extract_description(data: Dict[Any, Any]) -> str:
    """Extract description with improved field mapping."""
    # Try multiple description fields in order of preference
    description_fields = ['description', 'summary', 'details', 'overview', 'abstract']
    
    for field in description_fields:
        if field in data and data[field]:
            desc = str(data[field]).strip()
            # Handle descriptions that start with ": "
            if desc.startswith(': '):
                desc = desc[2:]
            if desc:  # Only return if we have actual content
                return desc
    
    return ''  # Return empty string instead of None


def detect_json_format(data: Dict[Any, Any]) -> str:
    """Detect the format/source of CTI JSON data."""
    # Order by most common first for efficiency
    if 'threat_actor_name' in data:
        return 'threat_actor'
    
    # Security bulletins/advisories (Tailscale, vendor bulletins, etc.)
    if 'title' in data and 'summary' in data and ('url' in data or 'cve' in data):
        return 'security_bulletin'
    
    if 'objects' in data and isinstance(data['objects'], list):
        if data['objects'] and 'x_mitre' in str(data['objects'][0]):
            return 'mitre_attack'
        return 'stix_objects'
    
    if 'type' in data and data['type'] == 'bundle' and 'objects' in data:
        return 'stix_bundle'
    
    if 'entity_type' in data or 'standard_id' in data:
        return 'opencti'
    
    if any(key in data for key in ['threat_type', 'indicators', 'ttps', 'iocs']):
        return 'generic_threat'

    stix_types = ['indicator', 'malware', 'attack-pattern', 'intrusion-set']
    if ('type' in data and 'id' in data and data['type'] in stix_types):
        return 'stix_object'

    return 'generic'


def extract_all_fields_comprehensive(data: Dict[Any, Any]) -> Dict[str, Any]:
    """Comprehensively extract ALL fields from JSON data."""
    extracted = {
        'raw_data': {},
        'structured_fields': {},
        'all_keys': set(),
        'nested_data': {}
    }

    def process_value(key: str, value: Any, parent_path: str = "") -> Any:
        """Recursively process any value."""
        full_path = f"{parent_path}.{key}" if parent_path else key
        extracted['all_keys'].add(full_path)

        if value is None or value == "":
            return None
        elif isinstance(value, str):
            return clean_text(value)
        elif isinstance(value, (int, float, bool)):
            return value
        elif isinstance(value, list):
            if not value:
                return []
            processed_list = []
            for i, item in enumerate(value):
                if isinstance(item, dict):
                    processed_list.append(
                        process_dict(item, f"{full_path}[{i}]")
                    )
                else:
                    processed_item = process_value(f"item_{i}", item, full_path)
                    if processed_item is not None:
                        processed_list.append(processed_item)
            return processed_list if processed_list else []
        elif isinstance(value, dict):
            return process_dict(value, full_path)
        else:
            return str(value)

    def process_dict(obj: Dict[Any, Any], parent_path: str = "") -> Dict[str, Any]:
        """Process dictionary recursively."""
        processed = {}
        for k, v in obj.items():
            key_str = str(k)
            if v is not None and v != "" and v != []:
                processed_val = process_value(key_str, v, parent_path)
                if processed_val is not None:
                    processed[key_str] = processed_val
        return processed

    # Process the entire data structure
    extracted['raw_data'] = process_dict(data)
    extracted['structured_fields'] = extract_structured_fields(data)

    return extracted


def extract_structured_fields(data: Dict[Any, Any]) -> Dict[str, Any]:
    """Extract commonly expected fields efficiently with improved mapping."""
    # Enhanced extraction with better field mapping
    fields = {
        'name': (data.get('name') or data.get('threat_actor_name') or
                 data.get('title') or data.get('label', '')),
        'id': (data.get('id') or data.get('mitre_id') or
               data.get('misp_id') or data.get('standard_id', '')),
        'type': _extract_object_type(data),
        'description': _extract_description(data),
        'created': (data.get('created') or data.get('date_added') or
                   data.get('first_seen') or data.get('created_time', '')),
        'modified': (data.get('modified') or data.get('last_updated') or
                    data.get('last_seen') or data.get('updated_time', '')),
        'country': data.get('country', ''),
        'attribution': data.get('attribution', ''),
        'malpedia_url': data.get('malpedia_url', '')
    }
    
    # Handle URLs efficiently
    if 'urls' in data:
        fields['urls'] = (data['urls'] if isinstance(data['urls'], list) 
                         else [data['urls']])
    elif 'url' in data:  # Handle single URL field
        fields['urls'] = [data['url']]
    else:
        fields['urls'] = []

    # Return only non-empty fields
    return {k: v for k, v in fields.items() if v}


def generate_comprehensive_markdown(comprehensive_data: Dict[str, Any], 
                                  format_type: str) -> str:
    """Generate optimized markdown content using list-based building."""
    structured = comprehensive_data['structured_fields']
    raw_data = comprehensive_data['raw_data']
    
    # Cache cleaned values to avoid redundant processing
    name = clean_text(structured.get('name', 'Unknown Object'))
    obj_id = structured.get('id', '')
    obj_type = structured.get('type', 'unknown')
    description = clean_text(structured.get('description', 'Not specified'))

    # Create title with ID if available
    title = f"# {obj_id}: {name}" if obj_id and obj_id != name else f"# {name}"

    # Use list-based building for optimal performance
    content_parts = [
        f"{title}\n\n## Overview\n{description}\n\n## Object Type\n{obj_type}\n"
    ]

    # Optimized section mapping reduces code duplication
    SECTIONS = {
        "Country": "country",
        "MITRE ID": "mitre_id", 
        "MISP ID": "misp_id",
        "Malpedia URL": "malpedia_url",
        "URLs": "urls",
        "CVE References": "cve",
        "Vendor Names for Threat Actors": "vendor_names_for_threat_actors",
        "Associated MITRE Attack Techniques": "associated_mitre_attack_techniques",
        "Vendors and Products Targeted": "vendors_and_products_targeted",
        "MITRE Attack Group": "mitre_attack_group",
        "MISP Threat Actor": "misp_threat_actor",
        "Related Actors": "related_actors",
        "Targeted Countries": "targeted_countries",
        "Targeted Industries": "targeted_industries"
    }

    # Single loop with unified formatting eliminates redundancy
    for section_title, data_key in SECTIONS.items():
        value = raw_data.get(data_key)
        if value:
            section_content = format_section_content(value)
            content_parts.append(f"## {section_title}\n{section_content}\n")

    # Add comprehensive raw data section
    content_parts.extend([
        "## Complete Data Structure",
        "The following section contains all available data from the original JSON:\n",
        "```",
        format_dict_as_markdown(raw_data),
        "```\n"
    ])

    # Build metadata efficiently
    metadata_items = []
    metadata_fields = [
        ('created', 'Created'),
        ('modified', 'Modified')
    ]
    
    for field_key, label in metadata_fields:
        if structured.get(field_key):
            metadata_items.append(f"**{label}:** {structured[field_key]}")
    
    if raw_data.get('date_added'):
        metadata_items.append(f"**Date Added:** {raw_data['date_added']}")

    if metadata_items:
        content_parts.extend([
            "## Metadata",
            '\n'.join(metadata_items) + '\n'
        ])

    # Add footer
    format_title = format_type.replace('_', ' ').title()
    content_parts.extend([
        "---",
        f"*Generated from {format_title} CTI data*",
        "*All available data from the original JSON has been included above*"
    ])

    return '\n'.join(content_parts)


def process_json_array(data: List[Dict], json_file: str, 
                      output_dir: str) -> bool:
    """Process a JSON array containing multiple objects."""
    try:
        success_count = 0
        base_filename = os.path.splitext(os.path.basename(json_file))[0]

        for i, item in enumerate(data):
            if not isinstance(item, dict):
                continue

            # Get comprehensive extraction for each item
            comprehensive_data = extract_all_fields_comprehensive(item)
            format_type = detect_json_format(item)
            markdown_content = generate_comprehensive_markdown(
                comprehensive_data, format_type
            )

            # Create meaningful filename using name or index
            item_name = comprehensive_data['structured_fields'].get(
                'name', f'item_{i+1}'
            )
            # Clean filename efficiently
            safe_name = re.sub(r'[<>:"/\\|?*]', '_', 
                             item_name.replace(' ', '_'))
            output_filename = f"{base_filename}_{safe_name}.md"
            output_file = os.path.join(output_dir, output_filename)

            # Create output directory
            os.makedirs(output_dir, exist_ok=True)

            # Write markdown file
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(markdown_content)

            success_count += 1

        return success_count > 0

    except Exception as e:
        print(f"Error processing array in {json_file}: {str(e)}")
        return False


def process_json_file(json_file: str, output_dir: str) -> bool:
    """Process a single JSON file and convert to markdown."""
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Handle root-level arrays (common in threat intel feeds)
        if isinstance(data, list):
            return process_json_array(data, json_file, output_dir)

        # Process single object
        comprehensive_data = extract_all_fields_comprehensive(data)
        format_type = detect_json_format(data)
        markdown_content = generate_comprehensive_markdown(
            comprehensive_data, format_type
        )

        # Determine output path
        rel_path = os.path.relpath(json_file, os.path.dirname(json_file))
        output_file = os.path.join(output_dir, rel_path.replace('.json', '.md'))

        # Create output directory
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        # Write markdown file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(markdown_content)

        return True

    except Exception as e:
        print(f"Error processing {json_file}: {str(e)}")
        return False


def print_detailed_statistics(output_path: str) -> None:
    """Print detailed statistics about the converted files."""
    print("\n" + "=" * 60)
    print("CONVERSION STATISTICS")
    print("=" * 60)

    # Count total output files efficiently
    total_md_files = sum(
        len([f for f in files if f.endswith('.md')])
        for _, _, files in os.walk(output_path)
    )

    print(f"\nTotal markdown files created: {total_md_files}")
    print("=" * 60)


def process_directory(source_dir: str, output_dir: str) -> None:
    """Process all JSON files in a directory."""
    source_path = Path(source_dir)
    output_path = Path(output_dir)

    if not source_path.exists():
        print(f"Error: Source directory '{source_dir}' does not exist")
        return

    # Create output directory
    output_path.mkdir(parents=True, exist_ok=True)

    # Find all JSON files
    json_files = list(source_path.rglob("*.json"))

    if not json_files:
        print(f"No JSON files found in {source_dir}")
        return

    print(f"\nScanning directory for JSON files...")
    print(f"Found {len(json_files)} JSON files to process")

    # Process files with progress bar
    processed_count = 0
    error_count = 0
    start_time = time.time()

    for json_file in tqdm(json_files, desc="Converting files", unit="files"):
        # Maintain directory structure in output
        rel_path = json_file.relative_to(source_path)
        output_file_dir = output_path / rel_path.parent
        output_file_dir.mkdir(parents=True, exist_ok=True)

        if process_json_file(str(json_file), str(output_file_dir)):
            processed_count += 1
        else:
            error_count += 1

    total_time = time.time() - start_time
    total_files = len(json_files)

    # Count total output files
    total_output_files = sum(
        len([f for f in files if f.endswith('.md')])
        for _, _, files in os.walk(output_path)
    )

    print(f"\nConversion complete!")
    print(f"Successfully processed: {processed_count} JSON files")
    print(f"Total output files created: {total_output_files}")
    print(f"Errors encountered: {error_count} files")
    print(f"Total time: {total_time:.2f} seconds")
    print(f"Average time per JSON file: {total_time/total_files:.3f} seconds")

    if error_count > 0:
        print(f"\nNote: {error_count} files had errors. "
              f"Check the output above for details.")

    print_detailed_statistics(output_dir)


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Convert CTI JSON files to comprehensive markdown format "
                   "(captures ALL data) - v3 with enhanced field mapping"
    )
    parser.add_argument(
        "source_dir",
        help="Source directory containing JSON files"
    )
    parser.add_argument(
        "output_dir", 
        nargs="?",
        default="cti_markdown_comprehensive_v3",
        help="Output directory for markdown files "
             "(default: cti_markdown_comprehensive_v3)"
    )
    
    args = parser.parse_args()
    
    print("Comprehensive CTI JSON to Markdown Converter v3")
    print("=" * 50)
    print(f"Source directory: {args.source_dir}")
    print(f"Output directory: {args.output_dir}")
    print("Enhanced field mapping for security bulletins and CTI data")
    
    process_directory(args.source_dir, args.output_dir)


if __name__ == "__main__":
    main()
