#!/usr/bin/env python3
"""
Comprehensive CTI JSON to Markdown Converter

This script processes JSON files from various CTI sources and converts them 
to markdown format, ensuring ALL data from the JSON is captured in the output.
"""

import os
import json
import argparse
import time
from pathlib import Path
from typing import Dict, Any, List, Union, Optional
from tqdm import tqdm
import re


def clean_text(input_text: Union[str, Any]) -> str:
    """Clean and format text for markdown display."""
    if not input_text:
        return "Not specified"
    return ' '.join(str(input_text).split())


def format_list_items(items: List[str], prefix: str = "-") -> str:
    """Format list items for markdown display with specified prefix."""
    if not items:
        return "Not specified"
    formatted_items = [f"{prefix} {clean_text(str(item))}" for item in items if item]
    return '\n'.join(formatted_items) if formatted_items else "Not specified"


def detect_json_format(data: Dict[Any, Any]) -> str:
    """Detect the format/source of CTI JSON data."""
    # Threat actor format (VulnCheck style)
    if 'threat_actor_name' in data:
        return 'threat_actor'
    
    # STIX Bundle format
    if 'type' in data and data['type'] == 'bundle' and 'objects' in data:
        return 'stix_bundle'
    
    # MITRE ATT&CK format
    if 'objects' in data and isinstance(data['objects'], list):
        if data['objects'] and 'x_mitre' in str(data['objects'][0]):
            return 'mitre_attack'
        return 'stix_objects'
    
    return 'generic'


def extract_all_fields_comprehensive(data: Dict[Any, Any]) -> Dict[str, Any]:
    """Comprehensively extract ALL fields from JSON data regardless of format."""
    extracted = {
        'raw_data': {},
        'structured_fields': {},
        'all_keys': set(),
        'nested_data': {}
    }
    
    def process_value(key: str, value: Any, parent_path: str = "") -> Any:
        """Recursively process any value and categorize it appropriately."""
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
            # Process list items
            processed_list = []
            for i, item in enumerate(value):
                if isinstance(item, dict):
                    processed_list.append(process_dict(item, f"{full_path}[{i}]"))
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
    
    # Extract structured fields based on common patterns
    extracted['structured_fields'] = extract_structured_fields(data)
    
    return extracted


def extract_structured_fields(data: Dict[Any, Any]) -> Dict[str, Any]:
    """Extract commonly expected fields in a structured way."""
    fields = {}
    
    # Basic identification fields
    fields['name'] = (data.get('name') or data.get('threat_actor_name') or 
                     data.get('title') or data.get('label', ''))
    fields['id'] = (data.get('id') or data.get('mitre_id') or 
                   data.get('misp_id') or data.get('standard_id', ''))
    fields['type'] = (data.get('type') or data.get('entity_type') or 
                     data.get('category') or data.get('threat_type', ''))
    
    # Description fields
    fields['description'] = (data.get('description') or data.get('summary') or 
                           data.get('details', ''))
    
    # Temporal fields
    fields['created'] = (data.get('created') or data.get('date_added') or 
                        data.get('first_seen') or data.get('created_time', ''))
    fields['modified'] = (data.get('modified') or data.get('last_updated') or 
                         data.get('last_seen') or data.get('updated_time', ''))
    
    # Attribution and location
    fields['country'] = data.get('country', '')
    fields['attribution'] = data.get('attribution', '')
    
    # URLs and external links
    fields['malpedia_url'] = data.get('malpedia_url', '')
    fields['urls'] = []
    if 'urls' in data:
        fields['urls'] = data['urls'] if isinstance(data['urls'], list) else [data['urls']]
    
    # Clean empty fields
    fields = {k: v for k, v in fields.items() if v}
    
    return fields


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
        elif isinstance(value, list):
            if value:
                result.append(f"{indent}- **{key}:**")
                for item in value:
                    if isinstance(item, dict):
                        result.append(f"{indent}  - {format_dict_as_markdown(item, indent_level + 2)}")
                    else:
                        result.append(f"{indent}  - {clean_text(str(item))}")
        else:
            result.append(f"{indent}- **{key}:** {clean_text(str(value))}")
    
    return '\n'.join(result)


def generate_comprehensive_markdown(comprehensive_data: Dict[str, Any], format_type: str) -> str:
    """Generate comprehensive markdown content from all extracted data."""
    structured = comprehensive_data['structured_fields']
    raw_data = comprehensive_data['raw_data']
    
    name = clean_text(structured.get('name', 'Unknown Object'))
    obj_id = structured.get('id', '')
    obj_type = structured.get('type', 'unknown')
    
    # Create title with ID if available
    title = f"# {obj_id}: {name}" if obj_id and obj_id != name else f"# {name}"
    
    markdown_content = f"""{title}

## Overview
{clean_text(structured.get('description', 'Not specified'))}

## Object Type
{obj_type}

"""
    
    # Add all available structured information
    def add_section_if_present(section_title: str, data_key: str, data_source: Dict = None):
        nonlocal markdown_content
        source = data_source if data_source else raw_data
        if data_key in source and source[data_key]:
            value = source[data_key]
            if isinstance(value, list):
                markdown_content += f"""## {section_title}
{format_list_items(value)}

"""
            elif isinstance(value, dict):
                markdown_content += f"""## {section_title}
{format_dict_as_markdown(value)}

"""
            else:
                markdown_content += f"""## {section_title}
{clean_text(value)}

"""
    
    # Add sections for common threat actor fields
    add_section_if_present("Country", "country")
    add_section_if_present("MITRE ID", "mitre_id")
    add_section_if_present("MISP ID", "misp_id")
    add_section_if_present("Malpedia URL", "malpedia_url")
    add_section_if_present("Vendor Names for Threat Actors", "vendor_names_for_threat_actors")
    add_section_if_present("CVE References", "cve_references")
    add_section_if_present("Associated MITRE Attack Techniques", "associated_mitre_attack_techniques")
    add_section_if_present("Vendors and Products Targeted", "vendors_and_products_targeted")
    add_section_if_present("MITRE Attack Group", "mitre_attack_group")
    add_section_if_present("MISP Threat Actor", "misp_threat_actor")
    add_section_if_present("Related Actors", "related_actors")
    add_section_if_present("Targeted Countries", "targeted_countries")
    add_section_if_present("Targeted Industries", "targeted_industries")
    
    # Add comprehensive raw data section
    markdown_content += """## Complete Data Structure
The following section contains all available data from the original JSON:

```
"""
    
    markdown_content += format_dict_as_markdown(raw_data)
    markdown_content += """
```

"""
    
    # Add metadata
    metadata_items = []
    if structured.get('created'):
        metadata_items.append(f"**Created:** {structured['created']}")
    if structured.get('modified'):
        metadata_items.append(f"**Modified:** {structured['modified']}")
    if raw_data.get('date_added'):
        metadata_items.append(f"**Date Added:** {raw_data['date_added']}")
    
    if metadata_items:
        markdown_content += f"""
## Metadata
{chr(10).join(metadata_items)}

"""
    
    markdown_content += f"""---
*Generated from {format_type.replace('_', ' ').title()} CTI data*
*All available data from the original JSON has been included above*
"""
    
    return markdown_content


def process_json_array(data: List[Dict], json_file: str, output_dir: str) -> bool:
    """Process a JSON array containing multiple objects."""
    try:
        success_count = 0
        base_filename = os.path.splitext(os.path.basename(json_file))[0]
        
        for i, item in enumerate(data):
            if not isinstance(item, dict):
                continue
                
            # Get comprehensive extraction for each item
            comprehensive_data = extract_all_fields_comprehensive(item)
            
            # Detect format for each item
            format_type = detect_json_format(item)
            
            # Generate comprehensive markdown
            markdown_content = generate_comprehensive_markdown(comprehensive_data, format_type)
            
            # Create meaningful filename using name or index
            item_name = comprehensive_data['structured_fields'].get('name', f'item_{i+1}')
            # Clean filename
            safe_name = re.sub(r'[<>:"/\\|?*]', '_', item_name.replace(' ', '_'))
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
        
        # Get comprehensive extraction
        comprehensive_data = extract_all_fields_comprehensive(data)
        
        # Detect format
        format_type = detect_json_format(data)
        
        # Generate comprehensive markdown
        markdown_content = generate_comprehensive_markdown(comprehensive_data, format_type)
        
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


def process_directory(source_dir: str, output_dir: str):
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
        if process_json_file(str(json_file), str(output_path)):
            processed_count += 1
        else:
            error_count += 1
    
    total_time = time.time() - start_time
    total_files = len(json_files)
    
    # Count total output files
    total_output_files = 0
    for root, dirs, files in os.walk(output_path):
        total_output_files += len([f for f in files if f.endswith('.md')])
    
    print(f"\nConversion complete!")
    print(f"Successfully processed: {processed_count} JSON files")
    print(f"Total output files created: {total_output_files}")
    print(f"Errors encountered: {error_count} files")
    print(f"Total time: {total_time:.2f} seconds")


def main():
    parser = argparse.ArgumentParser(
        description="Convert CTI JSON files to comprehensive markdown format (captures ALL data)"
    )
    parser.add_argument(
        "source_dir",
        help="Source directory containing JSON files"
    )
    parser.add_argument(
        "output_dir", 
        nargs="?",
        default="cti_markdown_comprehensive",
        help="Output directory for markdown files (default: cti_markdown_comprehensive)"
    )
    
    args = parser.parse_args()
    
    print("Comprehensive CTI JSON to Markdown Converter")
    print("=" * 50)
    print(f"Source directory: {args.source_dir}")
    print(f"Output directory: {args.output_dir}")
    print("This converter captures ALL data from the original JSON files")
    
    process_directory(args.source_dir, args.output_dir)


if __name__ == "__main__":
    main()
