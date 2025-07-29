#!/usr/bin/env python3
"""
Generic CTI JSON to Markdown Converter

This script processes JSON files from various CTI sources and converts them 
to markdown format. It supports MITRE ATT&CK, STIX, OpenCTI, and custom formats.
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
    return ' '.join(str(input_text).split())


def format_list_items(items: List[str], prefix: str = "-") -> str:
    """Format list items for markdown display with specified prefix."""
    if not items:
        return "Not specified"
    formatted_items = [f"{prefix} {clean_text(str(item))}" for item in items if item]
    return '\n'.join(formatted_items) if formatted_items else "Not specified"


def detect_json_format(data: Dict[Any, Any]) -> str:
    """Detect the format/source of CTI JSON data."""
    # STIX Bundle format
    if 'type' in data and data['type'] == 'bundle' and 'objects' in data:
        return 'stix_bundle'
    
    # MITRE ATT&CK format
    if 'objects' in data and isinstance(data['objects'], list):
        if data['objects'] and 'x_mitre' in str(data['objects'][0]):
            return 'mitre_attack'
        return 'stix_objects'
    
    # OpenCTI format indicators
    if 'entity_type' in data or 'standard_id' in data:
        return 'opencti'
    
    # Threat actor format (VulnCheck style)
    if 'threat_actor_name' in data:
        return 'threat_actor'
    
    # Generic threat intel format
    if any(key in data for key in ['threat_type', 'indicators', 'ttps', 'iocs']):
        return 'generic_threat'
    
    # STIX single object
    if 'type' in data and 'id' in data and data['type'] in ['indicator', 'malware', 'attack-pattern', 'intrusion-set']:
        return 'stix_object'
    
    return 'generic'


def extract_common_fields(data: Dict[Any, Any], format_type: str) -> Dict[str, Any]:
    """Extract common CTI fields regardless of format."""
    fields = {
        'name': '',
        'description': '',
        'type': '',
        'id': '',
        'aliases': [],
        'labels': [],
        'platforms': [],
        'tactics': [],
        'techniques': [],
        'indicators': [],
        'references': [],
        'created': '',
        'modified': '',
        'confidence': '',
        'severity': '',
        'attribution': ''
    }
    
    if format_type == 'stix_bundle':
        obj = data.get('objects', [{}])[0] if data.get('objects') else {}
        fields.update(extract_stix_fields(obj))
    
    elif format_type == 'mitre_attack':
        obj = data.get('objects', [{}])[0] if data.get('objects') else {}
        fields.update(extract_mitre_fields(obj))
    
    elif format_type == 'stix_objects':
        obj = data.get('objects', [{}])[0] if data.get('objects') else {}
        fields.update(extract_stix_fields(obj))
    
    elif format_type == 'stix_object':
        fields.update(extract_stix_fields(data))
    
    elif format_type == 'opencti':
        fields.update(extract_opencti_fields(data))
    
    elif format_type == 'threat_actor':
        fields.update(extract_threat_actor_fields(data))
    
    elif format_type == 'generic_threat':
        fields.update(extract_generic_threat_fields(data))
    
    else:  # generic
        fields.update(extract_generic_fields(data))
    
    return fields


def extract_stix_fields(obj: Dict[Any, Any]) -> Dict[str, Any]:
    """Extract fields from STIX format objects."""
    return {
        'name': obj.get('name', ''),
        'description': obj.get('description', ''),
        'type': obj.get('type', ''),
        'id': obj.get('id', ''),
        'labels': obj.get('labels', []),
        'created': obj.get('created', ''),
        'modified': obj.get('modified', ''),
        'pattern': obj.get('pattern', ''),
        'confidence': obj.get('confidence', ''),
        'references': extract_references(obj.get('external_references', []))
    }


def extract_mitre_fields(obj: Dict[Any, Any]) -> Dict[str, Any]:
    """Extract fields from MITRE ATT&CK format objects."""
    platforms = obj.get('x_mitre_platforms', [])
    
    # Extract tactics from kill chain phases
    tactics = []
    for phase in obj.get('kill_chain_phases', []):
        if 'mitre' in phase.get('kill_chain_name', ''):
            tactics.append(phase.get('phase_name', '').replace('-', ' ').title())
    
    # Extract MITRE ID from external references
    mitre_id = ''
    external_refs = obj.get('external_references', [])
    for ref in external_refs:
        if ref.get('source_name') in ['mitre-attack', 'mitre-ics-attack']:
            mitre_id = ref.get('external_id', '')
            break
    
    # Extract data sources (MITRE specific)
    data_sources = obj.get('x_mitre_data_sources', [])
    if not data_sources:
        # Try alternative data source formats
        data_sources = obj.get('x_mitre_data_source_refs', [])
    
    # Detection information
    detection = obj.get('x_mitre_detection', '')
    
    return {
        'name': obj.get('name', ''),
        'description': obj.get('description', ''),
        'type': obj.get('type', ''),
        'id': obj.get('id', ''),
        'mitre_id': mitre_id,
        'platforms': platforms,
        'tactics': tactics,
        'data_sources': data_sources,
        'detection': detection,
        'aliases': obj.get('x_mitre_aliases', []),
        'references': extract_references(obj.get('external_references', [])),
        'created': obj.get('created', ''),
        'modified': obj.get('modified', ''),
        'version': obj.get('x_mitre_version', '')
    }


def extract_opencti_fields(data: Dict[Any, Any]) -> Dict[str, Any]:
    """Extract fields from OpenCTI format."""
    return {
        'name': data.get('name', ''),
        'description': data.get('description', ''),
        'type': data.get('entity_type', ''),
        'id': data.get('standard_id', data.get('id', '')),
        'labels': data.get('labels', []),
        'platforms': data.get('platforms', []),
        'confidence': data.get('confidence', ''),
        'created': data.get('created', ''),
        'modified': data.get('modified', '')
    }


def extract_generic_threat_fields(data: Dict[Any, Any]) -> Dict[str, Any]:
    """Extract fields from generic threat intel format."""
    return {
        'name': data.get('name', ''),
        'description': data.get('description', ''),
        'type': data.get('threat_type', data.get('type', '')),
        'id': data.get('id', ''),
        'indicators': data.get('indicators', data.get('iocs', [])),
        'techniques': data.get('ttps', data.get('techniques', [])),
        'attribution': data.get('attribution', ''),
        'created': data.get('first_seen', data.get('created', '')),
        'modified': data.get('last_seen', data.get('modified', ''))
    }


def extract_threat_actor_fields(data: Dict[Any, Any]) -> Dict[str, Any]:
    """Extract fields from threat actor format (VulnCheck style)."""
    # Extract CVE references
    cve_refs = []
    for cve_ref in data.get('cve_references', []):
        if 'cve' in cve_ref:
            cves = ', '.join(cve_ref['cve'])
            url = cve_ref.get('url', '')
            if url:
                cve_refs.append(f"{cves} ({url})")
            else:
                cve_refs.append(cves)
    
    # Extract MITRE techniques
    techniques = []
    for tech in data.get('associated_mitre_attack_techniques', []):
        tech_name = f"{tech.get('id', '')} - {tech.get('name', '')}"
        techniques.append(tech_name)
    
    # Extract vendor/product targets
    targets = []
    for target in data.get('vendors_and_products_targeted', []):
        vendor = target.get('vendor', '')
        product = target.get('product', '')
        if vendor and product:
            targets.append(f"{vendor} {product}")
        elif vendor:
            targets.append(vendor)
        elif product:
            targets.append(product)
    
    return {
        'name': data.get('threat_actor_name', ''),
        'description': f"Threat actor active since {data.get('date_added', 'unknown date')}",
        'type': 'threat-actor',
        'id': data.get('mitre_id', data.get('misp_id', '')),
        'country': data.get('country', ''),
        'references': cve_refs,
        'techniques': techniques,
        'targets': targets,
        'created': data.get('date_added', ''),
        'aliases': [alias.get('threat_actor_name', '') for alias in data.get('vendor_names_for_threat_actors', [])]
    }


def extract_generic_fields(data: Dict[Any, Any]) -> Dict[str, Any]:
    """Extract fields from completely generic JSON."""
    return {
        'name': data.get('name', data.get('title', '')),
        'description': data.get('description', data.get('summary', '')),
        'type': data.get('type', data.get('category', '')),
        'id': data.get('id', data.get('identifier', ''))
    }


def extract_references(refs: List[Dict]) -> List[str]:
    """Extract external references into a readable format."""
    if not refs:
        return []
    
    ref_list = []
    for ref in refs:
        if isinstance(ref, dict):
            source = ref.get('source_name', '')
            url = ref.get('url', '')
            external_id = ref.get('external_id', '')
            
            if external_id and source:
                ref_list.append(f"{source}: {external_id}")
            elif url:
                ref_list.append(url)
            elif source:
                ref_list.append(source)
    
    return ref_list


def generate_markdown(fields: Dict[str, Any], format_type: str) -> str:
    """Generate markdown content from extracted fields."""
    name = clean_text(fields.get('name', 'Unknown Object'))
    obj_id = fields.get('id', '')
    obj_type = fields.get('type', 'unknown')
    
    # Create title with ID if available
    title = f"# {obj_id}: {name}" if obj_id and obj_id != name else f"# {name}"
    
    markdown_content = f"""{title}

## Overview
{clean_text(fields.get('description', 'Not specified'))}

## Object Type
{obj_type}
"""
    
    # Add format-specific sections
    if fields.get('mitre_id'):
        # Use MITRE ID in title if available
        title = f"# {fields['mitre_id']}: {name}" if fields['mitre_id'] != name else f"# {name}"
        markdown_content = markdown_content.replace(f"# {obj_id}: {name}", title)
        markdown_content = markdown_content.replace(f"# {name}", title)
    
    if fields.get('country'):
        markdown_content += f"""
## Country
{fields['country']}
"""
    
    if fields.get('targets'):
        markdown_content += f"""
## Targeted Vendors/Products
{format_list_items(fields['targets'])}
"""
    
    if fields.get('platforms'):
        markdown_content += f"""
## Platforms
{format_list_items(fields['platforms'])}
"""
    
    if fields.get('tactics'):
        markdown_content += f"""
## Tactics
{format_list_items(fields['tactics'])}
"""
    
    if fields.get('data_sources'):
        markdown_content += f"""
## Data Sources
{format_list_items(fields['data_sources'])}
"""
    
    if fields.get('detection'):
        markdown_content += f"""
## Detection
{clean_text(fields['detection'])}
"""
    
    if fields.get('techniques'):
        markdown_content += f"""
## Techniques/TTPs
{format_list_items(fields['techniques'])}
"""
    
    if fields.get('indicators'):
        markdown_content += f"""
## Indicators
{format_list_items(fields['indicators'])}
"""
    
    if fields.get('labels'):
        markdown_content += f"""
## Labels
{format_list_items(fields['labels'])}
"""
    
    if fields.get('aliases'):
        markdown_content += f"""
## Known Aliases
{format_list_items(fields['aliases'])}
"""
    
    # Add metadata section
    metadata_items = []
    if fields.get('created'):
        metadata_items.append(f"**Created:** {fields['created']}")
    if fields.get('modified'):
        metadata_items.append(f"**Modified:** {fields['modified']}")
    if fields.get('confidence'):
        metadata_items.append(f"**Confidence:** {fields['confidence']}")
    if fields.get('attribution'):
        metadata_items.append(f"**Attribution:** {fields['attribution']}")
    if fields.get('pattern'):
        metadata_items.append(f"**Pattern:** `{fields['pattern']}`")
    
    if metadata_items:
        markdown_content += f"""
## Metadata
{chr(10).join(metadata_items)}
"""
    
    # Add references
    if fields.get('references'):
        markdown_content += f"""
## External References
{format_list_items(fields['references'])}
"""
    else:
        markdown_content += """
## External References
No external references available
"""
    
    markdown_content += f"""
---
*Generated from {format_type.replace('_', ' ').title()} CTI data*
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
                
            # Detect format for each item
            format_type = detect_json_format(item)
            
            # Extract common fields
            fields = extract_common_fields(item, format_type)
            
            # Generate markdown
            markdown_content = generate_markdown(fields, format_type)
            
            # Create meaningful filename using name or index
            item_name = fields.get('name', f'item_{i+1}')
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
        
        # Detect format
        format_type = detect_json_format(data)
        
        # Extract common fields
        fields = extract_common_fields(data, format_type)
        
        # Generate markdown
        markdown_content = generate_markdown(fields, format_type)
        
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


def print_detailed_statistics(output_path: str):
    """Print detailed statistics about the converted files."""
    print("\n" + "=" * 60)
    print("CONVERSION STATISTICS")
    print("=" * 60)
    
    # Get all subdirectories
    subdirs = []
    for item in os.listdir(output_path):
        item_path = os.path.join(output_path, item)
        if os.path.isdir(item_path) and not item.startswith('__') and not item.startswith('.'):
            subdirs.append(item)
    
    subdirs.sort()
    
    if subdirs:
        print("\nDirectories created:")
        for subdir in subdirs:
            print(f"  {subdir}/")
    
    print("\nFile counts per category:")
    total_md_files = 0
    category_stats = []
    
    # Count files in each directory
    for subdir in subdirs:
        subdir_path = os.path.join(output_path, subdir)
        md_files = [f for f in os.listdir(subdir_path) if f.endswith('.md')]
        count = len(md_files)
        total_md_files += count
        category_stats.append((subdir, count))
        print(f"  {subdir}: {count} files")
    
    # Count root-level .md files
    root_md_files = [f for f in os.listdir(output_path) if f.endswith('.md') and os.path.isfile(os.path.join(output_path, f))]
    if root_md_files:
        print(f"  Root level: {len(root_md_files)} files")
        total_md_files += len(root_md_files)
    
    print(f"\nTotal markdown files: {total_md_files}")
    
    # Show top categories
    if category_stats:
        category_stats.sort(key=lambda x: x[1], reverse=True)
        if len(category_stats) > 3:
            print("\nTop categories by file count:")
            for category, count in category_stats[:3]:
                percentage = (count / total_md_files) * 100 if total_md_files > 0 else 0
                print(f"  {category}: {count} files ({percentage:.1f}%)")
    
    print("=" * 60)


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
    total_output_files = 0
    for root, dirs, files in os.walk(output_path):
        total_output_files += len([f for f in files if f.endswith('.md')])
    
    print(f"\nConversion complete!")
    print(f"Successfully processed: {processed_count} JSON files")
    print(f"Total output files created: {total_output_files}")
    print(f"Errors encountered: {error_count} files")
    print(f"Total time: {total_time:.2f} seconds")
    print(f"Average time per JSON file: {total_time/total_files:.3f} seconds")
    
    if error_count > 0:
        print(f"\nNote: {error_count} files had errors. Check the output above for details.")
    
    # Print detailed statistics
    print_detailed_statistics(output_dir)


def main():
    parser = argparse.ArgumentParser(
        description="Convert CTI JSON files to markdown format (supports MITRE, STIX, OpenCTI, and generic formats)"
    )
    parser.add_argument(
        "source_dir",
        help="Source directory containing JSON files"
    )
    parser.add_argument(
        "output_dir", 
        nargs="?",
        default="cti_markdown_output",
        help="Output directory for markdown files (default: cti_markdown_output)"
    )
    
    args = parser.parse_args()
    
    print("Generic CTI JSON to Markdown Converter")
    print("=" * 50)
    print(f"Source directory: {args.source_dir}")
    print(f"Output directory: {args.output_dir}")
    
    process_directory(args.source_dir, args.output_dir)


if __name__ == "__main__":
    main()
