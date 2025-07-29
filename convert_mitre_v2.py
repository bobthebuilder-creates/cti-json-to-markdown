#!/usr/bin/env python3
"""
MITRE ATT&CK JSON to Markdown Converter

This script recursively processes a directory of JSON files from MITRE ATT&CK
and converts them to markdown format while preserving directory structure.
"""

import argparse
import json
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from tqdm import tqdm


def clean_text(input_text: str) -> str:
    """Clean and format text for markdown display."""
    if not input_text:
        return "Not specified"
    # Remove excessive whitespace and normalize
    return ' '.join(str(input_text).split())


def format_list_items(items: List[str], prefix: str = "-") -> str:
    """Format list items for markdown display with specified prefix."""
    if not items:
        return "Not specified"
    # Format each item with prefix and join with newlines
    formatted_items = [f"{prefix} {clean_text(str(item))}" for item in items if item]
    return '\n'.join(formatted_items) if formatted_items else "Not specified"


def estimate_tokens(text: str) -> int:
    """Estimate token count using a simple approximation (1 token ≈ 4 characters)."""
    return len(str(text)) // 4


def chunk_text_with_overlap(text: str, max_tokens: int = 800, overlap_ratio: float = 0.22) -> List[str]:
    """
    Split text into overlapping chunks optimized for cybersecurity content.
    
    Args:
        text: Input text to chunk
        max_tokens: Maximum tokens per chunk (default 800 for cybersecurity content)
        overlap_ratio: Overlap ratio between chunks (default 22% for security relationships)
    
    Returns:
        List of text chunks with appropriate overlap
    """
    text = str(text)  # Ensure text is a string
    if estimate_tokens(text) <= max_tokens:
        return [text]
    
    # Split into paragraphs first to maintain semantic boundaries
    paragraphs = [p.strip() for p in text.split('\n\n') if p.strip()]
    
    chunks = []
    current_chunk = ""
    overlap_tokens = int(max_tokens * overlap_ratio)
    
    i = 0
    while i < len(paragraphs):
        paragraph = paragraphs[i]
        paragraph_tokens = estimate_tokens(paragraph)
        current_tokens = estimate_tokens(current_chunk)
        
        # If adding this paragraph would exceed max_tokens, finalize current chunk
        if current_tokens + paragraph_tokens > max_tokens and current_chunk:
            chunks.append(current_chunk.strip())
            
            # Create overlap by keeping last part of previous chunk
            if overlap_tokens > 0 and current_tokens > overlap_tokens:
                # Find a good break point for overlap (preferably at sentence boundary)
                sentences = re.split(r'(?<=[.!?])\s+', current_chunk)
                overlap_text = ""
                overlap_current = 0
                
                # Build overlap from the end backwards
                for sentence in reversed(sentences):
                    sentence_tokens = estimate_tokens(sentence)
                    if overlap_current + sentence_tokens <= overlap_tokens:
                        overlap_text = sentence + " " + overlap_text
                        overlap_current += sentence_tokens
                    else:
                        break
                
                current_chunk = overlap_text.strip()
            else:
                current_chunk = ""
        
        # Add current paragraph
        if current_chunk:
            current_chunk += "\n\n" + paragraph
        else:
            current_chunk = paragraph
        
        i += 1
    
    # Add final chunk if it exists
    if current_chunk.strip():
        chunks.append(current_chunk.strip())
    
    return chunks


def create_chunked_documents(markdown_content: str, base_filename: str, chunk_info: str = "") -> List[tuple]:
    """
    Create chunked documents from markdown content if it's too long.
    
    Returns:
        List of (filename, content) tuples
    """
    chunks = chunk_text_with_overlap(markdown_content)
    
    if len(chunks) == 1:
        # Single chunk, return as-is
        return [(base_filename, markdown_content)]
    
    # Multiple chunks needed
    chunked_documents = []
    for i, chunk in enumerate(chunks):
        chunk_filename = base_filename.replace('.md', f'_chunk_{i+1}.md')
        
        # Add chunk metadata to the beginning
        chunk_header = f"""<!-- CHUNK {i+1} of {len(chunks)} {chunk_info} -->
<!-- Tokens: ~{estimate_tokens(chunk)} -->

"""
        
        chunked_content = chunk_header + chunk
        chunked_documents.append((chunk_filename, chunked_content))
    
    return chunked_documents
    """Format a list of items as markdown list."""
    if not items:
        return "None specified"
    return '\n'.join([f"{prefix} {clean_text(item)}" for item in items])


def extract_references(obj: Dict[Any, Any]) -> str:
    """Extract external references from the object."""
    refs = obj.get('external_references', [])
    if not refs:
        return "No external references available"
    
    formatted_refs = []
    for ref in refs:
        if 'source_name' in ref and 'url' in ref:
            formatted_refs.append(f"- [{ref['source_name']}]({ref['url']})")
        elif 'source_name' in ref:
            formatted_refs.append(f"- {ref['source_name']}")
    
    return '\n'.join(formatted_refs) if formatted_refs else "No external references available"


def convert_technique_json(data: Dict[Any, Any]) -> str:
    """Convert a technique JSON object to markdown."""
    obj = data.get('objects', [{}])[0]  # Get first object from STIX bundle
    
    # Extract basic information
    name = obj.get('name', 'Unknown Technique')
    tech_id = obj.get('external_references', [{}])[0].get('external_id', 'Unknown ID')
    description = clean_text(obj.get('description', ''))
    
    # Extract platforms and tactics
    platforms = obj.get('x_mitre_platforms', [])
    tactics = []
    kill_chain_phases = obj.get('kill_chain_phases', [])
    for phase in kill_chain_phases:
        if phase.get('kill_chain_name') == 'mitre-ics-attack':
            tactics.append(phase.get('phase_name', '').replace('-', ' ').title())
    
    # Extract data sources and detection
    data_sources = obj.get('x_mitre_data_sources', [])
    detection = clean_text(obj.get('x_mitre_detection', ''))
    
    # Build markdown content
    markdown_content = f"""# {tech_id}: {name}

## Technique Overview
{description}

## Tactics
{format_list_items(tactics) if tactics else "Not specified"}

## Platforms Affected
{format_list_items(platforms) if platforms else "Not specified"}

## Data Sources
{format_list_items(data_sources) if data_sources else "Not specified"}

## Detection Methods
{detection if detection != "Not specified" else "No specific detection methods documented"}

## External References
{extract_references(obj)}

---
*Generated from MITRE ATT&CK JSON data*
"""
    
    return markdown_content


def convert_mitigation_json(data: Dict[Any, Any]) -> str:
    """Convert a mitigation JSON object to markdown."""
    obj = data.get('objects', [{}])[0]
    
    name = obj.get('name', 'Unknown Mitigation')
    mit_id = obj.get('external_references', [{}])[0].get('external_id', 'Unknown ID')
    description = clean_text(obj.get('description', ''))
    
    markdown_content = f"""# {mit_id}: {name}

## Mitigation Overview
{description}

## External References
{extract_references(obj)}

---
*Generated from MITRE ATT&CK JSON data*
"""
    
    return markdown_content


def convert_group_json(data: Dict[Any, Any]) -> str:
    """Convert a group/threat actor JSON object to markdown."""
    obj = data.get('objects', [{}])[0]
    
    name = obj.get('name', 'Unknown Group')
    group_id = obj.get('external_references', [{}])[0].get('external_id', 'Unknown ID')
    description = clean_text(obj.get('description', ''))
    aliases = obj.get('aliases', [])
    
    markdown_content = f"""# {group_id}: {name}

## Group Overview
{description}

## Known Aliases
{format_list_items(aliases) if aliases else "No known aliases"}

## External References
{extract_references(obj)}

---
*Generated from MITRE ATT&CK JSON data*
"""
    
    return markdown_content


def detect_json_type(data: Dict[Any, Any], file_path: Path = None) -> str:
    """Detect the type of MITRE ATT&CK object from JSON data and file context."""
    if 'objects' not in data or not data['objects']:
        return 'unknown'
    
    obj = data['objects'][0]
    obj_type = obj.get('type', '')
    
    # Primary detection from STIX object type
    type_mapping = {
        'attack-pattern': 'technique',
        'course-of-action': 'mitigation', 
        'intrusion-set': 'group',
        'malware': 'software',
        'tool': 'software',
        'x-mitre-tactic': 'tactic',
        'x-mitre-matrix': 'matrix'
    }
    
    detected_type = type_mapping.get(obj_type, 'unknown')
    
    # Secondary detection from directory structure if available
    if file_path and detected_type == 'unknown':
        path_parts = [part.lower() for part in file_path.parts]
        
        if any('technique' in part for part in path_parts):
            detected_type = 'technique'
        elif any('mitigation' in part for part in path_parts):
            detected_type = 'mitigation'
        elif any('group' in part for part in path_parts):
            detected_type = 'group'
        elif any('software' in part or 'tool' in part or 'malware' in part for part in path_parts):
            detected_type = 'software'
        elif any('tactic' in part for part in path_parts):
            detected_type = 'tactic'
    
    # Tertiary detection from external ID patterns
    if detected_type == 'unknown':
        external_refs = obj.get('external_references', [])
        for ref in external_refs:
            ext_id = ref.get('external_id', '')
            if ext_id.startswith('T'):
                detected_type = 'technique'
                break
            elif ext_id.startswith('M'):
                detected_type = 'mitigation'
                break
            elif ext_id.startswith('G'):
                detected_type = 'group'
                break
            elif ext_id.startswith('S'):
                detected_type = 'software'
                break
    
    return detected_type


def convert_software_json(data: Dict[Any, Any]) -> str:
    """Convert a software/tool/malware JSON object to markdown."""
    obj = data.get('objects', [{}])[0]
    
    name = obj.get('name', 'Unknown Software')
    software_id = obj.get('external_references', [{}])[0].get('external_id', 'Unknown ID')
    description = clean_text(obj.get('description', ''))
    labels = obj.get('labels', [])
    platforms = obj.get('x_mitre_platforms', [])
    
    markdown_content = f"""# {software_id}: {name}

## Software Overview
{description}

## Type
{format_list_items(labels) if labels else "Not specified"}

## Platforms
{format_list_items(platforms) if platforms else "Not specified"}

## External References
{extract_references(obj)}

---
*Generated from MITRE ATT&CK JSON data*
"""
    
    return markdown_content


def convert_tactic_json(data: Dict[Any, Any]) -> str:
    """Convert a tactic JSON object to markdown."""
    obj = data.get('objects', [{}])[0]
    
    name = obj.get('name', 'Unknown Tactic')
    tactic_id = obj.get('external_references', [{}])[0].get('external_id', 'Unknown ID')
    description = clean_text(obj.get('description', ''))
    short_name = obj.get('x_mitre_shortname', '')
    
    markdown_content = f"""# {tactic_id}: {name}

## Tactic Overview
{description}

## Short Name
{short_name if short_name else "Not specified"}

## External References
{extract_references(obj)}

---
*Generated from MITRE ATT&CK JSON data*
"""
    
    return markdown_content


def convert_json_to_markdown(json_data: Dict[Any, Any], file_path: Path = None) -> str:
    """Convert JSON data to markdown based on detected type."""
    json_type = detect_json_type(json_data, file_path)
    
    if json_type == 'technique':
        return convert_technique_json(json_data)
    elif json_type == 'mitigation':
        return convert_mitigation_json(json_data)
    elif json_type == 'group':
        return convert_group_json(json_data)
    elif json_type == 'software':
        return convert_software_json(json_data)
    elif json_type == 'tactic':
        return convert_tactic_json(json_data)
    else:
        # Generic conversion for unknown types
        obj = json_data.get('objects', [{}])[0]
        name = obj.get('name', 'Unknown Object')
        description = clean_text(obj.get('description', ''))
        obj_type = obj.get('type', 'unknown')
        
        return f"""# {name}

## Overview
{description}

## Object Type
{obj_type}

## External References
{extract_references(obj)}

---
*Generated from MITRE ATT&CK JSON data*
"""


def process_directory(source_dir: str, output_dir: str):
    """Process all JSON files in source directory and convert to markdown."""
    source_path = Path(source_dir)
    output_path = Path(output_dir)
    
    if not source_path.exists():
        print(f"Error: Source directory '{source_dir}' does not exist.")
        return
    
    # Create output directory if it doesn't exist
    output_path.mkdir(parents=True, exist_ok=True)
    
    # First pass: count total JSON files for progress bar
    print("Scanning directory for JSON files...")
    json_files = []
    for root, dirs, files in os.walk(source_path):
        for file in files:
            if file.endswith('.json'):
                json_files.append(Path(root) / file)
    
    total_files = len(json_files)
    if total_files == 0:
        print("No JSON files found in the source directory.")
        return
    
    print(f"Found {total_files} JSON files to process")
    
    processed_count = 0
    error_count = 0
    start_time = time.time()
    
    # Process files with progress bar
    with tqdm(total=total_files, desc="Converting files", unit="files") as pbar:
        for source_file in json_files:
            # Calculate relative path from source directory
            relative_path = source_file.relative_to(source_path)
            
            # Create corresponding output path with .md extension
            output_file = output_path / relative_path.with_suffix('.md')
            
            # Create output subdirectory if needed
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            try:
                # Read and parse JSON
                with open(source_file, 'r', encoding='utf-8') as f:
                    json_data = json.load(f)
                
                # Convert to markdown
                markdown_content = convert_json_to_markdown(json_data, source_file)
                
                # Write markdown file
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(markdown_content)
                
                # Show what type was detected for user feedback
                detected_type = detect_json_type(json_data, source_file)
                
                processed_count += 1
                
                # Update progress bar with current file info
                pbar.set_postfix({
                    'current': relative_path.name[:20] + "..." if len(relative_path.name) > 20 else relative_path.name,
                    'type': detected_type,
                    'errors': error_count
                })
                pbar.update(1)
                
            except Exception as e:
                error_count += 1
                pbar.set_postfix({
                    'current': f"ERROR: {relative_path.name[:15]}...",
                    'errors': error_count
                })
                pbar.update(1)
                
                # Log error details to a separate line (so it doesn't mess up progress bar)
                tqdm.write(f"Error processing {relative_path}: {str(e)}")
    
    # Final statistics
    end_time = time.time()
    total_time = end_time - start_time
    
    # Count total output files (including chunks)
    total_output_files = 0
    for root, dirs, files in os.walk(output_path):
        total_output_files += len([f for f in files if f.endswith('.md')])
    
    print(f"\nConversion complete!")
    print(f"Successfully processed: {processed_count} JSON files")
    print(f"Total output files created: {total_output_files} (including chunks)")
    print(f"Errors encountered: {error_count} files") 
    print(f"Total time: {total_time:.2f} seconds")
    print(f"Average time per JSON file: {total_time/total_files:.3f} seconds")
    
    if total_output_files > total_files:
        print(f"Note: {total_output_files - total_files} additional chunk files created for optimal token size")
    
    if error_count > 0:
        print(f"\nNote: {error_count} files had errors. Check the output above for details.")
    
    # Print detailed statistics
    print_detailed_statistics(output_dir)



def print_detailed_statistics(output_path: str):
    """Print detailed statistics about the converted files."""
    from pathlib import Path
    import os
    
    print("\n" + "=" * 60)
    print("CONVERSION STATISTICS")
    print("=" * 60)
    
    # Get all subdirectories (excluding any __pycache__ or temp directories)
    subdirs = []
    for item in os.listdir(output_path):
        item_path = os.path.join(output_path, item)
        if os.path.isdir(item_path) and not item.startswith('__') and not item.startswith('.') and item not in ['my_custom_output']:
            subdirs.append(item)
    
    subdirs.sort()
    
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
    category_stats.sort(key=lambda x: x[1], reverse=True)
    if len(category_stats) > 3:
        print("\nTop categories by file count:")
        for category, count in category_stats[:3]:
            percentage = (count / total_md_files) * 100 if total_md_files > 0 else 0
            print(f"  {category}: {count} files ({percentage:.1f}%)")
    
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Convert MITRE ATT&CK JSON files to markdown format"
    )
    parser.add_argument(
        "source_dir",
        help="Source directory containing JSON files"
    )
    parser.add_argument(
        "output_dir", 
        nargs="?",
        default="mitre_markdown_output",
        help="Output directory for markdown files (default: mitre_markdown_output)"
    )
    
    args = parser.parse_args()
    
    print("MITRE ATT&CK JSON to Markdown Converter")
    print("=" * 50)
    print(f"Source directory: {args.source_dir}")
    print(f"Output directory: {args.output_dir}")
    print()
    
    # Install note for tqdm if not available
    try:
        import tqdm
    except ImportError:
        print("Note: For progress bars, install tqdm with: pip install tqdm")
        print("Continuing without progress bars...\n")
    
    process_directory(args.source_dir, args.output_dir)


if __name__ == "__main__":
    main()
