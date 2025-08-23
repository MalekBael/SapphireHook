import re
from datetime import datetime

def parse_functions_txt(input_file):
    """Parse the functions.txt file and extract just function names and addresses."""
    functions = {}
    
    with open(input_file, 'r', encoding='utf-8') as file:
        # Skip the header line
        header = file.readline()
        
        for line in file:
            line = line.strip()
            if not line:
                continue
                
            # Split by tabs
            parts = line.split('\t')
            if len(parts) < 3:
                continue
                
            function_name = parts[0].strip()
            start_address = parts[2].strip()
            
            # Skip empty function names or invalid addresses
            if not function_name or not start_address:
                continue
            
            # Convert address to hex format without 0x prefix for easier reading
            if start_address.startswith('0x') or start_address.startswith('0X'):
                addr = start_address
            else:
                addr = '0x' + start_address
            
            # Clean up the function name (remove C++ mangling decorations)
            clean_name = clean_function_name(function_name)
            
            # Filter out unwanted function types
            if should_filter_function(clean_name):
                continue
            
            functions[addr] = clean_name
    
    return functions

def should_filter_function(name):
    """Filter out unwanted function types."""
    # Filter patterns to exclude
    filter_patterns = [
        r'^sub_[0-9A-F]+$',      # sub_7FF749043A90
        r'^nullsub_\d+$',        # nullsub_1
        r'^unknown_libname_\d+$', # unknown_libname_1
        r'^j_sub_[0-9A-F]+$',    # j_sub_...
        r'^j_nullsub_\d+$',      # j_nullsub_...
    ]
    
    for pattern in filter_patterns:
        if re.match(pattern, name):
            return True
    
    return False

def clean_function_name(name):
    """Clean up function names to be more readable."""
    # Remove function call counts like "(xx)" at the end
    name = re.sub(r'\(\d+\)$', '', name)
    
    # Remove "(void)" parameter lists
    name = re.sub(r'\(void\)$', '', name)
    
    # Remove other parameter lists in parentheses at the end
    name = re.sub(r'\([^)]*\)$', '', name)
    
    # Convert __ to :: for C++ style names
    if name.startswith('Client__ExdData__'):
        name = name.replace('__', '::')
    elif '__' in name:
        name = name.replace('__', '::')
    
    return name

def generate_yaml(functions, output_file):
    """Generate YAML file in the desired format."""
    # Generate version string
    now = datetime.now()
    version = f"{now.year}.{now.month:02d}.{now.day:02d}.{now.hour:02d}{now.minute:02d}.{now.second:02d}{now.microsecond//10000:02d}"
    
    with open(output_file, 'w', encoding='utf-8') as file:
        file.write("# FFXIV Function and Global Database\n")
        file.write("# Based on IDA analysis and reverse engineering\n")
        file.write(f"version: {version}\n\n")
        
        file.write("functions:\n")
        
        # Group functions by category for better organization
        exd_functions = {}
        concurrency_functions = {}
        client_functions = {}
        other_functions = {}
        
        for addr, name in sorted(functions.items()):
            if 'Client::ExdData::' in name:
                exd_functions[addr] = name
            elif 'Concurrency::' in name:
                concurrency_functions[addr] = name
            elif 'Client::' in name:
                client_functions[addr] = name
            else:
                other_functions[addr] = name
        
        # Write ExdData functions first (these are most useful for FFXIV)
        if exd_functions:
            file.write("  # ExdData functions - data access functions for game databases\n")
            for addr, name in sorted(exd_functions.items()):
                file.write(f"  {addr}: {name}\n")
            file.write("\n")
        
        # Write other Client functions
        if client_functions:
            file.write("  # Other Client functions\n")
            for addr, name in sorted(client_functions.items()):
                file.write(f"  {addr}: {name}\n")
            file.write("\n")
        
        # Write Concurrency functions
        if concurrency_functions:
            file.write("  # Concurrency functions\n")
            for addr, name in sorted(concurrency_functions.items()):
                file.write(f"  {addr}: {name}\n")
            file.write("\n")
        
        # Write remaining functions
        if other_functions:
            file.write("  # Other functions\n")
            for addr, name in sorted(other_functions.items()):
                file.write(f"  {addr}: {name}\n")
        
        file.write("\nglobals:\n")
        file.write("  # Add any global variables you discover here\n")
        file.write("  # Example format:\n")
        file.write("  # 0x7FF749ABC123: g_SomeGlobalVariable # comment about what it does\n")

def main():
    input_file = 'functions.txt'
    output_file = 'data.yml'
    
    print(f"Parsing {input_file}...")
    functions = parse_functions_txt(input_file)
    
    if not functions:
        print("No functions found!")
        return
    
    print(f"Found {len(functions)} functions")
    print(f"Generating {output_file}...")
    
    generate_yaml(functions, output_file)
    
    print(f"Successfully generated {output_file}")
    
    # Print some statistics
    exd_count = sum(1 for name in functions.values() if 'Client::ExdData::' in name)
    concurrency_count = sum(1 for name in functions.values() if 'Concurrency::' in name)
    
    print(f"\nFunction breakdown:")
    print(f"  ExdData functions: {exd_count}")
    print(f"  Concurrency functions: {concurrency_count}")
    print(f"  Other functions: {len(functions) - exd_count - concurrency_count}")

if __name__ == "__main__":
    main()