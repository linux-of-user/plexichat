#!/usr/bin/env python3
"""
Find duplicate files and unused code in PlexiChat project
"""

import os
import hashlib
from pathlib import Path
from collections import defaultdict
import ast

class DuplicateFinder:
    def __init__(self, root_dir="."):
        self.root_dir = Path(root_dir)
        self.file_hashes = defaultdict(list)
        self.duplicates = []
        
    def get_file_hash(self, file_path):
        """Get MD5 hash of file content"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except Exception:
            return None
    
    def find_duplicate_files(self):
        """Find files with identical content"""
        print("🔍 Scanning for duplicate files...")
        
        for file_path in self.root_dir.rglob("*.py"):
            if any(part in str(file_path) for part in ['.git', '__pycache__', 'node_modules']):
                continue
                
            file_hash = self.get_file_hash(file_path)
            if file_hash:
                self.file_hashes[file_hash].append(file_path)
        
        # Find duplicates
        for file_hash, files in self.file_hashes.items():
            if len(files) > 1:
                self.duplicates.append(files)
                print(f"\n📋 Duplicate files found:")
                for file in files:
                    print(f"   - {file}")
        
        return self.duplicates
    
    def find_similar_files(self):
        """Find files with similar names that might be duplicates"""
        print("\n🔍 Scanning for similar file names...")
        
        files_by_name = defaultdict(list)
        
        for file_path in self.root_dir.rglob("*.py"):
            if any(part in str(file_path) for part in ['.git', '__pycache__', 'node_modules']):
                continue
            
            name = file_path.name.lower()
            # Group by similar names
            base_name = name.replace('_', '').replace('-', '')
            files_by_name[base_name].append(file_path)
        
        similar_groups = []
        for base_name, files in files_by_name.items():
            if len(files) > 1:
                similar_groups.append(files)
                print(f"\n📋 Similar files found ({base_name}):")
                for file in files:
                    print(f"   - {file}")
        
        return similar_groups
    
    def find_empty_files(self):
        """Find empty or nearly empty files"""
        print("\n🔍 Scanning for empty/minimal files...")
        
        empty_files = []
        minimal_files = []
        
        for file_path in self.root_dir.rglob("*.py"):
            if any(part in str(file_path) for part in ['.git', '__pycache__', 'node_modules']):
                continue
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                
                if not content:
                    empty_files.append(file_path)
                elif len(content.split('\n')) <= 5:
                    minimal_files.append(file_path)
                    
            except Exception:
                continue
        
        if empty_files:
            print(f"\n📋 Empty files found:")
            for file in empty_files:
                print(f"   - {file}")
        
        if minimal_files:
            print(f"\n📋 Minimal files found (≤5 lines):")
            for file in minimal_files:
                print(f"   - {file}")
        
        return empty_files, minimal_files
    
    def find_unused_imports(self, file_path):
        """Find unused imports in a Python file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content)
            
            # Extract imports
            imports = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name.split('.')[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.append(node.module.split('.')[0])
                    for alias in node.names:
                        imports.append(alias.name)
            
            # Check usage (simple text search)
            unused = []
            for imp in set(imports):
                if imp not in content.replace(f"import {imp}", "").replace(f"from {imp}", ""):
                    unused.append(imp)
            
            return unused
            
        except Exception:
            return []
    
    def analyze_project_structure(self):
        """Analyze overall project structure"""
        print("\n🏗️  Analyzing project structure...")
        
        directories = defaultdict(int)
        file_types = defaultdict(int)
        
        for item in self.root_dir.rglob("*"):
            if any(part in str(item) for part in ['.git', '__pycache__', 'node_modules']):
                continue
            
            if item.is_dir():
                directories[item.name] += 1
            else:
                file_types[item.suffix] += 1
        
        print(f"\n📊 Directory frequency:")
        for dir_name, count in sorted(directories.items(), key=lambda x: x[1], reverse=True)[:10]:
            if count > 1:
                print(f"   {dir_name}: {count} times")
        
        print(f"\n📊 File type distribution:")
        for ext, count in sorted(file_types.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"   {ext or 'no extension'}: {count} files")

def main():
    print("🧹 PlexiChat Project Cleanup Analysis")
    print("=" * 50)
    
    finder = DuplicateFinder()
    
    # Find duplicates
    duplicates = finder.find_duplicate_files()
    
    # Find similar files
    similar = finder.find_similar_files()
    
    # Find empty files
    empty, minimal = finder.find_empty_files()
    
    # Analyze structure
    finder.analyze_project_structure()
    
    print(f"\n📈 Summary:")
    print(f"   Duplicate file groups: {len(duplicates)}")
    print(f"   Similar file groups: {len(similar)}")
    print(f"   Empty files: {len(empty)}")
    print(f"   Minimal files: {len(minimal)}")
    
    # Recommendations
    print(f"\n💡 Recommendations:")
    if duplicates:
        print(f"   - Review and merge {len(duplicates)} duplicate file groups")
    if empty:
        print(f"   - Remove {len(empty)} empty files")
    if minimal:
        print(f"   - Review {len(minimal)} minimal files for consolidation")

if __name__ == "__main__":
    main()
