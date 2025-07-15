"""
File Manager Plugin Tests - Compression

Tests for file compression and archive functionality.
"""

import asyncio
import tempfile
import zipfile
import tarfile
import gzip
from pathlib import Path
from typing import Dict, Any


async def test_zip_compression(, Optional):
    """Test ZIP file compression."""
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create test files
            test_files = []
            for i in range(3):
                test_file = temp_path / f"test_{i}.txt"
                test_file.write_text(f"Test file content {i}")
                test_files.append(test_file)
            
            # Create ZIP archive
            zip_file = temp_path / "test_archive.zip"
            with zipfile.ZipFile(zip_file, 'w', zipfile.ZIP_DEFLATED) as zf:
                for test_file in test_files:
                    zf.write(test_file, test_file.name)
            
            # Verify ZIP file was created
            if not zip_file.exists():
                return {
                    "success": False,
                    "error": "ZIP file was not created"
                }
            
            # Test extraction
            extract_dir = temp_path / "extracted"
            extract_dir.mkdir()
            
            with zipfile.ZipFile(zip_file, 'r') as zf:
                zf.extractall(extract_dir)
            
            # Verify extracted files
            extracted_files = list(extract_dir.glob("*.txt"))
            if len(extracted_files) == 3:
                return {
                    "success": True,
                    "message": f"ZIP compression test passed - compressed and extracted {len(extracted_files)} files"
                }
            else:
                return {
                    "success": False,
                    "error": f"Expected 3 extracted files, found {len(extracted_files)}"
                }
                
    except Exception as e:
        return {
            "success": False,
            "error": f"ZIP compression test failed: {str(e)}"
        }


async def test_tar_compression():
    """Test TAR file compression."""
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create test files
            test_files = []
            for i in range(3):
                test_file = temp_path / f"test_{i}.txt"
                test_file.write_text(f"Test file content {i}")
                test_files.append(test_file)
            
            # Create TAR archive
            tar_file = temp_path / "test_archive.tar.gz"
            with tarfile.open(tar_file, 'w:gz') as tf:
                for test_file in test_files:
                    tf.add(test_file, test_file.name)
            
            # Verify TAR file was created
            if not tar_file.exists():
                return {
                    "success": False,
                    "error": "TAR file was not created"
                }
            
            # Test extraction
            extract_dir = temp_path / "extracted"
            extract_dir.mkdir()
            
            with tarfile.open(tar_file, 'r:gz') as tf:
                tf.extractall(extract_dir)
            
            # Verify extracted files
            extracted_files = list(extract_dir.glob("*.txt"))
            if len(extracted_files) == 3:
                return {
                    "success": True,
                    "message": f"TAR compression test passed - compressed and extracted {len(extracted_files)} files"
                }
            else:
                return {
                    "success": False,
                    "error": f"Expected 3 extracted files, found {len(extracted_files)}"
                }
                
    except Exception as e:
        return {
            "success": False,
            "error": f"TAR compression test failed: {str(e)}"
        }


async def test_gzip_compression():
    """Test GZIP compression for single files."""
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create test file
            test_file = temp_path / "test.txt"
            test_content = "This is test content for GZIP compression" * 100  # Make it larger
            test_file.write_text(test_content)
            
            # Compress with GZIP
            gz_file = temp_path / "test.txt.gz"
            with open(test_file, 'rb') as f_in:
                with gzip.open(gz_file, 'wb') as f_out:
                    f_out.write(f_in.read())
            
            # Verify compressed file exists and is smaller
            if not gz_file.exists():
                return {
                    "success": False,
                    "error": "GZIP file was not created"
                }
            
            original_size = test_file.stat().st_size
            compressed_size = gz_file.stat().st_size
            
            # Test decompression
            decompressed_file = temp_path / "decompressed.txt"
            with gzip.open(gz_file, 'rb') as f_in:
                with open(decompressed_file, 'wb') as f_out:
                    f_out.write(f_in.read())
            
            # Verify decompressed content
            if decompressed_file.read_text() == test_content:
                compression_ratio = (1 - compressed_size / original_size) * 100
                return {
                    "success": True,
                    "message": f"GZIP compression test passed - {compression_ratio:.1f}% compression ratio"
                }
            else:
                return {
                    "success": False,
                    "error": "Decompressed content does not match original"
                }
                
    except Exception as e:
        return {
            "success": False,
            "error": f"GZIP compression test failed: {str(e)}"
        }


async def test_compression_ratio():
    """Test compression efficiency."""
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create test file with repetitive content (should compress well)
            test_file = temp_path / "repetitive.txt"
            repetitive_content = "This line repeats many times.\n" * 1000
            test_file.write_text(repetitive_content)
            
            original_size = test_file.stat().st_size
            
            # Test ZIP compression
            zip_file = temp_path / "test.zip"
            with zipfile.ZipFile(zip_file, 'w', zipfile.ZIP_DEFLATED) as zf:
                zf.write(test_file, test_file.name)
            
            zip_size = zip_file.stat().st_size
            zip_ratio = (1 - zip_size / original_size) * 100
            
            # Test GZIP compression
            gz_file = temp_path / "test.gz"
            with open(test_file, 'rb') as f_in:
                with gzip.open(gz_file, 'wb') as f_out:
                    f_out.write(f_in.read())
            
            gz_size = gz_file.stat().st_size
            gz_ratio = (1 - gz_size / original_size) * 100
            
            # Both should achieve significant compression on repetitive data
            if zip_ratio > 50 and gz_ratio > 50:
                return {
                    "success": True,
                    "message": f"Compression ratio test passed - ZIP: {zip_ratio:.1f}%, GZIP: {gz_ratio:.1f}%"
                }
            else:
                return {
                    "success": False,
                    "error": f"Poor compression ratios - ZIP: {zip_ratio:.1f}%, GZIP: {gz_ratio:.1f}%"
                }
                
    except Exception as e:
        return {
            "success": False,
            "error": f"Compression ratio test failed: {str(e)}"
        }


async def test_archive_integrity():
    """Test archive integrity verification."""
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create test files
            test_files = []
            for i in range(5):
                test_file = temp_path / f"integrity_test_{i}.txt"
                test_file.write_text(f"Integrity test content {i}")
                test_files.append(test_file)
            
            # Create ZIP archive
            zip_file = temp_path / "integrity_test.zip"
            with zipfile.ZipFile(zip_file, 'w', zipfile.ZIP_DEFLATED) as zf:
                for test_file in test_files:
                    zf.write(test_file, test_file.name)
            
            # Test ZIP integrity
            try:
                with zipfile.ZipFile(zip_file, 'r') as zf:
                    # Test the archive
                    bad_file = zf.testzip()
                    if bad_file is not None:
                        return {
                            "success": False,
                            "error": f"ZIP integrity check failed - corrupt file: {bad_file}"
                        }
                    
                    # Verify file list
                    file_list = zf.namelist()
                    if len(file_list) == 5:
                        return {
                            "success": True,
                            "message": f"Archive integrity test passed - {len(file_list)} files verified"
                        }
                    else:
                        return {
                            "success": False,
                            "error": f"Expected 5 files in archive, found {len(file_list)}"
                        }
                        
            except zipfile.BadZipFile:
                return {
                    "success": False,
                    "error": "ZIP file is corrupted"
                }
                
    except Exception as e:
        return {
            "success": False,
            "error": f"Archive integrity test failed: {str(e)}"
        }


async def test_large_file_compression():
    """Test compression of larger files."""
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create a larger test file (1MB)
            test_file = temp_path / "large_test.txt"
            large_content = "Large file test content.\n" * 50000  # ~1MB
            test_file.write_text(large_content)
            
            original_size = test_file.stat().st_size
            
            # Compress with ZIP
            zip_file = temp_path / "large_test.zip"
            with zipfile.ZipFile(zip_file, 'w', zipfile.ZIP_DEFLATED) as zf:
                zf.write(test_file, test_file.name)
            
            compressed_size = zip_file.stat().st_size
            
            # Test extraction
            extract_dir = temp_path / "extracted"
            extract_dir.mkdir()
            
            with zipfile.ZipFile(zip_file, 'r') as zf:
                zf.extractall(extract_dir)
            
            extracted_file = extract_dir / "large_test.txt"
            
            # Verify extraction
            if (extracted_file.exists() and 
                extracted_file.stat().st_size == original_size):
                compression_ratio = (1 - compressed_size / original_size) * 100
                return {
                    "success": True,
                    "message": f"Large file compression test passed - {compression_ratio:.1f}% compression"
                }
            else:
                return {
                    "success": False,
                    "error": "Large file extraction verification failed"
                }
                
    except Exception as e:
        return {
            "success": False,
            "error": f"Large file compression test failed: {str(e)}"
        }
