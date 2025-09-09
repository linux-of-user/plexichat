"""Core files module with fallback implementations."""
__version__ = "0.0.0"
__all__ = ["FileManager", "FileMetadata", "file_manager", "upload_file", "get_file_metadata"]

class FileManager:
    def __init__(self):
        pass

class FileMetadata:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

file_manager = None

def upload_file(*args, **kwargs):
    pass

def get_file_metadata(*args, **kwargs):
    pass