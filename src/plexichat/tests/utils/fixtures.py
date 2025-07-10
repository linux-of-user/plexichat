"""Test fixtures."""
class TestFixtures:
    """Common test fixtures."""
    
    @staticmethod
    def get_sample_config():
        """Get sample configuration for tests."""
        return {"test": True, "debug": True}
    
    @staticmethod
    def get_sample_data():
        """Get sample data for tests."""
        return {"data": "sample"}
