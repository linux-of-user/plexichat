"""Custom test assertions."""
class CustomAssertions:
    """Custom assertion methods for tests."""
    
    @staticmethod
    def assert_response_success(response):
        """Assert API response is successful."""
        assert response.status_code == 200
    
    @staticmethod
    def assert_valid_json(data):
        """Assert data is valid JSON."""
        import json
        json.dumps(data)  # Will raise if not serializable
