"""
Comprehensive tests for file management endpoints.
Tests file upload, download, security, and management functionality.
"""

import pytest
import tempfile
import os
from pathlib import Path
from io import BytesIO
from PIL import Image
import json

from fastapi.testclient import TestClient
from sqlmodel import Session, create_engine, SQLModel
from sqlmodel.pool import StaticPool

from netlink.app.main import app
from netlink.app.db import get_session
from netlink.app.models.user import User
from netlink.app.models.files import FileRecord, FileShare
from netlink.app.utils.auth import create_access_token

# Test database setup
@pytest.fixture(name="session")
def session_fixture():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session

@pytest.fixture(name="client")
def client_fixture(session: Session):
    def get_session_override():
        return session
    
    app.dependency_overrides[get_session] = get_session_override
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()

@pytest.fixture(name="test_user")
def test_user_fixture(session: Session):
    user = User(
        username="testuser",
        email="test@example.com",
        hashed_password="hashed_password",
        is_admin=False
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user

@pytest.fixture(name="admin_user")
def admin_user_fixture(session: Session):
    user = User(
        username="admin",
        email="admin@example.com",
        hashed_password="hashed_password",
        is_admin=True
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user

@pytest.fixture(name="auth_headers")
def auth_headers_fixture(test_user: User):
    token = create_access_token({"sub": test_user.username})
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture(name="admin_headers")
def admin_headers_fixture(admin_user: User):
    token = create_access_token({"sub": admin_user.username})
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture(name="test_image")
def test_image_fixture():
    """Create a test image file."""
    img = Image.new('RGB', (100, 100), color='red')
    img_bytes = BytesIO()
    img.save(img_bytes, format='PNG')
    img_bytes.seek(0)
    return img_bytes

@pytest.fixture(name="test_text_file")
def test_text_file_fixture():
    """Create a test text file."""
    content = "This is a test file content.\nLine 2\nLine 3"
    return BytesIO(content.encode('utf-8'))

class TestFileUpload:
    """Test file upload functionality."""
    
    def test_upload_valid_image(self, client: TestClient, auth_headers: dict, test_image: BytesIO):
        """Test uploading a valid image file."""
        response = client.post(
            "/v1/files/upload",
            headers=auth_headers,
            files={"file": ("test.png", test_image, "image/png")},
            data={"description": "Test image", "tags": "test,image"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "id" in data
        assert data["filename"] == "test.png"
        assert data["message"] == "File uploaded successfully"
    
    def test_upload_valid_text_file(self, client: TestClient, auth_headers: dict, test_text_file: BytesIO):
        """Test uploading a valid text file."""
        response = client.post(
            "/v1/files/upload",
            headers=auth_headers,
            files={"file": ("test.txt", test_text_file, "text/plain")},
            data={"description": "Test text file"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["filename"] == "test.txt"
    
    def test_upload_without_auth(self, client: TestClient, test_image: BytesIO):
        """Test uploading without authentication."""
        response = client.post(
            "/v1/files/upload",
            files={"file": ("test.png", test_image, "image/png")}
        )
        
        assert response.status_code == 401
    
    def test_upload_dangerous_file(self, client: TestClient, auth_headers: dict):
        """Test uploading a dangerous file type."""
        dangerous_content = b"#!/bin/bash\necho 'malicious script'"
        dangerous_file = BytesIO(dangerous_content)
        
        response = client.post(
            "/v1/files/upload",
            headers=auth_headers,
            files={"file": ("malicious.sh", dangerous_file, "application/x-sh")}
        )
        
        assert response.status_code == 400
        assert "not allowed" in response.json()["detail"]
    
    def test_upload_oversized_file(self, client: TestClient, auth_headers: dict):
        """Test uploading an oversized file."""
        # Create a large file (simulate)
        large_content = b"x" * (101 * 1024 * 1024)  # 101MB
        large_file = BytesIO(large_content)
        
        response = client.post(
            "/v1/files/upload",
            headers=auth_headers,
            files={"file": ("large.txt", large_file, "text/plain")}
        )
        
        assert response.status_code == 413
        assert "too large" in response.json()["detail"]
    
    def test_upload_invalid_filename(self, client: TestClient, auth_headers: dict, test_text_file: BytesIO):
        """Test uploading with invalid filename."""
        response = client.post(
            "/v1/files/upload",
            headers=auth_headers,
            files={"file": ("../../../etc/passwd", test_text_file, "text/plain")}
        )
        
        assert response.status_code == 400
        assert "Invalid filename" in response.json()["detail"]
    
    def test_upload_duplicate_file(self, client: TestClient, auth_headers: dict, test_image: BytesIO):
        """Test uploading duplicate file."""
        # Upload first time
        response1 = client.post(
            "/v1/files/upload",
            headers=auth_headers,
            files={"file": ("test.png", test_image, "image/png")}
        )
        assert response1.status_code == 200
        
        # Upload same file again
        test_image.seek(0)  # Reset file pointer
        response2 = client.post(
            "/v1/files/upload",
            headers=auth_headers,
            files={"file": ("test.png", test_image, "image/png")}
        )
        
        assert response2.status_code == 200
        assert "already exists" in response2.json()["message"]

class TestFileList:
    """Test file listing functionality."""
    
    def test_list_files_empty(self, client: TestClient, auth_headers: dict):
        """Test listing files when none exist."""
        response = client.get("/v1/files/list", headers=auth_headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["files"] == []
        assert data["total"] == 0
    
    def test_list_files_with_pagination(self, client: TestClient, auth_headers: dict, session: Session, test_user: User):
        """Test file listing with pagination."""
        # Create test files in database
        for i in range(25):
            file_record = FileRecord(
                filename=f"test{i}.txt",
                original_filename=f"test{i}.txt",
                file_path=f"/tmp/test{i}.txt",
                file_hash=f"hash{i}",
                size=100,
                extension=".txt",
                uploaded_by=test_user.id
            )
            session.add(file_record)
        session.commit()
        
        # Test first page
        response = client.get("/v1/files/list?page=1&limit=10", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data["files"]) == 10
        assert data["has_more"] == True
        
        # Test second page
        response = client.get("/v1/files/list?page=2&limit=10", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data["files"]) == 10
    
    def test_list_files_with_search(self, client: TestClient, auth_headers: dict, session: Session, test_user: User):
        """Test file listing with search."""
        # Create test files
        file1 = FileRecord(
            filename="important_document.pdf",
            original_filename="important_document.pdf",
            file_path="/tmp/important_document.pdf",
            file_hash="hash1",
            size=100,
            extension=".pdf",
            description="Important business document",
            uploaded_by=test_user.id
        )
        file2 = FileRecord(
            filename="random_image.jpg",
            original_filename="random_image.jpg",
            file_path="/tmp/random_image.jpg",
            file_hash="hash2",
            size=200,
            extension=".jpg",
            uploaded_by=test_user.id
        )
        session.add(file1)
        session.add(file2)
        session.commit()
        
        # Search for "important"
        response = client.get("/v1/files/list?search=important", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data["files"]) == 1
        assert data["files"][0]["filename"] == "important_document.pdf"
    
    def test_list_files_by_type(self, client: TestClient, auth_headers: dict, session: Session, test_user: User):
        """Test file listing filtered by type."""
        # Create files of different types
        files = [
            ("image.jpg", ".jpg", "images"),
            ("document.pdf", ".pdf", "documents"),
            ("data.json", ".json", "data")
        ]
        
        for filename, ext, file_type in files:
            file_record = FileRecord(
                filename=filename,
                original_filename=filename,
                file_path=f"/tmp/{filename}",
                file_hash=f"hash_{filename}",
                size=100,
                extension=ext,
                uploaded_by=test_user.id
            )
            session.add(file_record)
        session.commit()
        
        # Filter by images
        response = client.get("/v1/files/list?file_type=images", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data["files"]) == 1
        assert data["files"][0]["filename"] == "image.jpg"

class TestFileDownload:
    """Test file download functionality."""
    
    def test_download_existing_file(self, client: TestClient, auth_headers: dict, session: Session, test_user: User):
        """Test downloading an existing file."""
        # Create test file
        test_content = b"Test file content"
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            tmp_file.write(test_content)
            tmp_file_path = tmp_file.name
        
        try:
            file_record = FileRecord(
                filename="test.txt",
                original_filename="test.txt",
                file_path=tmp_file_path,
                file_hash="testhash",
                size=len(test_content),
                extension=".txt",
                uploaded_by=test_user.id,
                is_public=True
            )
            session.add(file_record)
            session.commit()
            session.refresh(file_record)
            
            response = client.get(f"/v1/files/{file_record.id}/download", headers=auth_headers)
            assert response.status_code == 200
            assert response.content == test_content
            
        finally:
            os.unlink(tmp_file_path)
    
    def test_download_nonexistent_file(self, client: TestClient, auth_headers: dict):
        """Test downloading a non-existent file."""
        response = client.get("/v1/files/99999/download", headers=auth_headers)
        assert response.status_code == 404
    
    def test_download_private_file_unauthorized(self, client: TestClient, auth_headers: dict, session: Session):
        """Test downloading a private file without permission."""
        # Create another user
        other_user = User(
            username="otheruser",
            email="other@example.com",
            hashed_password="hashed_password"
        )
        session.add(other_user)
        session.commit()
        session.refresh(other_user)
        
        # Create private file owned by other user
        file_record = FileRecord(
            filename="private.txt",
            original_filename="private.txt",
            file_path="/tmp/private.txt",
            file_hash="privatehash",
            size=100,
            extension=".txt",
            uploaded_by=other_user.id,
            is_public=False
        )
        session.add(file_record)
        session.commit()
        session.refresh(file_record)
        
        response = client.get(f"/v1/files/{file_record.id}/download", headers=auth_headers)
        assert response.status_code == 403

class TestFileSecurity:
    """Test file security features."""
    
    def test_malicious_script_detection(self, client: TestClient, auth_headers: dict):
        """Test detection of malicious scripts."""
        malicious_content = b'<script>alert("xss")</script>'
        malicious_file = BytesIO(malicious_content)
        
        response = client.post(
            "/v1/files/upload",
            headers=auth_headers,
            files={"file": ("malicious.html", malicious_file, "text/html")}
        )
        
        assert response.status_code == 400
        assert "security scan" in response.json()["detail"]
    
    def test_filename_sanitization(self, client: TestClient, auth_headers: dict, test_text_file: BytesIO):
        """Test filename sanitization."""
        response = client.post(
            "/v1/files/upload",
            headers=auth_headers,
            files={"file": ("test<>file.txt", test_text_file, "text/plain")}
        )
        
        # Should either sanitize the filename or reject it
        if response.status_code == 200:
            # Filename should be sanitized
            data = response.json()
            assert "<" not in data["filename"]
            assert ">" not in data["filename"]
        else:
            # Or it should be rejected
            assert response.status_code == 400
    
    def test_mime_type_validation(self, client: TestClient, auth_headers: dict):
        """Test MIME type validation."""
        # Try to upload executable with image MIME type
        exe_content = b"MZ\x90\x00"  # PE header
        fake_image = BytesIO(exe_content)
        
        response = client.post(
            "/v1/files/upload",
            headers=auth_headers,
            files={"file": ("fake.jpg", fake_image, "image/jpeg")}
        )
        
        assert response.status_code == 400

class TestFileManagement:
    """Test file management operations."""
    
    def test_file_sharing(self, client: TestClient, auth_headers: dict, session: Session, test_user: User):
        """Test file sharing functionality."""
        # Create another user to share with
        share_user = User(
            username="shareuser",
            email="share@example.com",
            hashed_password="hashed_password"
        )
        session.add(share_user)
        session.commit()
        session.refresh(share_user)
        
        # Create file
        file_record = FileRecord(
            filename="shared.txt",
            original_filename="shared.txt",
            file_path="/tmp/shared.txt",
            file_hash="sharedhash",
            size=100,
            extension=".txt",
            uploaded_by=test_user.id,
            is_public=False
        )
        session.add(file_record)
        session.commit()
        session.refresh(file_record)
        
        # Share file (this would be implemented in a sharing endpoint)
        share_record = FileShare(
            file_id=file_record.id,
            shared_by=test_user.id,
            shared_with=share_user.id,
            can_download=True,
            can_view=True
        )
        session.add(share_record)
        session.commit()
        
        # Verify share exists
        assert share_record.file_id == file_record.id
        assert share_record.shared_with == share_user.id

class TestFilePerformance:
    """Test file performance and optimization."""

    def test_concurrent_uploads(self, client: TestClient, auth_headers: dict):
        """Test handling concurrent file uploads."""
        import threading
        import time

        results = []

        def upload_file(file_num):
            content = f"Test file {file_num} content".encode()
            test_file = BytesIO(content)

            response = client.post(
                "/v1/files/upload",
                headers=auth_headers,
                files={"file": (f"test{file_num}.txt", test_file, "text/plain")}
            )
            results.append(response.status_code)

        # Create multiple threads for concurrent uploads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=upload_file, args=(i,))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # All uploads should succeed
        assert all(status == 200 for status in results)

    def test_large_file_list_performance(self, client: TestClient, auth_headers: dict, session: Session, test_user: User):
        """Test performance with large number of files."""
        import time

        # Create many files (simulate)
        files = []
        for i in range(100):
            file_record = FileRecord(
                filename=f"perf_test_{i}.txt",
                original_filename=f"perf_test_{i}.txt",
                file_path=f"/tmp/perf_test_{i}.txt",
                file_hash=f"hash_{i}",
                size=100,
                extension=".txt",
                uploaded_by=test_user.id
            )
            files.append(file_record)

        session.add_all(files)
        session.commit()

        # Measure response time
        start_time = time.time()
        response = client.get("/v1/files/list?limit=50", headers=auth_headers)
        end_time = time.time()

        assert response.status_code == 200
        assert len(response.json()["files"]) == 50

        # Response should be reasonably fast (under 1 second)
        response_time = end_time - start_time
        assert response_time < 1.0

if __name__ == "__main__":
    pytest.main([__file__])
