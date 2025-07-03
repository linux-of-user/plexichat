"""
Comprehensive authentication endpoint tests.
Tests all authentication-related endpoints with various scenarios.
"""

import asyncio
import time
import json
from typing import Dict, Any, List
import httpx

from .test_base import BaseEndpointTest, TestResult
from netlink.app.logger_config import logger


class AuthEndpointTests(BaseEndpointTest):
    """Comprehensive tests for authentication endpoints."""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        super().__init__(base_url)
        self.category = "authentication"
    
    async def _run_endpoint_tests(self):
        """Run all authentication endpoint tests."""
        await self.test_user_registration()
        await self.test_user_login()
        await self.test_token_validation()
        await self.test_password_reset()
        await self.test_session_management()
        await self.test_rate_limiting()
        await self.test_security_features()
        await self.test_edge_cases()
    
    async def test_user_registration(self):
        """Test user registration endpoint with various scenarios."""
        test_start = time.time()
        
        try:
            async with httpx.AsyncClient() as client:
                # Test 1: Valid registration
                user_data = self.test_data_generator.random_user_data()
                response = await client.post(
                    f"{self.base_url}/api/v1/auth/register",
                    json=user_data
                )
                
                duration = (time.time() - test_start) * 1000
                
                if response.status_code == 201:
                    self.record_test_result(
                        test_name="Valid User Registration",
                        category=self.category,
                        endpoint="/api/v1/auth/register",
                        method="POST",
                        status="passed",
                        duration_ms=duration,
                        request_data=user_data,
                        response_data=response.json(),
                        status_code=response.status_code
                    )
                else:
                    self.record_test_result(
                        test_name="Valid User Registration",
                        category=self.category,
                        endpoint="/api/v1/auth/register",
                        method="POST",
                        status="failed",
                        duration_ms=duration,
                        error_message=f"Expected 201, got {response.status_code}",
                        status_code=response.status_code
                    )
                
                # Test 2: Duplicate username
                test_start = time.time()
                duplicate_response = await client.post(
                    f"{self.base_url}/api/v1/auth/register",
                    json=user_data
                )
                duration = (time.time() - test_start) * 1000
                
                if duplicate_response.status_code == 400:
                    self.record_test_result(
                        test_name="Duplicate Username Registration",
                        category=self.category,
                        endpoint="/api/v1/auth/register",
                        method="POST",
                        status="passed",
                        duration_ms=duration,
                        status_code=duplicate_response.status_code
                    )
                else:
                    self.record_test_result(
                        test_name="Duplicate Username Registration",
                        category=self.category,
                        endpoint="/api/v1/auth/register",
                        method="POST",
                        status="failed",
                        duration_ms=duration,
                        error_message=f"Expected 400, got {duplicate_response.status_code}",
                        status_code=duplicate_response.status_code
                    )
                
                # Test 3: Invalid email format
                test_start = time.time()
                invalid_user = self.test_data_generator.random_user_data()
                invalid_user["email"] = "invalid-email-format"
                
                invalid_response = await client.post(
                    f"{self.base_url}/api/v1/auth/register",
                    json=invalid_user
                )
                duration = (time.time() - test_start) * 1000
                
                if invalid_response.status_code == 422:
                    self.record_test_result(
                        test_name="Invalid Email Format Registration",
                        category=self.category,
                        endpoint="/api/v1/auth/register",
                        method="POST",
                        status="passed",
                        duration_ms=duration,
                        status_code=invalid_response.status_code
                    )
                else:
                    self.record_test_result(
                        test_name="Invalid Email Format Registration",
                        category=self.category,
                        endpoint="/api/v1/auth/register",
                        method="POST",
                        status="failed",
                        duration_ms=duration,
                        error_message=f"Expected 422, got {invalid_response.status_code}",
                        status_code=invalid_response.status_code
                    )
                
                # Test 4: Weak password
                test_start = time.time()
                weak_user = self.test_data_generator.random_user_data()
                weak_user["password"] = "123"
                
                weak_response = await client.post(
                    f"{self.base_url}/api/v1/auth/register",
                    json=weak_user
                )
                duration = (time.time() - test_start) * 1000
                
                if weak_response.status_code in [400, 422]:
                    self.record_test_result(
                        test_name="Weak Password Registration",
                        category=self.category,
                        endpoint="/api/v1/auth/register",
                        method="POST",
                        status="passed",
                        duration_ms=duration,
                        status_code=weak_response.status_code
                    )
                else:
                    self.record_test_result(
                        test_name="Weak Password Registration",
                        category=self.category,
                        endpoint="/api/v1/auth/register",
                        method="POST",
                        status="warning",
                        duration_ms=duration,
                        error_message=f"Weak password accepted, got {weak_response.status_code}",
                        status_code=weak_response.status_code
                    )
        
        except Exception as e:
            self.record_test_result(
                test_name="User Registration Tests",
                category=self.category,
                endpoint="/api/v1/auth/register",
                method="POST",
                status="failed",
                duration_ms=(time.time() - test_start) * 1000,
                error_message=str(e)
            )
    
    async def test_user_login(self):
        """Test user login endpoint with various scenarios."""
        test_start = time.time()
        
        try:
            async with httpx.AsyncClient() as client:
                # First register a user for login tests
                user_data = self.test_data_generator.random_user_data()
                await client.post(f"{self.base_url}/api/v1/auth/register", json=user_data)
                
                # Test 1: Valid login
                login_data = {
                    "username": user_data["username"],
                    "password": user_data["password"]
                }
                
                response = await client.post(
                    f"{self.base_url}/api/v1/auth/login",
                    data=login_data
                )
                
                duration = (time.time() - test_start) * 1000
                
                if response.status_code == 200:
                    response_data = response.json()
                    if "access_token" in response_data:
                        self.auth_tokens[user_data["username"]] = response_data["access_token"]
                        self.record_test_result(
                            test_name="Valid User Login",
                            category=self.category,
                            endpoint="/api/v1/auth/login",
                            method="POST",
                            status="passed",
                            duration_ms=duration,
                            status_code=response.status_code,
                            performance_metrics={"token_generation_time_ms": duration}
                        )
                    else:
                        self.record_test_result(
                            test_name="Valid User Login",
                            category=self.category,
                            endpoint="/api/v1/auth/login",
                            method="POST",
                            status="failed",
                            duration_ms=duration,
                            error_message="No access token in response",
                            status_code=response.status_code
                        )
                else:
                    self.record_test_result(
                        test_name="Valid User Login",
                        category=self.category,
                        endpoint="/api/v1/auth/login",
                        method="POST",
                        status="failed",
                        duration_ms=duration,
                        error_message=f"Expected 200, got {response.status_code}",
                        status_code=response.status_code
                    )
                
                # Test 2: Invalid password
                test_start = time.time()
                invalid_login = {
                    "username": user_data["username"],
                    "password": "wrong_password"
                }
                
                invalid_response = await client.post(
                    f"{self.base_url}/api/v1/auth/login",
                    data=invalid_login
                )
                duration = (time.time() - test_start) * 1000
                
                if invalid_response.status_code == 401:
                    self.record_test_result(
                        test_name="Invalid Password Login",
                        category=self.category,
                        endpoint="/api/v1/auth/login",
                        method="POST",
                        status="passed",
                        duration_ms=duration,
                        status_code=invalid_response.status_code
                    )
                else:
                    self.record_test_result(
                        test_name="Invalid Password Login",
                        category=self.category,
                        endpoint="/api/v1/auth/login",
                        method="POST",
                        status="failed",
                        duration_ms=duration,
                        error_message=f"Expected 401, got {invalid_response.status_code}",
                        status_code=invalid_response.status_code
                    )
                
                # Test 3: Non-existent user
                test_start = time.time()
                nonexistent_login = {
                    "username": "nonexistent_user_12345",
                    "password": "any_password"
                }
                
                nonexistent_response = await client.post(
                    f"{self.base_url}/api/v1/auth/login",
                    data=nonexistent_login
                )
                duration = (time.time() - test_start) * 1000
                
                if nonexistent_response.status_code == 401:
                    self.record_test_result(
                        test_name="Non-existent User Login",
                        category=self.category,
                        endpoint="/api/v1/auth/login",
                        method="POST",
                        status="passed",
                        duration_ms=duration,
                        status_code=nonexistent_response.status_code
                    )
                else:
                    self.record_test_result(
                        test_name="Non-existent User Login",
                        category=self.category,
                        endpoint="/api/v1/auth/login",
                        method="POST",
                        status="failed",
                        duration_ms=duration,
                        error_message=f"Expected 401, got {nonexistent_response.status_code}",
                        status_code=nonexistent_response.status_code
                    )
        
        except Exception as e:
            self.record_test_result(
                test_name="User Login Tests",
                category=self.category,
                endpoint="/api/v1/auth/login",
                method="POST",
                status="failed",
                duration_ms=(time.time() - test_start) * 1000,
                error_message=str(e)
            )
    
    async def test_token_validation(self):
        """Test token validation and protected endpoints."""
        test_start = time.time()
        
        try:
            async with httpx.AsyncClient() as client:
                # Test with valid token
                if self.auth_tokens:
                    token = list(self.auth_tokens.values())[0]
                    headers = {"Authorization": f"Bearer {token}"}
                    
                    response = await client.get(
                        f"{self.base_url}/api/v1/users/me",
                        headers=headers
                    )
                    
                    duration = (time.time() - test_start) * 1000
                    
                    if response.status_code == 200:
                        self.record_test_result(
                            test_name="Valid Token Access",
                            category=self.category,
                            endpoint="/api/v1/users/me",
                            method="GET",
                            status="passed",
                            duration_ms=duration,
                            status_code=response.status_code
                        )
                    else:
                        self.record_test_result(
                            test_name="Valid Token Access",
                            category=self.category,
                            endpoint="/api/v1/users/me",
                            method="GET",
                            status="failed",
                            duration_ms=duration,
                            error_message=f"Expected 200, got {response.status_code}",
                            status_code=response.status_code
                        )
                
                # Test with invalid token
                test_start = time.time()
                invalid_headers = {"Authorization": "Bearer invalid_token_12345"}
                
                invalid_response = await client.get(
                    f"{self.base_url}/api/v1/users/me",
                    headers=invalid_headers
                )
                duration = (time.time() - test_start) * 1000
                
                if invalid_response.status_code == 401:
                    self.record_test_result(
                        test_name="Invalid Token Access",
                        category=self.category,
                        endpoint="/api/v1/users/me",
                        method="GET",
                        status="passed",
                        duration_ms=duration,
                        status_code=invalid_response.status_code
                    )
                else:
                    self.record_test_result(
                        test_name="Invalid Token Access",
                        category=self.category,
                        endpoint="/api/v1/users/me",
                        method="GET",
                        status="failed",
                        duration_ms=duration,
                        error_message=f"Expected 401, got {invalid_response.status_code}",
                        status_code=invalid_response.status_code
                    )
                
                # Test without token
                test_start = time.time()
                no_token_response = await client.get(f"{self.base_url}/api/v1/users/me")
                duration = (time.time() - test_start) * 1000
                
                if no_token_response.status_code == 401:
                    self.record_test_result(
                        test_name="No Token Access",
                        category=self.category,
                        endpoint="/api/v1/users/me",
                        method="GET",
                        status="passed",
                        duration_ms=duration,
                        status_code=no_token_response.status_code
                    )
                else:
                    self.record_test_result(
                        test_name="No Token Access",
                        category=self.category,
                        endpoint="/api/v1/users/me",
                        method="GET",
                        status="failed",
                        duration_ms=duration,
                        error_message=f"Expected 401, got {no_token_response.status_code}",
                        status_code=no_token_response.status_code
                    )
        
        except Exception as e:
            self.record_test_result(
                test_name="Token Validation Tests",
                category=self.category,
                endpoint="/api/v1/users/me",
                method="GET",
                status="failed",
                duration_ms=(time.time() - test_start) * 1000,
                error_message=str(e)
            )
    
    async def test_password_reset(self):
        """Test password reset functionality."""
        # This would test password reset endpoints if they exist
        self.record_test_result(
            test_name="Password Reset",
            category=self.category,
            endpoint="/api/v1/auth/reset-password",
            method="POST",
            status="skipped",
            duration_ms=0,
            error_message="Password reset endpoint not implemented yet"
        )
    
    async def test_session_management(self):
        """Test session management features."""
        # This would test session management if implemented
        self.record_test_result(
            test_name="Session Management",
            category=self.category,
            endpoint="/api/v1/auth/sessions",
            method="GET",
            status="skipped",
            duration_ms=0,
            error_message="Session management endpoints not implemented yet"
        )
    
    async def test_rate_limiting(self):
        """Test rate limiting on authentication endpoints."""
        test_start = time.time()
        
        try:
            async with httpx.AsyncClient() as client:
                # Attempt multiple rapid login attempts
                login_data = {
                    "username": "nonexistent_user",
                    "password": "wrong_password"
                }
                
                responses = []
                for i in range(10):  # Try 10 rapid attempts
                    response = await client.post(
                        f"{self.base_url}/api/v1/auth/login",
                        data=login_data
                    )
                    responses.append(response.status_code)
                
                duration = (time.time() - test_start) * 1000
                
                # Check if rate limiting kicks in
                if 429 in responses:  # Too Many Requests
                    self.record_test_result(
                        test_name="Rate Limiting Protection",
                        category=self.category,
                        endpoint="/api/v1/auth/login",
                        method="POST",
                        status="passed",
                        duration_ms=duration,
                        performance_metrics={"attempts_before_limit": responses.index(429) + 1}
                    )
                else:
                    self.record_test_result(
                        test_name="Rate Limiting Protection",
                        category=self.category,
                        endpoint="/api/v1/auth/login",
                        method="POST",
                        status="warning",
                        duration_ms=duration,
                        error_message="No rate limiting detected after 10 attempts"
                    )
        
        except Exception as e:
            self.record_test_result(
                test_name="Rate Limiting Tests",
                category=self.category,
                endpoint="/api/v1/auth/login",
                method="POST",
                status="failed",
                duration_ms=(time.time() - test_start) * 1000,
                error_message=str(e)
            )
    
    async def test_security_features(self):
        """Test security features like SQL injection protection."""
        test_start = time.time()
        
        try:
            async with httpx.AsyncClient() as client:
                # Test SQL injection in login
                sql_injection_attempts = [
                    "admin'; DROP TABLE users; --",
                    "' OR '1'='1",
                    "admin'/**/OR/**/1=1#",
                    "'; UNION SELECT * FROM users; --"
                ]
                
                for injection in sql_injection_attempts:
                    login_data = {
                        "username": injection,
                        "password": "any_password"
                    }
                    
                    response = await client.post(
                        f"{self.base_url}/api/v1/auth/login",
                        data=login_data
                    )
                    
                    # Should not succeed with SQL injection
                    if response.status_code == 200:
                        self.record_test_result(
                            test_name="SQL Injection Protection",
                            category=self.category,
                            endpoint="/api/v1/auth/login",
                            method="POST",
                            status="failed",
                            duration_ms=(time.time() - test_start) * 1000,
                            error_message=f"SQL injection succeeded: {injection}",
                            status_code=response.status_code
                        )
                        return
                
                duration = (time.time() - test_start) * 1000
                self.record_test_result(
                    test_name="SQL Injection Protection",
                    category=self.category,
                    endpoint="/api/v1/auth/login",
                    method="POST",
                    status="passed",
                    duration_ms=duration,
                    performance_metrics={"injection_attempts_blocked": len(sql_injection_attempts)}
                )
        
        except Exception as e:
            self.record_test_result(
                test_name="Security Features Tests",
                category=self.category,
                endpoint="/api/v1/auth/login",
                method="POST",
                status="failed",
                duration_ms=(time.time() - test_start) * 1000,
                error_message=str(e)
            )
    
    async def test_edge_cases(self):
        """Test edge cases and boundary conditions."""
        test_start = time.time()
        
        try:
            async with httpx.AsyncClient() as client:
                # Test extremely long username
                long_user = self.test_data_generator.random_user_data()
                long_user["username"] = "a" * 1000  # Very long username
                
                response = await client.post(
                    f"{self.base_url}/api/v1/auth/register",
                    json=long_user
                )
                
                duration = (time.time() - test_start) * 1000
                
                if response.status_code in [400, 422]:
                    self.record_test_result(
                        test_name="Long Username Rejection",
                        category=self.category,
                        endpoint="/api/v1/auth/register",
                        method="POST",
                        status="passed",
                        duration_ms=duration,
                        status_code=response.status_code
                    )
                else:
                    self.record_test_result(
                        test_name="Long Username Rejection",
                        category=self.category,
                        endpoint="/api/v1/auth/register",
                        method="POST",
                        status="warning",
                        duration_ms=duration,
                        error_message=f"Long username accepted, got {response.status_code}",
                        status_code=response.status_code
                    )
        
        except Exception as e:
            self.record_test_result(
                test_name="Edge Cases Tests",
                category=self.category,
                endpoint="/api/v1/auth/register",
                method="POST",
                status="failed",
                duration_ms=(time.time() - test_start) * 1000,
                error_message=str(e)
            )
