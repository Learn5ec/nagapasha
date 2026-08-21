"""Tests for the template support module."""

import json
import pytest
from pathlib import Path

from nagapasha.engine.template import TemplateManager, TemplateError


class TestTemplateManager:
    """Tests for TemplateManager."""

    @pytest.fixture
    def tmpl_dir(self, tmp_path):
        """Create a temporary template directory."""
        return tmp_path / "templates"

    @pytest.fixture
    def manager(self, tmpl_dir):
        """Create a TemplateManager with temp dir."""
        return TemplateManager(template_dir=tmpl_dir)

    def test_create_basic_template(self, manager, tmpl_dir):
        """Should create a basic template."""
        path = manager.create(
            name="my-api",
            target_url="https://example.com/api",
            method="GET",
        )
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["name"] == "my-api"
        assert data["target_url"] == "https://example.com/api"
        assert data["method"] == "GET"

    def test_create_with_all_fields(self, manager, tmpl_dir):
        """Should create a template with all fields."""
        path = manager.create(
            name="full-api",
            target_url="https://example.com/api",
            method="POST",
            headers={"X-Custom": "value"},
            cookies={"session": "abc123"},
            body='{"key": "val"}',
            body_type="json",
            fuzz_preferences={"max_requests": 500},
        )
        data = json.loads(path.read_text())
        assert data["headers"] == {"X-Custom": "value"}
        assert data["cookies"] == {"session": "abc123"}
        assert data["body"] == '{"key": "val"}'
        assert data["body_type"] == "json"
        assert data["fuzz_preferences"]["max_requests"] == 500

    def test_create_duplicate_raises(self, manager, tmpl_dir):
        """Should raise on duplicate template name."""
        manager.create(name="dup", target_url="https://example.com")
        with pytest.raises(TemplateError, match="already exists"):
            manager.create(name="dup", target_url="https://other.com")

    def test_create_missing_name_raises(self, manager):
        """Should raise when name is empty."""
        with pytest.raises(TemplateError, match="name is required"):
            manager.create(name="", target_url="https://example.com")

    def test_create_missing_url_raises(self, manager):
        """Should raise when target_url is empty."""
        with pytest.raises(TemplateError, match="Target URL is required"):
            manager.create(name="test", target_url="")

    def test_create_invalid_method_raises(self, manager):
        """Should raise on invalid HTTP method."""
        with pytest.raises(TemplateError, match="Invalid method"):
            manager.create(name="test", target_url="https://example.com", method="INVALID")

    def test_create_invalid_body_type_raises(self, manager):
        """Should raise on invalid body_type."""
        with pytest.raises(TemplateError, match="Invalid body_type"):
            manager.create(
                name="test",
                target_url="https://example.com",
                body_type="invalid",
            )

    def test_load_template(self, manager):
        """Should load a valid template."""
        manager.create(name="test", target_url="https://example.com")
        data = manager.load("test")
        assert data["target_url"] == "https://example.com"

    def test_load_nonexistent_raises(self, manager):
        """Should raise when loading nonexistent template."""
        with pytest.raises(TemplateError, match="not found"):
            manager.load("does-not-exist")

    def test_list_templates(self, manager):
        """Should list all available templates."""
        manager.create(name="api-1", target_url="https://a.com")
        manager.create(name="api-2", target_url="https://b.com")
        templates = manager.list_templates()
        assert len(templates) == 2
        names = {t["name"] for t in templates}
        assert names == {"api-1", "api-2"}

    def test_list_empty(self, manager):
        """Should return empty list when no templates."""
        templates = manager.list_templates()
        assert templates == []

    def test_delete_template(self, manager):
        """Should delete an existing template."""
        manager.create(name="to-delete", target_url="https://example.com")
        assert manager.delete("to-delete") is True
        assert not (manager.template_dir / "to-delete.json").exists()

    def test_delete_nonexistent_returns_false(self, manager):
        """Should return False when deleting nonexistent template."""
        assert manager.delete("nope") is False

    def test_validate_valid_template(self, manager):
        """Should not raise for valid template data."""
        data = {"name": "test", "target_url": "https://example.com", "method": "GET"}
        manager.validate(data)  # should not raise

    def test_validate_missing_field_raises(self, manager):
        """Should raise when required field is missing."""
        data = {"name": "test", "target_url": "https://example.com"}
        with pytest.raises(TemplateError, match="Missing required field"):
            manager.validate(data)

    def test_validate_invalid_method_raises(self, manager):
        """Should raise on invalid method."""
        data = {"name": "test", "target_url": "https://example.com", "method": "BAD"}
        with pytest.raises(TemplateError, match="Invalid method"):
            manager.validate(data)

    def test_get_curl_command(self, manager):
        """Should generate a valid curl command from template."""
        data = {
            "name": "test",
            "target_url": "https://example.com/api",
            "method": "POST",
            "headers": {"Content-Type": "application/json", "X-Auth": "token"},
            "cookies": {},
            "body": '{"key": "val"}',
            "body_type": "json",
        }
        curl = manager.get_curl_command(data)
        assert "curl" in curl
        assert "-X POST" in curl
        assert "'https://example.com/api'" in curl
        assert "X-Auth: token" in curl
        assert "Content-Type: application/json" in curl
        assert "'{\"key\": \"val\"}'" in curl
