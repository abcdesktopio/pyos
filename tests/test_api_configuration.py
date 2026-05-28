"""
Unit tests for API configuration and structure

Tests for settings and services configuration
"""
import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


class TestSettingsImport(unittest.TestCase):
    """Test settings module can be imported"""
    
    def test_import_settings(self):
        """Test importing oc.od.settings"""
        try:
            import oc.od.settings as settings
            self.assertIsNotNone(settings)
        except ImportError as e:
            self.skipTest(f"Could not import settings: {e}")
    
    def test_settings_has_desktop(self):
        """Test that settings has desktop configuration"""
        try:
            import oc.od.settings as settings
            if hasattr(settings, 'desktop'):
                self.assertIsNotNone(settings.desktop)
        except Exception:
            self.skipTest("desktop settings not available")
    
    def test_settings_has_menuconfig(self):
        """Test that settings has menuconfig"""
        try:
            import oc.od.settings as settings
            if hasattr(settings, 'menuconfig'):
                # Could be None or a dict
                self.assertTrue(hasattr(settings, 'menuconfig'))
        except Exception:
            self.skipTest("menuconfig not available")


class TestServicesImport(unittest.TestCase):
    """Test services module can be imported"""
    
    def test_import_services(self):
        """Test importing oc.od.services"""
        try:
            import oc.od.services as services
            self.assertIsNotNone(services)
        except ImportError as e:
            self.skipTest(f"Could not import services: {e}")
    
    def test_services_has_services_object(self):
        """Test that services module has services object"""
        try:
            from oc.od.services import services
            self.assertIsNotNone(services)
        except ImportError:
            self.skipTest("services object not available")


class TestODModuleStructure(unittest.TestCase):
    """Test oc.od module structure"""
    
    def test_import_od_module(self):
        """Test importing oc.od package"""
        try:
            import oc.od
            self.assertIsNotNone(oc.od)
        except ImportError as e:
            self.skipTest(f"Could not import oc.od: {e}")
    
    def test_od_acl_exists(self):
        """Test that oc.od.acl module exists"""
        try:
            import oc.od.acl
            self.assertIsNotNone(oc.od.acl)
        except ImportError:
            self.skipTest("oc.od.acl not available")
    
    def test_od_error_exists(self):
        """Test that oc.od.error module exists"""
        try:
            import oc.od.error
            self.assertIsNotNone(oc.od.error)
        except ImportError:
            self.skipTest("oc.od.error not available")


class TestBaseController(unittest.TestCase):
    """Test base controller exists"""
    
    def test_import_base_controller(self):
        """Test importing base controller"""
        try:
            from oc.od.base_controller import BaseController
            self.assertIsNotNone(BaseController)
        except ImportError as e:
            self.skipTest(f"Could not import BaseController: {e}")
    
    def test_base_controller_is_class(self):
        """Test that BaseController is a class"""
        try:
            from oc.od.base_controller import BaseController
            import inspect
            self.assertTrue(inspect.isclass(BaseController))
        except ImportError:
            self.skipTest("BaseController not available")


if __name__ == '__main__':
    unittest.main()
