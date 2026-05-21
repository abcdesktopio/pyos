"""
Unit tests for model and schema classes

Tests for data models and schemas used in the project
"""
import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


class TestODDataModels(unittest.TestCase):
    """Test oc.od data models"""
    
    def test_import_od_models(self):
        """Test importing OD model modules"""
        model_modules = [
            'oc.od.apps',
            'oc.od.acl',
            'oc.od.appinstancestatus',
        ]
        
        for module_name in model_modules:
            try:
                __import__(module_name)
            except ImportError:
                # Skip if not available
                pass
    
    def test_od_accounting_module(self):
        """Test accounting module exists"""
        try:
            import oc.od.accounting
            self.assertIsNotNone(oc.od.accounting)
        except ImportError:
            self.skipTest("accounting module not available")


class TestNetworkModules(unittest.TestCase):
    """Test network-related modules"""
    
    def test_import_networks_module(self):
        """Test importing networks module"""
        try:
            import oc.networks
            self.assertIsNotNone(oc.networks)
        except ImportError:
            self.skipTest("networks module not available")
    
    def test_import_thread_event_networks(self):
        """Test importing thread_event_networks"""
        try:
            from oc.networks.thread_event_networks import ThreadEventNetworks
            self.assertIsNotNone(ThreadEventNetworks)
        except ImportError:
            self.skipTest("ThreadEventNetworks not available")


class TestDatastoreModule(unittest.TestCase):
    """Test datastore module"""
    
    def test_import_datastore(self):
        """Test importing datastore module"""
        try:
            import oc.datastore
            self.assertIsNotNone(oc.datastore)
        except ImportError:
            self.skipTest("datastore module not available")


class TestLoggingModule(unittest.TestCase):
    """Test logging module"""
    
    def test_import_logging(self):
        """Test importing oc.logging module"""
        try:
            import oc.logging
            self.assertIsNotNone(oc.logging)
        except ImportError:
            self.skipTest("oc.logging not available")
    
    def test_logging_has_with_logger_decorator(self):
        """Test that logging module has with_logger decorator"""
        try:
            import oc.logging
            self.assertTrue(hasattr(oc.logging, 'with_logger'))
        except ImportError:
            self.skipTest("oc.logging not available")


class TestI18nModule(unittest.TestCase):
    """Test i18n module"""
    
    def test_import_i18n(self):
        """Test importing i18n module"""
        try:
            import oc.i18n
            self.assertIsNotNone(oc.i18n)
        except ImportError:
            self.skipTest("i18n module not available")


if __name__ == '__main__':
    unittest.main()
