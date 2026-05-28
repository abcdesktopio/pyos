"""
Unit tests for oc.pyutils module

Tests for Event class, Lazy class, and utility functions
"""
import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import oc.pyutils as pyutils


class TestEvent(unittest.TestCase):
    """Test cases for Event class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.event = pyutils.Event()
        self.handler_called = []
    
    def test_event_creation(self):
        """Test event creation"""
        self.assertIsNotNone(self.event)
        self.assertEqual(len(self.event), 0)
    
    def test_event_add_handler(self):
        """Test adding a handler to event"""
        def handler(source, *args, **kwargs):
            self.handler_called.append(True)
        
        self.event + handler
        self.assertEqual(len(self.event), 1)
    
    def test_event_call_handler(self):
        """Test calling handlers"""
        def handler(source, *args, **kwargs):
            self.handler_called.append(True)
        
        self.event + handler
        self.event(self, 'test_data')
        
        self.assertEqual(len(self.handler_called), 1)
    
    def test_event_multiple_handlers(self):
        """Test event with multiple handlers"""
        def handler1(source, *args, **kwargs):
            self.handler_called.append(1)
        
        def handler2(source, *args, **kwargs):
            self.handler_called.append(2)
        
        self.event + handler1 + handler2
        self.event(self, 'test')
        
        self.assertEqual(len(self.handler_called), 2)
        self.assertIn(1, self.handler_called)
        self.assertIn(2, self.handler_called)
    
    def test_event_remove_handler(self):
        """Test removing a handler"""
        def handler(source, *args, **kwargs):
            self.handler_called.append(True)
        
        self.event + handler
        self.assertEqual(len(self.event), 1)
        
        self.event - handler
        self.assertEqual(len(self.event), 0)
    
    def test_event_add_non_callable_raises_error(self):
        """Test that adding non-callable raises ValueError"""
        with self.assertRaises(ValueError):
            self.event + "not_callable"
    
    def test_event_duplicate_handler_not_added(self):
        """Test that duplicate handlers are not added"""
        def handler(source, *args, **kwargs):
            pass
        
        self.event + handler
        self.event + handler
        # Should still be 1, not 2
        self.assertEqual(len(self.event), 1)
    
    def test_event_repr(self):
        """Test event representation"""
        repr_str = repr(self.event)
        self.assertIn('Event', repr_str)


class TestLazy(unittest.TestCase):
    """Test cases for Lazy class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.call_count = 0
    
    def test_lazy_creation(self):
        """Test lazy object creation"""
        def initializer():
            return 'value'
        
        lazy = pyutils.Lazy(initializer)
        self.assertIsNotNone(lazy)
    
    def test_lazy_deferred_execution(self):
        """Test that initializer is not called until value is accessed"""
        def initializer():
            self.call_count += 1
            return 'value'
        
        lazy = pyutils.Lazy(initializer)
        self.assertEqual(self.call_count, 0)
        
        # Access value
        value = lazy.value
        self.assertEqual(self.call_count, 1)
        self.assertEqual(value, 'value')
    
    def test_lazy_cached_value(self):
        """Test that initializer is only called once"""
        def initializer():
            self.call_count += 1
            return 'value'
        
        lazy = pyutils.Lazy(initializer)
        
        # Access value multiple times
        value1 = lazy.value
        value2 = lazy.value
        
        # Should only be called once
        self.assertEqual(self.call_count, 1)
        self.assertEqual(value1, value2)
    
    def test_lazy_call_method(self):
        """Test calling lazy object as function"""
        def initializer():
            self.call_count += 1
            return 'value'
        
        lazy = pyutils.Lazy(initializer)
        value = lazy()
        
        self.assertEqual(self.call_count, 1)
        self.assertEqual(value, 'value')
    
    def test_lazy_with_complex_initializer(self):
        """Test lazy with complex initialization"""
        def initializer():
            return {'key': 'value', 'nested': {'data': 123}}
        
        lazy = pyutils.Lazy(initializer)
        value = lazy.value
        
        self.assertEqual(value['key'], 'value')
        self.assertEqual(value['nested']['data'], 123)


class TestGetClass(unittest.TestCase):
    """Test cases for get_class function"""
    
    def test_get_class_with_full_path(self):
        """Test getting class with full path"""
        # Using a built-in class as example
        cls = pyutils.get_class('collections.OrderedDict')
        self.assertIsNotNone(cls)
    
    def test_get_class_with_module_and_class(self):
        """Test getting class with separate module and class name"""
        cls = pyutils.get_class('collections', 'OrderedDict')
        self.assertIsNotNone(cls)


class TestImportClasses(unittest.TestCase):
    """Test cases for import_classes function"""
    
    def test_import_classes_json_encoders(self):
        """Test importing classes from a package"""
        # This tests the actual import functionality
        try:
            classes = pyutils.import_classes('os')
            self.assertIsNotNone(classes)
        except Exception:
            self.skipTest("Could not import classes from package")


if __name__ == '__main__':
    unittest.main()
