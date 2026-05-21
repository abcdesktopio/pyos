"""
Unit tests for oc.auth.namedlib module

Tests for name normalization functions used in Kubernetes labels and DNS names
"""
import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import oc.auth.namedlib as namedlib


class TestNormalizeLabel(unittest.TestCase):
    """Test cases for normalize_label function"""
    
    def test_normalize_label_basic_alphanumeric(self):
        """Test with basic alphanumeric string"""
        result = namedlib.normalize_label('MyLabel')
        # normalize_label preserves case (unlike normalize_name)
        self.assertEqual(result, 'MyLabel')
    
    def test_normalize_label_with_dashes(self):
        """Test with dashes"""
        result = namedlib.normalize_label('my-label')
        self.assertEqual(result, 'my-label')
    
    def test_normalize_label_with_underscores(self):
        """Test with underscores"""
        result = namedlib.normalize_label('my_label')
        self.assertEqual(result, 'my_label')
    
    def test_normalize_label_with_dots(self):
        """Test with dots"""
        result = namedlib.normalize_label('my.label')
        self.assertEqual(result, 'my.label')
    
    def test_normalize_label_removes_special_chars(self):
        """Test that special characters are replaced with dashes"""
        result = namedlib.normalize_label('my<label>')
        self.assertIn('label', result)
        self.assertNotIn('<', result)
        self.assertNotIn('>', result)
    
    def test_normalize_label_leading_dash_removed(self):
        """Test that leading dash is removed"""
        result = namedlib.normalize_label('-label')
        self.assertFalse(result.startswith('-'))
    
    def test_normalize_label_trailing_dash_removed(self):
        """Test that trailing dash is removed"""
        result = namedlib.normalize_label('label-')
        self.assertFalse(result.endswith('-'))
    
    def test_normalize_label_max_length_63(self):
        """Test that result is truncated to 63 characters"""
        long_label = 'a' * 100
        result = namedlib.normalize_label(long_label)
        self.assertLessEqual(len(result), 63)
    
    def test_normalize_label_empty_string(self):
        """Test with empty string"""
        result = namedlib.normalize_label('')
        self.assertEqual(result, '')
    
    def test_normalize_label_non_alphanumeric_start(self):
        """Test with non-alphanumeric character at start"""
        result = namedlib.normalize_label('---abc')
        self.assertTrue(result[0].isalnum())
    
    def test_normalize_label_none_input(self):
        """Test with None input"""
        result = namedlib.normalize_label(None)
        self.assertIsNone(result)
    
    def test_normalize_label_unicode_characters(self):
        """Test with unicode characters"""
        result = namedlib.normalize_label('café')
        # normalize_label preserves unicode characters
        self.assertEqual(result, 'café')
    
    def test_normalize_label_real_world_example(self):
        """Test with real-world example from conversation"""
        result = namedlib.normalize_label('- A Zbfd-324-zear')
        # Should be valid Kubernetes label
        self.assertFalse(result.startswith('-'))
        if len(result) > 0:
            self.assertTrue(result[0].isalnum())
            if len(result) > 1:
                self.assertTrue(result[-1].isalnum())


class TestNormalizeName(unittest.TestCase):
    """Test cases for normalize_name function"""
    
    def test_normalize_name_basic(self):
        """Test basic name normalization"""
        result = namedlib.normalize_name('TestName')
        self.assertEqual(result, 'testname')
    
    def test_normalize_name_with_dashes(self):
        """Test that dashes are preserved"""
        result = namedlib.normalize_name('test-name')
        self.assertEqual(result, 'test-name')
    
    def test_normalize_name_with_special_chars(self):
        """Test that special characters are replaced with dashes"""
        result = namedlib.normalize_name('test@name#123')
        self.assertNotIn('@', result)
        self.assertNotIn('#', result)
    
    def test_normalize_name_no_lowercase(self):
        """Test without lowercase conversion"""
        result = namedlib.normalize_name('TestName', tolower=False)
        self.assertNotEqual(result, 'testname')
    
    def test_normalize_name_leading_dash_removed(self):
        """Test that leading dash is removed"""
        result = namedlib.normalize_name('-test')
        self.assertFalse(result.startswith('-'))
    
    def test_normalize_name_trailing_dash_removed(self):
        """Test that trailing dash is removed"""
        result = namedlib.normalize_name('test-')
        self.assertFalse(result.endswith('-'))


class TestNormalizeNameDnsname(unittest.TestCase):
    """Test cases for normalize_name_dnsname function"""
    
    def test_normalize_name_dnsname_max_length(self):
        """Test DNS name max length is 62 characters"""
        long_name = 'a' * 100
        result = namedlib.normalize_name_dnsname(long_name)
        self.assertLessEqual(len(result), 62)
    
    def test_normalize_name_dnsname_basic(self):
        """Test basic DNS name normalization"""
        result = namedlib.normalize_name_dnsname('MyDnsName')
        self.assertEqual(len(result), len('mydnsname'))


class TestNormalizeNameVolumename(unittest.TestCase):
    """Test cases for normalize_name_volunename function"""
    
    def test_normalize_name_volumename_max_length(self):
        """Test volume name max length is 63 characters"""
        long_name = 'a' * 100
        result = namedlib.normalize_name_volunename(long_name)
        self.assertLessEqual(len(result), 63)
    
    def test_normalize_name_volumename_lowercase(self):
        """Test volume name is lowercase"""
        result = namedlib.normalize_name_volunename('MyVolumeName')
        self.assertEqual(result, result.lower())


class TestNormalizeContainername(unittest.TestCase):
    """Test cases for normalize_containername function"""
    
    def test_normalize_containername_with_registry(self):
        """Test normalizing container name with registry path"""
        name = 'registry.domain.tld:443/oc.user.14.04:latest'
        result = namedlib.normalize_containername(name)
        # Should extract the image name part
        self.assertIsNotNone(result)
    
    def test_normalize_containername_simple(self):
        """Test with simple container name"""
        name = 'ubuntu:20.04'
        result = namedlib.normalize_containername(name)
        self.assertIsNotNone(result)


if __name__ == '__main__':
    unittest.main()
