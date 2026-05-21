"""
Unit tests for oc.lib module

Tests for utility functions like randomStringwithDigitsAndSymbols, remove_accents, etc.
"""
import unittest
import sys
import os
import string

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import oc.lib as lib


class TestRandomStringwithDigitsAndSymbols(unittest.TestCase):
    """Test cases for randomStringwithDigitsAndSymbols function"""
    
    def test_random_string_default_length(self):
        """Test random string generation with default length"""
        result = lib.randomStringwithDigitsAndSymbols()
        self.assertEqual(len(result), 10)
    
    def test_random_string_custom_length(self):
        """Test random string generation with custom length"""
        for length in [5, 15, 32, 64]:
            result = lib.randomStringwithDigitsAndSymbols(length)
            self.assertEqual(len(result), length)
    
    def test_random_string_contains_valid_chars(self):
        """Test that random string contains only allowed characters"""
        result = lib.randomStringwithDigitsAndSymbols(100)
        allowed_chars = set(string.ascii_letters + string.digits)
        
        for char in result:
            self.assertIn(char, allowed_chars)
    
    def test_random_string_is_random(self):
        """Test that generated strings are different"""
        str1 = lib.randomStringwithDigitsAndSymbols(20)
        str2 = lib.randomStringwithDigitsAndSymbols(20)
        # Very unlikely to be the same
        self.assertNotEqual(str1, str2)
    
    def test_random_string_zero_length(self):
        """Test with zero length"""
        result = lib.randomStringwithDigitsAndSymbols(0)
        self.assertEqual(len(result), 0)


class TestRemoveAccents(unittest.TestCase):
    """Test cases for remove_accents function"""
    
    def test_remove_accents_basic(self):
        """Test removing accents from basic accented string"""
        result = lib.remove_accents('café')
        self.assertNotIn('é', result)
        # Result should be lowercase
        self.assertEqual(result, result.lower())
    
    def test_remove_accents_french_accents(self):
        """Test removing French accents"""
        test_cases = {
            'été': 'ete',
            'élève': 'eleve',
            'résumé': 'resume',
        }
        for input_str, expected in test_cases.items():
            result = lib.remove_accents(input_str)
            self.assertEqual(result, expected)
    
    def test_remove_accents_lowercase(self):
        """Test that result is lowercase"""
        result = lib.remove_accents('CAFÉ')
        self.assertEqual(result, result.lower())
    
    def test_remove_accents_no_accents(self):
        """Test with string without accents"""
        result = lib.remove_accents('hello')
        self.assertEqual(result, 'hello')
    
    def test_remove_accents_special_chars(self):
        """Test with special characters"""
        result = lib.remove_accents('café@123')
        self.assertNotIn('é', result)


class TestUuidDigits(unittest.TestCase):
    """Test cases for uuid_digits function"""
    
    def test_uuid_digits_default(self):
        """Test uuid_digits with default number of digits"""
        result = lib.uuid_digits()
        self.assertEqual(len(result), 5)
    
    def test_uuid_digits_custom(self):
        """Test uuid_digits with custom number of digits"""
        for ndigits in [3, 8, 16, 32]:
            result = lib.uuid_digits(ndigits)
            self.assertEqual(len(result), ndigits)
    
    def test_uuid_digits_is_hex(self):
        """Test that result contains only hex characters"""
        result = lib.uuid_digits(20)
        # All characters should be valid hex
        try:
            int(result, 16)
            is_valid_hex = True
        except ValueError:
            is_valid_hex = False
        self.assertTrue(is_valid_hex)
    
    def test_uuid_digits_is_unique(self):
        """Test that generated UUIDs are unique"""
        uuid1 = lib.uuid_digits(10)
        uuid2 = lib.uuid_digits(10)
        # Very unlikely to be the same
        self.assertNotEqual(uuid1, uuid2)


class TestLoadLocalFile(unittest.TestCase):
    """Test cases for load_local_file function"""
    
    def setUp(self):
        """Create test files"""
        self.test_dir = os.path.dirname(__file__)
        self.test_file = os.path.join(self.test_dir, 'test_temp_file.txt')
        self.test_content = 'Test content\nLine 2\nLine 3'
        
        with open(self.test_file, 'w', encoding='utf-8') as f:
            f.write(self.test_content)
    
    def tearDown(self):
        """Clean up test files"""
        if os.path.exists(self.test_file):
            os.remove(self.test_file)
    
    def test_load_local_file_basic(self):
        """Test loading a file"""
        result = lib.load_local_file(self.test_file)
        self.assertEqual(result, self.test_content)
    
    def test_load_local_file_with_none(self):
        """Test with None input"""
        result = lib.load_local_file(None)
        self.assertIsNone(result)
    
    def test_load_local_file_preserves_content(self):
        """Test that file content is preserved"""
        result = lib.load_local_file(self.test_file)
        self.assertIn('Line 2', result)
        self.assertIn('Line 3', result)
    
    def test_load_local_file_utf8_encoding(self):
        """Test that UTF-8 encoding is used"""
        utf8_content = 'Café, naïve, 日本語'
        utf8_file = os.path.join(self.test_dir, 'test_utf8.txt')
        
        with open(utf8_file, 'w', encoding='utf-8') as f:
            f.write(utf8_content)
        
        result = lib.load_local_file(utf8_file)
        self.assertEqual(result, utf8_content)
        
        os.remove(utf8_file)


if __name__ == '__main__':
    unittest.main()
