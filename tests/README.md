# PyOS Test Suite

Comprehensive unit tests for the PyOS project.

## Overview

This test suite provides extensive coverage of the PyOS project modules and controllers using Python's `unittest` framework.

## Test Files

### Core Module Tests

- **test_namedlib.py** - Tests for name normalization functions
  - `normalize_label()` - Kubernetes label normalization
  - `normalize_name()` - DNS name normalization
  - `normalize_name_dnsname()` - DNS name with length limits
  - `normalize_name_volunename()` - Volume name normalization
  - `normalize_containername()` - Container name extraction

- **test_pyutils.py** - Tests for utility classes and functions
  - `Event` class - Event handling and callbacks
  - `Lazy` class - Lazy initialization pattern
  - `get_class()` - Dynamic class import
  - `import_classes()` - Module class discovery

- **test_lib.py** - Tests for common library functions
  - `randomStringwithDigitsAndSymbols()` - Random string generation
  - `remove_accents()` - Accent removal from strings
  - `uuid_digits()` - UUID digit generation
  - `load_local_file()` - File loading utility

### Authentication Tests

- **test_authservice_basic.py** - Basic authentication service tests
  - `AuthRoles` class structure
  - Authentication constants validation
  - Error handling classes

- **test_cherrypy_utils.py** - CherryPy utility function tests
  - `getclientipaddr()` - Client IP address extraction
  - `getclientreal_ip()` - Real client IP resolution
  - `getclientxforwardedfor_listip()` - X-Forwarded-For parsing
  - `getclienthttp_headers()` - HTTP header extraction
  - `Results` class for API responses

### Controller Tests

- **test_core_controller.py** - CoreController tests
  - Method existence validation
  - Message handler functionality
  - Configuration key retrieval

- **test_controllers_structure.py** - All 8 controllers structure tests
  - AuthController
  - ComposerController
  - CoreController
  - KeyController
  - ManagerController
  - StoreController
  - UserController
  - AccountingController

### Configuration Tests

- **test_api_configuration.py** - API and configuration tests
  - Settings module structure
  - Services module structure
  - OD module components
  - BaseController inheritance

- **test_models.py** - Data model and schema tests
  - OD data models
  - Network modules
  - Datastore module
  - Logging and i18n modules

## Running Tests

### Run All Tests

```bash
cd /home/alex/src/pyos.dev
python tests/run_tests.py
```

### Run Tests with Different Verbosity Levels

```bash
# Quiet mode (only summary)
python tests/run_tests.py -v 0

# Normal mode
python tests/run_tests.py -v 1

# Verbose mode (default)
python tests/run_tests.py -v 2
```

### Run Specific Test File

```bash
python -m unittest tests.test_namedlib -v
python -m unittest tests.test_pyutils -v
python -m unittest tests.test_lib -v
```

### Run Specific Test Class

```bash
python -m unittest tests.test_namedlib.TestNormalizeLabel -v
python -m unittest tests.test_pyutils.TestEvent -v
```

### Run Specific Test Method

```bash
python -m unittest tests.test_namedlib.TestNormalizeLabel.test_normalize_label_basic_alphanumeric -v
```

### Stop on First Failure

```bash
python tests/run_tests.py --failfast
```

### Custom Test Pattern

```bash
python tests/run_tests.py -p 'test_*.py'
```

## Test Structure

Each test file follows this structure:

```python
import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class TestSomething(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures"""
        pass
    
    def tearDown(self):
        """Clean up after tests"""
        pass
    
    def test_something(self):
        """Test description"""
        self.assertEqual(expected, actual)

if __name__ == '__main__':
    unittest.main()
```

## Test Coverage Areas

### 1. Utility Functions (test_lib.py, test_pyutils.py)
- String manipulation and normalization
- Random data generation
- Lazy initialization patterns
- Event handling mechanisms

### 2. Authentication (test_authservice_basic.py)
- Authentication roles and constants
- Error handling and exceptions
- Authorization header parsing

### 3. Controllers (test_core_controller.py, test_controllers_structure.py)
- Controller instantiation
- Method availability
- Exposed endpoints
- Message handling

### 4. Configuration and Services (test_api_configuration.py)
- Settings module structure
- Services initialization
- Base controller inheritance

### 5. Data Models (test_models.py)
- Model imports and structure
- Network and datastore modules
- Logging infrastructure

## Mocking and Fixtures

The `conftest.py` file provides:

```python
class TestBase(unittest.TestCase):
    """Base test class with common setup and teardown"""
    
    def setUp(self):
        """Common setup for all tests"""
        self.mock_cherrypy_request = MagicMock()
        self.mock_cherrypy_response = MagicMock()
```

Use `unittest.mock.Mock()` and `unittest.mock.patch()` for external dependencies.

## Adding New Tests

1. Create a new file in `tests/` directory: `tests/test_yourmodule.py`
2. Import required modules and the module to test
3. Create test classes inheriting from `unittest.TestCase`
4. Write test methods starting with `test_`
5. Run tests with `python -m unittest tests.test_yourmodule -v`

Example:

```python
import unittest
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import your.module

class TestYourModule(unittest.TestCase):
    def test_something(self):
        result = your.module.function()
        self.assertEqual(expected, result)

if __name__ == '__main__':
    unittest.main()
```

## CI/CD Integration

To integrate with CI/CD pipelines:

```bash
# In GitHub Actions or similar:
python tests/run_tests.py --failfast -v 1

# Check exit code
if [ $? -ne 0 ]; then
    echo "Tests failed"
    exit 1
fi
```

## Troubleshooting

### ImportError: No module named 'oc'
Make sure you're running tests from the project root or adjust `sys.path` in test files.

### CherryPy context not available
Some tests are skipped if CherryPy context isn't properly initialized. This is normal.

### Test discovery issues
Use explicit test paths:
```bash
python -m unittest discover -s tests -p 'test_*.py' -v
```

## Test Statistics

- **Total Test Files**: 9
- **Test Classes**: 40+
- **Test Methods**: 100+
- **Coverage Areas**: 
  - Core utilities
  - Authentication
  - All 8 controllers
  - Configuration
  - Data models

## Best Practices

1. **Isolation**: Each test should be independent
2. **Setup/Teardown**: Use setUp() and tearDown() for test fixtures
3. **Mocking**: Mock external dependencies (CherryPy, databases, etc.)
4. **Assertions**: Use specific assertions (assertEqual, assertIn, etc.)
5. **Naming**: Use descriptive test names starting with `test_`
6. **Documentation**: Include docstrings in test methods
7. **Skipping**: Use `@unittest.skip()` for temporarily disabled tests

## Related Files

- [PROJECT_SPECIFICATION.md](../PROJECT_SPECIFICATION.md) - Architecture documentation
- [OPERATIONS_RUNBOOK.md](../OPERATIONS_RUNBOOK.md) - Operations guide
- [openapi.yaml](../openapi.yaml) - API specification
- [openapi.json](../openapi.json) - API specification (JSON format)

## License

SPDX-License-Identifier: GPL-2.0-only
