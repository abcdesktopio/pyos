#!/usr/bin/env python3
"""
Test runner for pyos.dev project

This script runs all unit tests in the tests directory
"""
import sys
import os
import unittest

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


def run_tests(verbosity=2, pattern='test_*.py', failfast=False):
    """
    Run all tests in the tests directory
    
    Args:
        verbosity (int): Test verbosity level (0=quiet, 1=normal, 2=verbose)
        pattern (str): File pattern for test discovery
        failfast (bool): Stop on first failure
    
    Returns:
        int: Number of failures (0 if all passed)
    """
    # Discover and run tests
    loader = unittest.TestLoader()
    test_dir = os.path.dirname(__file__)
    
    # Discover tests
    suite = loader.discover(test_dir, pattern=pattern)
    
    # Run tests
    runner = unittest.TextTestRunner(
        verbosity=verbosity,
        failfast=failfast
    )
    
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    print("="*70)
    
    # Return exit code
    return len(result.failures) + len(result.errors)


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Run PyOS test suite')
    parser.add_argument('-v', '--verbosity', type=int, default=2, 
                       help='Test verbosity (0=quiet, 1=normal, 2=verbose)')
    parser.add_argument('-f', '--failfast', action='store_true',
                       help='Stop on first failure')
    parser.add_argument('-p', '--pattern', default='test_*.py',
                       help='Test file pattern')
    
    args = parser.parse_args()
    
    exit_code = run_tests(
        verbosity=args.verbosity,
        pattern=args.pattern,
        failfast=args.failfast
    )
    
    sys.exit(exit_code)
