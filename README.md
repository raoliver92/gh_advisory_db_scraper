# GitHub Advisory Database Scraper

A Python application that scrapes GitHub security advisories and organizes them by severity level into CSV and ZIP files.

## Getting Started

### Prerequisites

- Python 3.7 or higher
- GitHub Personal Access Token

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd gh_advisory_db_scraper
```

2. Install required dependencies:
```bash
pip install requests
```

### Setting Up GitHub API Token

1. **Create a Personal Access Token:**
   - Go to GitHub Settings → Developer settings → Personal access tokens → Tokens (classic)
   - Generate a new token with the following scopes:
     - `public_repo` (to read public repository data)
     - `read:security_events` (to read security advisories)
   - Copy the generated token

2. **Set Environment Variable:**
   ```bash
   export GITHUB_TOKEN="your_token_here"
   ```
   
   Or on Windows:
   ```cmd
   set GITHUB_TOKEN=your_token_here
   ```

## Running the App

### Basic Usage

Run the main script to fetch all advisories and organize them by severity:

```bash
python main.py
```

This will:
- Fetch all GitHub security advisories for the pip ecosystem
- Organize them by severity (low, moderate, high, critical)
- Create CSV files for each severity level
- Create ZIP archives for each CSV file
- Store all files in the `advisories/` directory

### Output Structure

After running, you'll find:
```
advisories/
├── low_advisories.csv
├── low_advisories.zip
├── moderate_advisories.csv
├── moderate_advisories.zip
├── high_advisories.csv
├── high_advisories.zip
├── critical_advisories.csv
└── critical_advisories.zip
```

### Customizing the Scraper

You can modify the scraper behavior in `main.py`:

```python
# Change ecosystem (default: "pip")
scraper = AdvisoryScraper()
advisories = scraper.fetch_all_advisories(delay=0.1, ecosystem="npm")

# Add delay between requests to respect rate limits
advisories = scraper.fetch_all_advisories(delay=1.0)

# Limit number of pages fetched
advisories = scraper.fetch_all_advisories(max_pages=5)
```

## Troubleshooting

### Common Issues

#### 1. Authentication Errors
**Error:** `403 Forbidden` or `401 Unauthorized`

**Solution:**
- Verify your `GITHUB_TOKEN` is set correctly
- Check that the token has the required scopes
- Ensure the token hasn't expired

```bash
echo $GITHUB_TOKEN  # Check if token is set
```

#### 2. Rate Limiting
**Error:** `403 Rate limit exceeded`

**Solutions:**
- Increase the delay between requests:
  ```python
  advisories = scraper.fetch_all_advisories(delay=2.0)
  ```
- Use a token with higher rate limits (GitHub Pro/Enterprise)
- Wait for the rate limit to reset (usually 1 hour)

#### 3. Network/Connection Issues
**Error:** `ConnectionError` or `TimeoutError`

**Solutions:**
- Check your internet connection
- Try increasing the delay between requests
- Use a VPN if GitHub is blocked in your region

#### 4. Missing Dependencies
**Error:** `ModuleNotFoundError: No module named 'requests'`

**Solution:**
```bash
pip install requests
```

#### 5. Permission Errors
**Error:** `Permission denied` when creating files

**Solutions:**
- Ensure you have write permissions in the current directory
- Run with appropriate permissions:
  ```bash
  chmod +x main.py
  python main.py
  ```

### Logging and Debugging

The application uses comprehensive logging. Check the `app.log` file for detailed information:

```bash
tail -f app.log  # Monitor logs in real-time
```

Log levels available:
- `DEBUG`: Detailed information for debugging
- `INFO`: General information about program execution
- `WARNING`: Warning messages for potential issues
- `ERROR`: Error messages for failed operations

### Performance Optimization

For large datasets:
- Increase delay between requests to avoid rate limiting
- Use `max_pages` parameter to limit data fetched during testing
- Monitor memory usage for very large advisory sets

## Testing

The project includes comprehensive tests for all components.

### Running Tests

#### Quick Test Run
```bash
python run_tests.py
```

#### Manual Test Execution
```bash
# Install test dependencies
pip install -r requirements-test.txt

# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=. --cov-report=html

# Run specific test categories
pytest tests/ -m unit          # Unit tests only
pytest tests/ -m integration   # Integration tests only
pytest tests/ -m "not slow"    # Skip slow tests
```

#### Test Categories

- **Unit Tests**: Test individual functions and classes in isolation
- **Integration Tests**: Test the complete workflow from API calls to file generation
- **Helper Tests**: Test utility functions for CSV creation, ZIP files, and directory management
- **Scraper Tests**: Test GitHub and CISA API interactions with mocked responses

### Test Coverage

The test suite provides comprehensive coverage including:

- ✅ **AdvisoryScraper**: API interactions, error handling, pagination (89% coverage)
- ✅ **CISAAdvisoryScraper**: CISA API integration, KEV checking (100% coverage)
- ✅ **Helper Functions**: CSV creation, ZIP files, directory management (95% coverage)
- ✅ **Main Workflow**: Complete end-to-end functionality (98% coverage)
- ✅ **Error Handling**: Network errors, API failures, file permission issues
- ✅ **Edge Cases**: Empty responses, missing fields, large datasets
- ✅ **Integration Tests**: Simplified integration tests for workflow components

**Overall Test Coverage: 77%** (55 tests passing)

### Test Files Structure

```
tests/
├── __init__.py
├── conftest.py              # Pytest fixtures and configuration
├── test_helpers.py          # Tests for helpers.py functions
├── test_scraper.py          # Tests for scraper classes
├── test_main.py            # Tests for main.py functionality
├── test_integration.py     # Integration tests (currently disabled)
└── test_integration_simple.py  # Simplified integration tests
```

### Continuous Integration

The test suite is designed to run in CI/CD environments:

```bash
# Run tests in parallel (faster)
pytest tests/ -n auto

# Run with specific Python version
python -m pytest tests/ -v

# Generate JUnit XML for CI systems
pytest tests/ --junitxml=test-results.xml
```

### Getting Help

If you encounter issues not covered here:
1. Check the `app.log` file for detailed error messages
2. Verify your GitHub token permissions
3. Test with a smaller dataset using `max_pages=1`
4. Check GitHub's API status page for service issues
5. Run the test suite to verify your environment: `python run_tests.py`
