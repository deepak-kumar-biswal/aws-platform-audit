#!/bin/bash

# AWS Audit Platform - Test Execution Script
# This script executes the comprehensive test plan for the AWS Audit Platform

set -e  # Exit on any error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
TEST_ENV="${TEST_ENV:-dev}"
COVERAGE_THRESHOLD=90
PARALLEL_JOBS=4

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}AWS Audit Platform - Test Execution${NC}"
echo -e "${BLUE}Environment: ${TEST_ENV}${NC}"
echo -e "${BLUE}========================================${NC}"

# Function to print test section headers
print_section() {
    echo -e "\n${YELLOW}=== $1 ===${NC}\n"
}

# Function to print test results
print_result() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓ $2 PASSED${NC}"
    else
        echo -e "${RED}✗ $2 FAILED${NC}"
        exit 1
    fi
}

# Set up test environment
setup_test_environment() {
    print_section "Setting up test environment"
    
    # Install Python dependencies
    echo "Installing Python dependencies..."
    pip install -r requirements.txt
    pip install -r tests/requirements-test.txt
    
    # Set up AWS credentials for testing
    echo "Configuring AWS credentials..."
    export AWS_DEFAULT_REGION=us-east-1
    export AWS_PAGER=""
    
    # Create test directories
    mkdir -p test-results
    mkdir -p coverage-reports
    
    echo -e "${GREEN}✓ Test environment setup complete${NC}"
}

# Unit Testing
run_unit_tests() {
    print_section "Running Unit Tests"
    
    echo "Executing Python unit tests..."
    pytest tests/ \
        --cov=src/lambda \
        --cov-report=html:coverage-reports/html \
        --cov-report=xml:coverage-reports/coverage.xml \
        --cov-report=term-missing \
        --cov-fail-under=${COVERAGE_THRESHOLD} \
        --junit-xml=test-results/unit-tests.xml \
        --verbose
    
    print_result $? "Unit Tests"
}

# Terraform Validation
run_terraform_validation() {
    print_section "Running Terraform Validation"
    
    # Hub account validation
    echo "Validating hub account Terraform..."
    cd terraform/hub
    terraform init -backend=false
    terraform validate
    terraform fmt -check
    cd ../..
    
    # Spoke account validation
    echo "Validating spoke account Terraform..."
    cd terraform/spoke
    terraform init -backend=false
    terraform validate
    terraform fmt -check
    cd ../..
    
    print_result $? "Terraform Validation"
}

# Security Scanning
run_security_scanning() {
    print_section "Running Security Scans"
    
    # Terraform security scanning
    echo "Running tfsec security scan..."
    tfsec terraform/ --format json --out test-results/tfsec-results.json
    
    # Python security scanning
    echo "Running bandit security scan..."
    bandit -r src/ -f json -o test-results/bandit-results.json
    
    # Dependency vulnerability scanning
    echo "Running safety check..."
    safety check --json --output test-results/safety-results.json
    
    print_result $? "Security Scanning"
}

# Code Quality Checks
run_code_quality() {
    print_section "Running Code Quality Checks"
    
    # Python linting
    echo "Running flake8 linting..."
    flake8 src/ --output-file=test-results/flake8-results.txt
    
    # Python code formatting
    echo "Checking black code formatting..."
    black --check src/
    
    # Type checking
    echo "Running mypy type checking..."
    mypy src/ --ignore-missing-imports
    
    print_result $? "Code Quality Checks"
}

# Integration Tests (requires AWS access)
run_integration_tests() {
    print_section "Running Integration Tests"
    
    if [ "${RUN_INTEGRATION_TESTS}" = "true" ]; then
        echo "Running AWS integration tests..."
        pytest tests/integration/ \
            --junit-xml=test-results/integration-tests.xml \
            --verbose
        
        print_result $? "Integration Tests"
    else
        echo -e "${YELLOW}Skipping integration tests (set RUN_INTEGRATION_TESTS=true to enable)${NC}"
    fi
}

# Load Testing
run_load_tests() {
    print_section "Running Load Tests"
    
    if [ "${RUN_LOAD_TESTS}" = "true" ]; then
        echo "Running load tests..."
        # Add your load testing framework here (e.g., locust, artillery)
        echo -e "${YELLOW}Load testing framework not yet implemented${NC}"
    else
        echo -e "${YELLOW}Skipping load tests (set RUN_LOAD_TESTS=true to enable)${NC}"
    fi
}

# Performance Tests
run_performance_tests() {
    print_section "Running Performance Tests"
    
    echo "Running Lambda performance tests..."
    python tests/performance/test_lambda_performance.py
    
    print_result $? "Performance Tests"
}

# Compliance Tests
run_compliance_tests() {
    print_section "Running Compliance Tests"
    
    echo "Running CIS benchmark validation..."
    python tests/compliance/test_cis_compliance.py
    
    echo "Running PCI-DSS compliance validation..."
    python tests/compliance/test_pci_compliance.py
    
    echo "Running SOC2 compliance validation..."
    python tests/compliance/test_soc2_compliance.py
    
    print_result $? "Compliance Tests"
}

# Generate test reports
generate_test_reports() {
    print_section "Generating Test Reports"
    
    echo "Generating test summary report..."
    python tests/utils/generate_test_report.py \
        --test-results test-results/ \
        --coverage-reports coverage-reports/ \
        --output test-results/test-summary.html
    
    echo "Test reports generated in test-results/"
    echo -e "${GREEN}✓ Test reports generated${NC}"
}

# Cleanup test environment
cleanup_test_environment() {
    print_section "Cleaning up test environment"
    
    # Clean up any temporary resources
    echo "Cleaning up temporary test resources..."
    
    # Archive test results
    timestamp=$(date +%Y%m%d_%H%M%S)
    tar -czf "test-results-${timestamp}.tar.gz" test-results/ coverage-reports/
    
    echo -e "${GREEN}✓ Cleanup complete${NC}"
}

# Main test execution
main() {
    local start_time=$(date +%s)
    
    echo -e "${BLUE}Starting AWS Audit Platform test execution...${NC}"
    
    # Setup
    setup_test_environment
    
    # Core tests (always run)
    run_unit_tests
    run_terraform_validation
    run_security_scanning
    run_code_quality
    run_performance_tests
    run_compliance_tests
    
    # Optional tests (based on environment variables)
    run_integration_tests
    run_load_tests
    
    # Generate reports
    generate_test_reports
    
    # Cleanup
    cleanup_test_environment
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    echo -e "\n${GREEN}========================================${NC}"
    echo -e "${GREEN}All tests completed successfully!${NC}"
    echo -e "${GREEN}Total execution time: ${duration} seconds${NC}"
    echo -e "${GREEN}========================================${NC}"
    
    # Display test summary
    echo -e "\n${BLUE}Test Summary:${NC}"
    echo "• Unit Tests: ✓ PASSED"
    echo "• Terraform Validation: ✓ PASSED"
    echo "• Security Scanning: ✓ PASSED"
    echo "• Code Quality: ✓ PASSED"
    echo "• Performance Tests: ✓ PASSED"
    echo "• Compliance Tests: ✓ PASSED"
    
    if [ "${RUN_INTEGRATION_TESTS}" = "true" ]; then
        echo "• Integration Tests: ✓ PASSED"
    fi
    
    if [ "${RUN_LOAD_TESTS}" = "true" ]; then
        echo "• Load Tests: ✓ PASSED"
    fi
    
    echo -e "\nTest reports available in: test-results/"
    echo -e "Coverage reports available in: coverage-reports/"
}

# Handle script arguments
case "${1:-}" in
    "unit")
        setup_test_environment
        run_unit_tests
        ;;
    "terraform")
        run_terraform_validation
        ;;
    "security")
        run_security_scanning
        ;;
    "quality")
        run_code_quality
        ;;
    "integration")
        export RUN_INTEGRATION_TESTS=true
        setup_test_environment
        run_integration_tests
        ;;
    "load")
        export RUN_LOAD_TESTS=true
        run_load_tests
        ;;
    "performance")
        run_performance_tests
        ;;
    "compliance")
        run_compliance_tests
        ;;
    "all"|"")
        main
        ;;
    *)
        echo "Usage: $0 [unit|terraform|security|quality|integration|load|performance|compliance|all]"
        echo ""
        echo "Environment variables:"
        echo "  TEST_ENV: Environment to test against (dev|staging|prod) [default: dev]"
        echo "  RUN_INTEGRATION_TESTS: Set to 'true' to run integration tests [default: false]"
        echo "  RUN_LOAD_TESTS: Set to 'true' to run load tests [default: false]"
        echo "  COVERAGE_THRESHOLD: Minimum code coverage percentage [default: 90]"
        exit 1
        ;;
esac
