#!/bin/bash

# Test script for the screenshot API endpoint

echo "Testing Blink Screenshot API"
echo "============================"

# Base URL for the API
BASE_URL="${BASE_URL:-http://localhost:8080}"

# Test 1: Basic screenshot
echo -e "\n1. Basic screenshot test:"
curl -X POST "$BASE_URL/screenshot" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "format": "jpeg",
    "quality": 75,
    "width": 1280,
    "height": 720,
    "timeout_ms": 3000
  }' | jq .

# Test 2: Base64 response test
echo -e "\n2. Base64 response test:"
curl -X POST "$BASE_URL/screenshot" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "response_type": "base64",
    "width": 640,
    "height": 360,
    "quality": 70
  }' | jq '.base64_data = (.base64_data | if . then "data:image/jpeg;base64,[truncated]" else null end)'

# Test 3: File path response (default)
echo -e "\n3. File path response test:"
curl -X POST "$BASE_URL/screenshot" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://google.com"}' | jq .

# Test 4: Invalid URL test
echo -e "\n4. Invalid URL test (should fail):"
curl -X POST "$BASE_URL/screenshot" \
  -H "Content-Type: application/json" \
  -d '{"url": ""}' | jq .

# Test 5: Performance test - multiple requests
echo -e "\n5. Performance test - 10 sequential requests:"
START_TIME=$(date +%s%N)

for i in {1..10}; do
  curl -s -X POST "$BASE_URL/screenshot" \
    -H "Content-Type: application/json" \
    -d '{"url": "https://example.com"}' > /dev/null
  echo -n "."
done

END_TIME=$(date +%s%N)
ELAPSED=$((($END_TIME - $START_TIME) / 1000000))
echo -e "\nCompleted 10 requests in ${ELAPSED}ms"
echo "Average: $((ELAPSED / 10))ms per request"

echo -e "\nTests completed!"