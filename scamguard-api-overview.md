Overview

ScamGuard V1 API is a comprehensive threat detection service that uses AI-powered analysis to identify and prevent scam attempts through multiple channels including chat messages, URLs, emails, and phone numbers. The API supports an agentic workflow where AI agents can autonomously check references and request user confirmation for reporting suspicious content. The API is stateless - clients are responsible for managing conversation history and context.

Key Features

AI-Powered Scam Detection: Advanced analysis of text and image content

Multi-Modal Support: Text and image content analysis (OCR and QR code detection handled by client)

Reference Validation: URL, email, and phone number threat intelligence

Tool Integration: Autonomous reference checking and user-confirmed reporting

Conversation Management: Client-managed chat history and title generation

Configuration Constants

Base URLs

Production: <https://scamguard.malwarebytes.com>
Staging: <https://scamguard.mwbsys-stage.com>
Development: <http://10.164.46.88:8000> (behind Tailscale VPN)

Product Codes

mbios-c - iOS applications

MBMA-C - Android applications

ScamGuard-Playground - Development and testing

Reference Types

url - Web URLs and links

email - Email addresses

phone_number - Phone numbers

Status Values

safe - Verified as legitimate

unknown - No threat intelligence available

suspicious - Potentially harmful, requires caution

malicious - Confirmed threat, should be blocked

Image Formats

Supported: JPG, PNG, WebP

Recommended: WebP (better compression)

Additional Resources

API Documentation: http://10.164.46.88:8000/docs (interactive Swagger/OpenAPI docs)

Playground: http://10.164.46.88:8501/ (testing interface behind Tailscale VPN)

Getting Started

Prerequisites

Valid product code (see Authentication)

Installation token

HTTP client with JSON support

For Development: Access to Tailscale VPN for development environment and playground

Development Environment

The development environment provides additional tools for testing and integration:

Interactive API Documentation

Visit http://10.164.46.88:8000/docs for complete Swagger/OpenAPI documentation where you can:

Explore all available endpoints

Test API calls directly in the browser

View detailed request/response schemas

Try different authentication scenarios

Playground Interface

The playground at http://10.164.46.88:8501/ offers a user-friendly interface to:

Test conversation flows with the AI agent

Experiment with tool calling (reference checking and reporting)

Upload and analyze images

Monitor HTTP request/response traces

Configure different client settings and overrides

Note: Both development resources require Tailscale VPN access.

Quick Start - AI Agent Workflow

Here's a complete example showing how the AI agent analyzes a suspicious message and automatically checks references:

1. Send Message for Analysis

curl -X POST "<https://scamguard.malwarebytes.com/v1/chat/completion>" \
 -H "Content-Type: application/json" \
 -d '{
"usecase": "chat",
"messages": [
{
"role": "user",
"content": [
{
"type": "text",
"text": "I received this text: URGENT! You have won $50,000! Claim now at <https://fake-lottery.com/claim?id=12345> or call 1-800-555-SCAM"
}
]
}
],
"client": {
"version": "1.0",
"productCode": "mbios-c",
"region_code": "US"
},
"installation": {
"installationToken": "your-installation-token"
}
}'

2. AI Response with Tool Calls

The AI automatically detects suspicious elements and calls tools:

{
"message": {
"role": "assistant",
"content": "I'll analyze this message for scam indicators. Let me check the URL and phone number.",
"tool_calls": [
{
"id": "call_url_check",
"type": "function",
"function": {
"name": "reference_check",
"arguments": {
"value": "<https://fake-lottery.com/claim?id=12345>",
"type": "url"
}
}
},
{
"id": "call_phone_check",
"type": "function",
"function": {
"name": "reference_check",
"arguments": {
"value": "1-800-555-SCAM",
"type": "phone_number"
}
}
}
]
},
"thread_id": "550e8400-e29b-41d4-a716-446655440000"
}

3. Process Tool Calls with Reference Check API

The client processes each tool call by calling the reference check API directly (see Reference Check endpoint for complete details):

# Example: Check the URL

curl -X POST "<https://scamguard.malwarebytes.com/v1/reference/check>" \
 -H "Content-Type: application/json" \
 -d '{
"reference": {"type": "url", "value": "<https://fake-lottery.com/claim?id=12345>"},
// ... standard request fields (see Common Request Structure)
}'

# Response: {"status": "malicious"}

# Example: Check the phone number

curl -X POST "<https://scamguard.malwarebytes.com/v1/reference/check>" \
 -H "Content-Type: application/json" \
 -d '{
"reference": {"type": "phone_number", "value": "1-800-555-SCAM"},
// ... standard request fields (see Common Request Structure)
}'

# Response: {"status": "suspicious"}

4. Continue Conversation with Tool Results

Add tool messages and get final analysis:

curl -X POST "<https://scamguard.malwarebytes.com/v1/chat/completion>" \
 -H "Content-Type: application/json" \
 -d '{
"usecase": "chat",
"messages": [
{
"role": "user",
"content": [{"type": "text", "text": "I received this text: URGENT! You have won $50,000!..."}]
},
{
"role": "assistant",
"content": "I'\''ll analyze this message for scam indicators...",
"tool_calls": [...]
},
{
"role": "tool",
"content": "Reference check result for <https://fake-lottery.com/claim?id=12345:> malicious",
"tool_call_id": "call_url_check"
},
{
"role": "tool",
"content": "Reference check result for 1-800-555-SCAM: suspicious",
"tool_call_id": "call_phone_check"
}
],
"client": {...},
"installation": {...},
"thread_id": "550e8400-e29b-41d4-a716-446655440000"
}'

5. Final AI Analysis

{
"message": {
"role": "assistant",
"content": "⚠️ **SCAM ALERT** ⚠️\n\nThis is definitely a scam message. Here's why:\n• Urgent language and fake prize claims are classic scam tactics\n• The URL <https://fake-lottery.com/claim?id=12345> is flagged as MALICIOUS\n• The phone number 1-800-555-SCAM appears SUSPICIOUS\n\n**Do not click the link or call the number.** Delete this message immediately."
}
}

This demonstrates the complete AI agentic workflow: analysis → tool calling → final response.

Authentication

Product Code Validation

All API requests require a valid product code in the client.productCode field (see Configuration Constants for supported codes).

Common Request Structure

All API requests must include the following standard fields:

{
"client": {
"version": "5.16.0", // Client application version
"productCode": "mbios-c", // Product identifier (see supported codes below)
"region_code": "US" // ISO country code
},
"installation": {
"installationToken": "unique-installation-id" // Unique per installation
},
"thread_id": "optional-uuid-v4" // Optional conversation identifier
}

Field Descriptions:

client.version: Client application version (e.g., "5.16.0", "2.1.3")

client.productCode: Product identifier (see supported codes below)

client.region_code: ISO 3166-1 alpha-2 country code

installation.installationToken: Unique identifier for this installation

thread_id: Optional UUID for conversation grouping (see API Architecture for details)

Request Headers

Content-Type: application/json (required)

x-correlation-id: string (optional, auto-generated if not provided, used for tracing and logging)

AI Agentic Lifecycle

The ScamGuard API implements a sophisticated AI agent lifecycle that enables autonomous scam detection and response:

1. Chat Completion Flow

User Input → AI Analysis → Tool Calls → Response Generation → Title Generation

Phase 1: User Input Processing (Client-Side)

Input Validation: Validate and format user text input

Image Preparation: Format conversion, downscaling, and base64 encoding (see Image Processing Guide)

OCR and QR Code Detection: Optional extraction of text and QR codes from images before sending

Message Structure: Prepare ContentTextPart and ContentImagePart objects for API submission

Context Preservation: Client maintains conversation history for multi-turn interactions

Phase 2: AI Analysis & Tool Invocation

The AI agent autonomously decides when to invoke tools based on content analysis:

{
"tool_calls": [
{
"id": "call_123",
"type": "function",
"function": {
"name": "reference_check",
"arguments": {
"value": "<https://suspicious-link.com>",
"type": "url"
}
}
}
]
}

Phase 3: Tool Execution & Response

Tools execute and return results that feed back into the conversation:

{
"role": "tool",
"content": "Reference check result for <https://suspicious-link.com:> malicious",
"tool_call_id": "call_123"
}

Phase 4: Title Generation

After conversation completion, the API can generate contextual titles:

{
"usecase": "title",
"messages": [...conversation_history...]
}

2. Tool Handling Lifecycle

⚠️ CRITICAL: Client has full responsibility for tool handling and persisting internal tool status. If an assistant message contains tool calls, the client MUST always include ALL tool results in the next request, otherwise chat completion will fail.

Available Tools:

reference_check: Validates URLs, emails, phone numbers

reference_report: Requests user confirmation to report suspicious references

Client Tool State Management:

The client must maintain tool call status and results:

// Client-side tool status tracking (required)
{
"tool_call_id": {
"status": "malicious",
"reported": false,
"reference_value": "<https://suspicious-link.com>",
"reference_type": "url"
}
}

Tool Processing Requirements:

Detect Tool Calls: Check if assistant_message.tool_calls exists

Process Each Tool:

reference_check: Execute API call immediately to get status

reference_report: Show confirmation dialog, DO NOT execute API call until user confirms

Create Tool Messages: Generate ChatCompletionToolMessage for each tool call result

Include ALL Results: Add all tool messages to conversation before next chat completion

Maintain State: Track tool status for UI and workflow management

3. Reporting Workflow

The reporting process requires user confirmation and involves client-side UI handling:

Step 1: AI Requests Reporting

When the AI wants to report a reference, it calls the reference_report tool:

{
"tool_calls": [
{
"id": "call_report_123",
"type": "function",
"function": {
"name": "reference_report",
"arguments": {
"value": "<https://malicious-site.com>",
"type": "url"
}
}
}
]
}

Step 2: Client Shows Confirmation Dialog

The client must return a tool message requesting user confirmation:

{
"role": "tool",
"content": "Confirm reporting suspicious reference: <https://malicious-site.com.> Tap 'Submit' to confirm.",
"tool_call_id": "call_report_123"
}

Key Points:

The message text is client-specific and should match the client's UI

The reporting process is asynchronous

The tool response unblocks the AI workflow while the user decides

The actual reporting to threat intelligence happens separately when the user confirms

Step 3: User Confirmation (Client-Side)

Client displays confirmation dialog/button

If user confirms, client calls /v1/reference/report API directly

If user cancels, no further action needed

4. Complete Conversation Flow Example

1. User: "Check this link: <https://malicious-site.com>"
1. AI Agent: Analyzes → Calls reference_check tool
1. Tool Response: "Reference check result: malicious"
1. AI Agent: "⚠️ This link is malicious. Do not click it."
1. Title Generation: "Malicious Link Detection and Reporting"
1. User: "Report this"
1. AI Agent: Calls reference_report tool
1. Tool Response: "Confirm reporting suspicious reference: <https://malicious-site.com.> Tap 'Submit' to confirm."
1. AI Agent: "I've prepared a report for this malicious link. Please confirm if you'd like to submit it to our threat intelligence system."
1. [User taps Submit in UI] → Client calls /v1/reference/report

API Endpoints

Chat Completion

POST /v1/chat/completion

Primary endpoint for AI-powered conversation and analysis.

Request Body:

{
"usecase": "chat", // "chat" or "title"
"messages": [
{
"role": "user",
"content": [
{
"type": "text",
"text": "Analyze this message for scams"
},
{
"type": "image_url",
"image_url": "data:image/webp;base64,...",
"ocr_text": "Text found in image (optional)",
"qr_code": "<https://suspicious-link.com> (optional)"
}
]
}
],
// ... standard request fields (see Common Request Structure above)
}

Response:

{
"message": {
"role": "assistant",
"content": "I'll analyze this content for potential scams...",
"tool_calls": [
{
"id": "call_123",
"type": "function",
"function": {
"name": "reference_check",
"arguments": {
"value": "<https://suspicious-link.com>",
"type": "url"
}
}
}
]
},
"thread_id": "550e8400-e29b-41d4-a716-446655440000"
}

Response Fields:

message: The assistant's response message

thread_id: Auto-generated UUID if not provided in request, or the same thread_id if provided

Reference Check

POST /v1/reference/check

Validate individual references against threat intelligence.

Request Body:

{
"reference": {
"type": "url", // "url", "email", "phone_number"
"value": "<https://suspicious-site.com>"
}
// ... standard request fields (see Common Request Structure above)
}

Response:

{
"status": "malicious" // "safe", "unknown", "suspicious", "malicious"
}

Reference Report

POST /v1/reference/report

Report suspicious references to threat intelligence system. This endpoint is typically called by the client after user confirmation, not directly by the AI agent.

Request Body:

{
"reference": {
"type": "url",
"value": "<https://malicious-site.com>"
},
"userFeedback": {
"description": "User reported this as suspicious"
}
// ... standard request fields (see Common Request Structure above)
}

Response:

{
"status": "success" // "success", "error"
}

Image Processing Guide

Overview

While the ScamGuard API handles visual content analysis, clients should perform image processing before submitting requests to optimize quality and meet API requirements.

Required Image Processing

Image Downscaling

Images must be downscaled before sending to the API, with different requirements based on use case:

For Chat Usecase:

Downscale longest side to ≤ 2048 pixels

Downscale shortest side to < 768 pixels

Preserve aspect ratio during scaling

For Title Usecase:

Downscale to exactly 512x512 pixels

Aspect ratio preservation not required

Supported Formats: See Configuration Constants for image format details.

Optional Client-Side Processing

OCR (Optical Character Recognition)

Purpose: Extract text from images for enhanced analysis

Implementation: Client-side using libraries like Tesseract, Google Vision API, or device-native OCR

Advantage: OCR performed on original full-resolution images provides better accuracy than processing downscaled images

Usage: Include extracted text in the ocr_text field of ContentImagePart

QR Code Detection

Purpose: Extract URLs or data from QR codes in images

Implementation: Client-side using libraries like ZXing, qrcode-reader, or device cameras

Backend Limitation: The backend does not have QR code detection capability, making client-side processing essential for QR code analysis

Usage: Include detected URLs/data in the qr_code field of ContentImagePart

Processing Order: Always perform OCR and QR code detection on original full-resolution images before downscaling for optimal accuracy.

Complete Implementation Example

import cv2
import pytesseract
from pyzbar import pyzbar
import base64
from PIL import Image
import io

def process_image_for_api(image_path, usecase="chat"):
"""Complete image processing pipeline for ScamGuard API""" # Load original image
original_image = cv2.imread(image_path)
pil_image = Image.open(image_path)

    # Step 1: Extract information from original full-resolution image
    ocr_text = pytesseract.image_to_string(original_image)
    qr_codes = pyzbar.decode(original_image)
    qr_data = [qr.data.decode('utf-8') for qr in qr_codes]

    # Step 2: Downscale image based on usecase
    if usecase == "chat":
        # Chat usecase: preserve aspect ratio
        width, height = pil_image.size
        longest_side = max(width, height)
        shortest_side = min(width, height)

        # Scale down longest side to ≤ 2048
        if longest_side > 2048:
            scale_factor = 2048 / longest_side
            new_width = int(width * scale_factor)
            new_height = int(height * scale_factor)
            pil_image = pil_image.resize((new_width, new_height), Image.Resampling.LANCZOS)

        # Ensure shortest side < 768
        width, height = pil_image.size
        shortest_side = min(width, height)
        if shortest_side >= 768:
            scale_factor = 767 / shortest_side
            new_width = int(width * scale_factor)
            new_height = int(height * scale_factor)
            pil_image = pil_image.resize((new_width, new_height), Image.Resampling.LANCZOS)

    elif usecase == "title":
        # Title usecase: exact 512x512, no aspect ratio preservation
        pil_image = pil_image.resize((512, 512), Image.Resampling.LANCZOS)

    # Step 3: Convert to WebP format and encode
    buffer = io.BytesIO()
    pil_image.save(buffer, format='WEBP', quality=85, optimize=True)
    image_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')

    # Step 4: Create ContentImagePart structure
    image_content = {
        "type": "image_url",
        "image_url": f"data:image/webp;base64,{image_base64}"
    }

    # Add optional extracted data
    if ocr_text.strip():
        image_content["ocr_text"] = ocr_text.strip()

    if qr_data:
        image_content["qr_code"] = qr_data[0]  # Use first QR code

    return image_content

# Usage example

image_content = process_image_for_api('suspicious_image.jpg', usecase="chat")
content_parts = [
{"type": "text", "text": "Analyze this image for scams"},
image_content
]

Benefits: Client-side processing significantly improves analysis quality by providing additional context that enhances the AI's ability to identify scams. Since the backend lacks QR code detection capability, client-side processing is essential for analyzing QR codes in images.

API Architecture

Stateless Design

The ScamGuard API follows a stateless architecture:

No Server-Side Session Storage: The API does not maintain conversation history or user sessions

Client Responsibility: Clients must manage and maintain conversation context

Request Independence: Each API request is independent and self-contained

Conversation History: Must be included in each request's messages array

Thread ID Management

The thread_id is used to group related conversations and requests:

Optional Field: Can be omitted in the first chat completion request

Auto-Generation: If not provided, the API will generate a new UUID and return it in the response

UUID Format: Recommended format is UUID v4 (e.g., 550e8400-e29b-41d4-a716-446655440000)

Consistency: Use the same thread_id for all requests in a conversation

First Request (without thread_id):

{
"usecase": "chat",
"messages": [...],
"client": {...},
"installation": {...}
// thread_id omitted - will be auto-generated
}

API Response with Generated thread_id:

{
"message": {...},
"thread_id": "550e8400-e29b-41d4-a716-446655440000"
}

Subsequent Requests (with thread_id):

{
"usecase": "chat",
"messages": [...],
"client": {...},
"installation": {...},
"thread_id": "550e8400-e29b-41d4-a716-446655440000"
}

Client Implementation Requirements

import uuid

class ConversationManager:
def **init**(self):
self.messages = [] # Client maintains full conversation history
self.thread_id = None # Will be set from first API response or generated

    def add_user_message(self, content):
        """Add user message to conversation history"""
        self.messages.append({
            "role": "user",
            "content": content
        })

    def add_assistant_message(self, message):
        """Add assistant response to conversation history"""
        self.messages.append(message)

    def get_conversation_context(self):
        """Return full conversation for API request"""
        context = {"messages": self.messages}

        # Include thread_id if we have one, otherwise let API generate one
        if self.thread_id:
            context["thread_id"] = self.thread_id

        return context

    def set_thread_id_from_response(self, response):
        """Set thread_id from API response if not already set"""
        if not self.thread_id and "thread_id" in response:
            self.thread_id = response["thread_id"]

    def generate_thread_id(self):
        """Generate a new UUID for thread_id if needed"""
        if not self.thread_id:
            self.thread_id = str(uuid.uuid4())

Data Models

Note: For the most up-to-date and complete data model definitions, refer to the interactive Swagger/OpenAPI documentation at http://10.164.46.88:8000/docs (requires Tailscale VPN access). The following examples provide common usage patterns.

Message Types

ChatCompletionUserMessage

{
"role": "user",
"content": [
{
"type": "text",
"text": "User message text"
},
{
"type": "image_url",
"image_url": "data:image/webp;base64,...",
"ocr_text": "Text extracted from image (optional)",
"qr_code": "<https://qr-code-url.com> (optional)"
}
]
}

ChatCompletionAssistantMessage

{
"role": "assistant",
"content": "Assistant response text",
"tool_calls": [
{
"id": "call_123",
"type": "function",
"function": {
"name": "reference_check",
"arguments": {
"value": "<https://example.com>",
"type": "url"
}
}
}
]
}

ChatCompletionToolMessage

{
"role": "tool",
"content": "Tool execution result",
"tool_call_id": "call_123"
}

Content Types

ContentTextPart

{
"type": "text",
"text": "Text content"
}

ContentImagePart

{
"type": "image_url",
"image_url": "data:image/webp;base64,...", // or URL
"ocr_text": "Text extracted from image (optional)",
"qr_code": "<https://example.com> (optional QR code content)"
}

Optional Fields:

ocr_text: Text extracted from the image using client-side OCR

qr_code: QR code content (URL or data) extracted from the image

Note: See Image Processing Guide for format requirements and processing details.

Reference Types and Status Values

See Configuration Constants for complete lists of supported reference types and status values.

Agentic Workflow Examples

Example 1: Complete Scam Detection Workflow

import httpx
import json

class ScamGuardClient:
def **init**(self, api_base_url, product_code, installation_token):
self.api_base_url = api_base_url
self.product_code = product_code
self.installation_token = installation_token
self.thread_id = None # Will be set from first API response
self.messages = []
self.pending_reports = {} # Track references awaiting user confirmation

    def chat_completion(self, user_message, usecase="chat"):
        """Send chat completion request"""
        if user_message:  # Only add message if provided
            self.messages.append({
                "role": "user",
                "content": [{"type": "text", "text": user_message}]
            })

        request = {
            "usecase": usecase,
            "messages": self.messages,
            "client": {
                "version": "1.0",
                "productCode": self.product_code,
                "region_code": "US"
            },
            "installation": {
                "installationToken": self.installation_token
            }
        }

        # Include thread_id only if we have one
        if self.thread_id:
            request["thread_id"] = self.thread_id

        with httpx.Client() as client:
            response = client.post(
                f"{self.api_base_url}/v1/chat/completion",
                json=request
            )
            response.raise_for_status()
            result = response.json()

            # Set thread_id from response if not already set
            if not self.thread_id and "thread_id" in result:
                self.thread_id = result["thread_id"]

            return result

    def process_tool_calls(self, tool_calls):
        """Process tool calls and generate tool messages"""
        for tool_call in tool_calls:
            if tool_call["function"]["name"] == "reference_check":
                # Process reference check
                args = tool_call["function"]["arguments"]
                result = self.check_reference(args["value"], args["type"])

                tool_message = {
                    "role": "tool",
                    "content": f"Reference check result for {args['value']}: {result['status']}",
                    "tool_call_id": tool_call["id"]
                }
                self.messages.append(tool_message)

            elif tool_call["function"]["name"] == "reference_report":
                # Process reference report - return confirmation message
                # The actual reporting happens separately when user confirms
                args = tool_call["function"]["arguments"]
                tool_message = {
                    "role": "tool",
                    "content": f"Confirm reporting suspicious reference: {args['value']}. Tap 'Submit' to confirm.",
                    "tool_call_id": tool_call["id"]
                }
                self.messages.append(tool_message)

                # Store reference info for potential reporting
                self.pending_reports[tool_call["id"]] = {
                    "value": args["value"],
                    "type": args["type"]
                }

    def check_reference(self, value, ref_type):
        """Check individual reference - see Reference Check API endpoint for details"""
        # Implementation follows standard request structure pattern
        # See API Endpoints > Reference Check section for complete example
        pass  # Shortened for brevity - see Integration Examples for full implementation

    def submit_report(self, tool_call_id):
        """Submit a report after user confirmation"""
        if tool_call_id not in self.pending_reports:
            return {"error": "No pending report found"}

        report_info = self.pending_reports[tool_call_id]
        request = {
            "reference": {
                "type": report_info["type"],
                "value": report_info["value"]
            },
            "client": {
                "version": "1.0",
                "productCode": self.product_code,
                "region_code": "US"
            },
            "installation": {
                "installationToken": self.installation_token
            },
            "thread_id": self.thread_id,
            "userFeedback": {
                "description": "User confirmed suspicious reference"
            }
        }

        with httpx.Client() as client:
            response = client.post(
                f"{self.api_base_url}/v1/reference/report",
                json=request
            )
            response.raise_for_status()

            # Remove from pending reports
            del self.pending_reports[tool_call_id]
            return response.json()

    def run_conversation(self, initial_message):
        """Run complete agentic conversation with tool call loop"""
        print(f"User: {initial_message}")

        # Send initial message
        response = self.chat_completion(initial_message)
        assistant_message = response["message"]
        self.messages.append(assistant_message)

        # Tool call processing loop with 10 cycle limit
        cycle_count = 0
        max_cycles = 10

        while True:
            cycle_count += 1

            # Check for tool calls
            if not assistant_message.get("tool_calls"):
                # No tool calls - exit loop
                break

            # Check cycle limit
            if cycle_count > max_cycles:
                print(f"Warning: Reached maximum tool call cycles ({max_cycles})")
                break

            print(f"Processing tool calls (cycle {cycle_count})...")

            # Process tool calls
            self.process_tool_calls(assistant_message["tool_calls"])

            # Get next assistant response
            response = self.chat_completion("", usecase="chat")
            assistant_message = response["message"]
            self.messages.append(assistant_message)

        # Display final assistant message
        if assistant_message.get("content"):
            print(f"Assistant: {assistant_message['content']}")

        # Generate conversation title
        title_response = self.chat_completion("", usecase="title")
        title = title_response["message"]["content"]
        print(f"Conversation Title: {title}")

# Usage example

client = ScamGuardClient(
api_base_url="<https://scamguard.malwarebytes.com>",
product_code="mbios-c",
installation_token="your-installation-token"
)

client.run_conversation("Is this link safe? <https://suspicious-site.com>")

Example 2: Multi-Modal Analysis (Text + Image)

def analyze_screenshot(self, image_path, description):
"""Analyze screenshot for scam indicators""" # Process image using the complete pipeline (see Image Processing Guide)
from process_image_for_api import process_image_for_api # From Image Processing Guide

    # Get properly processed image content
    image_content = process_image_for_api(image_path, usecase="chat")

    user_message = {
        "role": "user",
        "content": [
            {
                "type": "text",
                "text": f"Analyze this screenshot: {description}"
            },
            image_content
        ]
    }

    self.messages.append(user_message)
    response = self.chat_completion("", usecase="chat")

    # Process the response and any tool calls
    assistant_message = response["message"]
    if assistant_message.get("tool_calls"):
        self.process_tool_calls(assistant_message["tool_calls"])
        # Get final response after tool execution
        final_response = self.chat_completion("", usecase="chat")
        return final_response["message"]["content"]

    return assistant_message["content"]

# Usage

result = client.analyze_screenshot(
"suspicious_email.png",
"I received this email claiming I won a lottery"
)
print(result)

Note: This example uses the process_image_for_api function from the Image Processing Guide to ensure proper image handling.

Error Handling

Error Response Format

{
"error": {
"state": "validation_error",
"message": "Invalid request data."
}
}

Error States

State

Description

Resolution

validation_error

Invalid request format or data

Check request schema and required fields

internal_server_error

Server-side processing error

Retry request, contact support if persistent

max_image_count_exceeded

Too many images in request (>5)

Reduce image count or send multiple requests

max_context_length_exceeded

Token limit exceeded (>12,500)

Show alert that conversation reached limit and recommend starting new chat

invalid_image_url

Image URL cannot be accessed

Verify URL accessibility and format

invalid_base64_image

Base64 image data is malformed

Check base64 encoding and image format

unknown

Generic error state

Check logs, retry, or contact support

HTTP Status Codes

200 OK: Successful request

400 Bad Request: Invalid request data or authentication

429 Too Many Requests: Rate limit exceeded

500 Internal Server Error: Server-side error

Error Handling Best Practices

import httpx
import time

def make_request_with_retry(url, data, max_retries=3):
"""Make API request with exponential backoff retry"""
for attempt in range(max_retries):
try:
with httpx.Client() as client:
response = client.post(url, json=data)

                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 429:
                    # Rate limited, wait and retry
                    wait_time = 2 ** attempt
                    time.sleep(wait_time)
                    continue
                else:
                    # Parse error response
                    error_data = response.json()
                    print(f"API Error: {error_data['error']['message']}")
                    break

        except httpx.RequestError as e:
            print(f"Request failed: {e}")
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
                continue
            break

    return None

Integration Examples

Complete Agentic Workflow - Python

Implementation following the patterns from Agentic Workflow Examples:

import httpx
import asyncio
from typing import List, Dict, Any

class ScamGuardAgenticClient:
def **init**(self, api_base_url: str, product_code: str, installation_token: str):
self.api_base_url = api_base_url
self.product_code = product_code
self.installation_token = installation_token
self.thread_id = None
self.messages = []
self.pending_reports = {}

    async def chat_completion(self, user_message=None, usecase="chat"):
        """Send chat completion with full agentic workflow support"""
        if user_message:
            self.messages.append({
                "role": "user",
                "content": [{"type": "text", "text": user_message}]
            })

        request = {
            "usecase": usecase,
            "messages": self.messages,
            "client": {
                "version": "1.0",
                "productCode": self.product_code,
                "region_code": "US"
            },
            "installation": {
                "installationToken": self.installation_token
            }
        }

        if self.thread_id:
            request["thread_id"] = self.thread_id

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{self.api_base_url}/v1/chat/completion",
                json=request
            )
            response.raise_for_status()
            result = response.json()

            if not self.thread_id and "thread_id" in result:
                self.thread_id = result["thread_id"]

            return result

    async def process_tool_calls(self, tool_calls):
        """Process tool calls following agentic pattern"""
        for tool_call in tool_calls:
            if tool_call["function"]["name"] == "reference_check":
                args = tool_call["function"]["arguments"]
                result = await self.check_reference(args["value"], args["type"])

                tool_message = {
                    "role": "tool",
                    "content": f"Reference check result for {args['value']}: {result['status']}",
                    "tool_call_id": tool_call["id"]
                }
                self.messages.append(tool_message)

            elif tool_call["function"]["name"] == "reference_report":
                args = tool_call["function"]["arguments"]
                tool_message = {
                    "role": "tool",
                    "content": f"Confirm reporting suspicious reference: {args['value']}. Tap 'Submit' to confirm.",
                    "tool_call_id": tool_call["id"]
                }
                self.messages.append(tool_message)
                self.pending_reports[tool_call["id"]] = {
                    "value": args["value"],
                    "type": args["type"]
                }

    async def check_reference(self, value, ref_type):
        """Check individual reference"""
        request = {
            "reference": {"type": ref_type, "value": value},
            "client": {
                "version": "1.0",
                "productCode": self.product_code,
                "region_code": "US"
            },
            "installation": {
                "installationToken": self.installation_token
            },
            "thread_id": self.thread_id
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{self.api_base_url}/v1/reference/check",
                json=request
            )
            response.raise_for_status()
            return response.json()

    async def run_agentic_conversation(self, initial_message):
        """Complete agentic workflow implementation"""
        print(f"User: {initial_message}")

        response = await self.chat_completion(initial_message)
        assistant_message = response["message"]
        self.messages.append(assistant_message)

        # Tool call processing loop
        cycle_count = 0
        max_cycles = 10

        while assistant_message.get("tool_calls") and cycle_count < max_cycles:
            cycle_count += 1
            print(f"Processing tool calls (cycle {cycle_count})...")

            await self.process_tool_calls(assistant_message["tool_calls"])

            response = await self.chat_completion()
            assistant_message = response["message"]
            self.messages.append(assistant_message)

        if assistant_message.get("content"):
            print(f"Assistant: {assistant_message['content']}")

        # Generate title
        title_response = await self.chat_completion(usecase="title")
        print(f"Title: {title_response['message']['content']}")

        return {
            "conversation": self.messages,
            "title": title_response["message"]["content"],
            "pending_reports": self.pending_reports
        }

# Usage example

async def main():
client = ScamGuardAgenticClient(
api_base_url="<https://scamguard.malwarebytes.com>",
product_code="mbios-c",
installation_token="your-installation-token"
)

    result = await client.run_agentic_conversation(
        "I received this text: URGENT! You have won $50,000! Claim now at <https://fake-lottery.com/claim>"
    )

    print(f"Conversation completed with {len(result['pending_reports'])} pending reports")

asyncio.run(main())

JavaScript/Node.js Agentic Example

class ScamGuardAgenticClient {
constructor(apiBaseUrl, productCode, installationToken) {
this.apiBaseUrl = apiBaseUrl;
this.productCode = productCode;
this.installationToken = installationToken;
this.threadId = null;
this.messages = [];
this.pendingReports = {};
}

    async chatCompletion(userMessage = null, usecase = 'chat') {
        if (userMessage) {
            this.messages.push({
                role: 'user',
                content: [{ type: 'text', text: userMessage }]
            });
        }

        const requestData = {
            usecase,
            messages: this.messages,
            client: {
                version: '1.0',
                productCode: this.productCode,
                region_code: 'US'
            },
            installation: {
                installationToken: this.installationToken
            }
        };

        if (this.threadId) {
            requestData.thread_id = this.threadId;
        }

        const response = await fetch(`${this.apiBaseUrl}/v1/chat/completion`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-correlation-id': `req-${Date.now()}`
            },
            body: JSON.stringify(requestData)
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(`API Error: ${errorData.error.message}`);
        }

        const result = await response.json();
        if (!this.threadId && result.thread_id) {
            this.threadId = result.thread_id;
        }

        return result;
    }

    async processToolCalls(toolCalls) {
        for (const toolCall of toolCalls) {
            if (toolCall.function.name === 'reference_check') {
                const args = toolCall.function.arguments;
                const result = await this.checkReference(args.value, args.type);

                this.messages.push({
                    role: 'tool',
                    content: `Reference check result for ${args.value}: ${result.status}`,
                    tool_call_id: toolCall.id
                });
            } else if (toolCall.function.name === 'reference_report') {
                const args = toolCall.function.arguments;

                this.messages.push({
                    role: 'tool',
                    content: `Confirm reporting suspicious reference: ${args.value}. Tap 'Submit' to confirm.`,
                    tool_call_id: toolCall.id
                });

                this.pendingReports[toolCall.id] = {
                    value: args.value,
                    type: args.type
                };
            }
        }
    }

    async checkReference(value, type) {
        const requestData = {
            reference: { type, value },
            client: {
                version: '1.0',
                productCode: this.productCode,
                region_code: 'US'
            },
            installation: {
                installationToken: this.installationToken
            },
            thread_id: this.threadId
        };

        const response = await fetch(`${this.apiBaseUrl}/v1/reference/check`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestData)
        });

        if (!response.ok) throw new Error('Reference check failed');
        return await response.json();
    }

    async runAgenticConversation(initialMessage) {
        console.log(`User: ${initialMessage}`);

        let response = await this.chatCompletion(initialMessage);
        let assistantMessage = response.message;
        this.messages.push(assistantMessage);

        // Tool call processing loop
        let cycleCount = 0;
        const maxCycles = 10;

        while (assistantMessage.tool_calls && cycleCount < maxCycles) {
            cycleCount++;
            console.log(`Processing tool calls (cycle ${cycleCount})...`);

            await this.processToolCalls(assistantMessage.tool_calls);

            response = await this.chatCompletion();
            assistantMessage = response.message;
            this.messages.push(assistantMessage);
        }

        if (assistantMessage.content) {
            console.log(`Assistant: ${assistantMessage.content}`);
        }

        // Generate title
        const titleResponse = await this.chatCompletion(null, 'title');
        console.log(`Title: ${titleResponse.message.content}`);

        return {
            conversation: this.messages,
            title: titleResponse.message.content,
            pendingReports: this.pendingReports
        };
    }

}

// Usage
const client = new ScamGuardAgenticClient(
'<https://scamguard.malwarebytes.com',>
'mbios-c',
'your-installation-token'
);

client.runAgenticConversation('I received this text: URGENT! You have won $50,000! Claim now at <https://fake-lottery.com/claim')>
.then(result => console.log('Conversation completed:', result))
.catch(error => console.error('Error:', error));

Rate Limits

Current Limits

Request Timeout: 30 seconds per request (AWS Gateway infrastructure limitation)

Maximum Images: 5 per chat completion request

Image Processing: See Image Processing Guide for format requirements and client-side processing details

Context Length: 12,500 tokens maximum

Output Length: 2,000 tokens maximum

Concurrent Requests: No explicit limit, but recommended to use reasonable concurrency

For additional support or questions, please contact the ScamGuard development team (@Aleksandr Kucherenko @Shahak Shalev ).
