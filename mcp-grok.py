"""
VectorLedger MCP integration for xAI Grok.

Grok does not use a local config file for MCP. Instead, you pass the MCP
server in the `tools` array on each API request. This script demonstrates
how to connect Grok to the VectorLedger MCP server running at
http://127.0.0.1:3000/sse.

Prerequisites:
  pip install openai

Usage:
  XAI_API_KEY=<your_key> python mcp-grok.py
"""

import os
from openai import OpenAI

XAI_API_KEY = os.environ.get("XAI_API_KEY")
if not XAI_API_KEY:
    raise EnvironmentError("XAI_API_KEY environment variable is not set.")

client = OpenAI(
    api_key=XAI_API_KEY,
    base_url="https://api.x.ai/v1",
)

VLEDGER_MCP = {
    "type": "mcp",
    "server_url": "http://127.0.0.1:3000/sse",   # VectorLedger MCP server (SSE)
    "server_label": "vledger",
    "server_description": "VectorLedger ledger operations, audit, compliance, and crypto tools.",
}

def ask_grok(prompt: str) -> str:
    """Send a prompt to Grok with the VectorLedger MCP server attached."""
    response = client.responses.create(
        model="grok-4.7",
        input=[{"role": "user", "content": prompt}],
        tools=[VLEDGER_MCP],
    )
    return response.output_text


if __name__ == "__main__":
    result = ask_grok("What tools does VectorLedger expose?")
    print(result)
