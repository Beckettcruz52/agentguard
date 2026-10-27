#!/usr/bin/env python3
"""
AgentGuard Launcher: Vector Memory Poisoning Scanner & Runtime Tool Sandbox.
Run this script to start the AgentGuard security suite and interactive web dashboard.
"""

import sys
import os

# Ensure package is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agentguard.server.api import run_server


def main():
    port = int(os.environ.get("PORT", 8765))
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass

    print("==================================================================")
    print("🛡️  AegisAI Security Gateway for Autonomous AI Agents")
    print("==================================================================")
    print(f"📡 Web Console: http://localhost:{port}")
    print(f"🧠 Memory Shield (RAG Poisoning Scanner): Active")
    print(f"⚡ Runtime Permission & Tool Sandbox: Enforced")
    print("==================================================================")
    print("Press Ctrl+C to terminate.")

    httpd = run_server(port=port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping AgentGuard server...")
        httpd.server_close()
        print("AgentGuard stopped.")


if __name__ == "__main__":
    main()
