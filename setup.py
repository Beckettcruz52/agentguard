#!/usr/bin/env python3
from setuptools import setup, find_packages

setup(
    name="agentguard",
    version="1.0.0",
    description="Vector Memory Poisoning Scanner & Runtime Tool Sandbox for Autonomous AI Agents",
    author="AgentGuard Security Team",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "agentguard": ["../../web/*"],
    },
    python_requires=">=3.9",
    install_requires=[],
    extras_require={
        "hf": [
            "sentence-transformers>=2.2.0",
            "transformers>=4.30.0",
            "huggingface_hub>=0.20.0",
        ],
        "all": [
            "sentence-transformers>=2.2.0",
            "transformers>=4.30.0",
            "huggingface_hub>=0.20.0",
            "langchain>=0.1.0",
            "chromadb>=0.4.0",
            "crewai>=0.28.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "agentguard=agentguard.server.api:run_server_cli",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
)
