# Warning: This is 90% Vibe coded

# ByteMate - LLM-powered Assistant for Ghidra

ByteMate is a Ghidra plugin that integrates large language models (LLMs) to assist with reverse engineering tasks. The plugin provides a chat interface similar to GitHub Copilot or Cursor, allowing you to interact with various LLM providers directly within Ghidra.

## Features

- Chat interface for interacting with LLMs
- Support for multiple providers:
  - OpenAI models (GPT-4o, GPT-4-turbo, GPT-3.5-turbo)
  - Anthropic models (Claude 3 Opus, Claude 3 Sonnet, Claude 3 Haiku)
  - Google models (Gemini Pro, Gemini Ultra)
- Code block extraction and copying
- Persistent chat history
- Secure API key storage

## Build
```
gradle distributeExtension
```

## Installation

1. The extension will be created in the `dist` directory after building.
2. In Ghidra, go to File → Install Extensions.
3. Click the "+" button and select the ByteMate ZIP file from the `dist` directory.
4. Restart Ghidra.

## Usage

1. Open ByteMate from the Window menu in Ghidra.
2. Configure your API keys in the Settings dialog.
3. Select your desired LLM provider and model.
4. Type your questions or commands in the input box and click Send.

## API Keys

You'll need to provide your own API keys for the LLM providers. These can be obtained from:

- OpenAI: https://platform.openai.com/
- Anthropic (Claude): https://console.anthropic.com/
- Google (Gemini): https://makersuite.google.com/

## Development

This project was started on a template project created by Ghidra, the reverse engineering tool, from a Ghidra CodeBrowser window using the menu options Tools -> Create VSCode Module project.

Required dependencies:
- OkHttp (for API calls)
- Gson (for JSON processing)

## License

This project is licensed under the Apache License 2.0.
