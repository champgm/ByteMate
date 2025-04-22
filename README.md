# Warning: This is 90% Vibe coded

# ByteMate - LLM-powered Assistant for Ghidra

ByteMate is a Ghidra plugin that integrates large language models (LLMs) to assist with reverse engineering tasks. The plugin provides a chat interface directly within Ghidra, allowing you to interact with various AI models while maintaining context awareness of your current program and function.

## Features

- **Interactive Chat Interface**: Communicate with AI models directly within Ghidra
- **Multi-Provider Support**:
  - OpenAI (GPT-4o, GPT-4-turbo, GPT-3.5-turbo)
  - Anthropic (Claude 3 Opus, Claude 3 Sonnet, Claude 3 Haiku)
  - Google (Gemini Pro, Gemini Ultra)
- **Context-Aware Assistant**: Automatically includes relevant program and function information
- **Specialized Tools**: Access Ghidra-specific tools and commands through the chat interface
- **Code Block Handling**: Extract and copy code blocks from responses
- **Persistent Chat History**: Save and reload your conversation history
- **Secure API Key Management**: Safely store your API credentials

## Building

```
gradle distributeExtension
```
The extension will be created in the `dist` directory after building.

## Testing

To test the plugin, press F5 in VSCode to launch Ghidra. You may need to enable the plugin by opening a Code Browser window and then choosing `File -> Configure` from the menus. Find the "Examples" category of plugins, then toggle this plugin to enabled. 


## Installation

1. In Ghidra, go to File → Install Extensions
2. Click the "+" button and select the ByteMate ZIP file from the `dist` directory
3. Restart Ghidra

## Usage

1. Open ByteMate from the Window menu in Ghidra
2. Configure your API keys in the Settings dialog
3. Select your preferred LLM provider and model
4. Type your questions or commands in the input box and click Send

The assistant can provide insights about your current function and decompiled code, making reverse engineering tasks more efficient.

## API Keys

You'll need to provide your own API keys for the LLM providers:

- OpenAI: https://platform.openai.com/
- Anthropic (Claude): https://console.anthropic.com/
- Google (Gemini): https://makersuite.google.com/

## Development

The project is built on Ghidra's plugin architecture and uses:
- OkHttp for API requests
- Gson for JSON processing
- Ghidra's decompiler API for context extraction

## License

This project is licensed under the Apache License 2.0.
