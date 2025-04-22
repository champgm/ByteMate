package bytemate;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;

import ghidra.util.Msg;
import okhttp3.*;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

/**
 * Service to handle API calls to different LLM providers.
 */
public class LLMService {
    
    private static final OkHttpClient client = new OkHttpClient();
    private static final Gson gson = new Gson();
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    
    /**
     * Sends a request to the specified LLM model.
     * 
     * @param provider The LLM provider (OpenAI, Claude, Google)
     * @param model The specific model to use
     * @param apiKey The API key for the provider
     * @param prompt The user's prompt
     * @param chatHistory The conversation history
     * @return A CompletableFuture containing the LLM's response
     */
    public static CompletableFuture<String> sendRequest(String provider, String model, String apiKey, 
                                                      String prompt, String chatHistory) {
        CompletableFuture<String> future = new CompletableFuture<>();
        
        try {
            switch (provider) {
                case "OpenAI":
                    callOpenAI(model, apiKey, prompt, chatHistory, future);
                    break;
                case "Claude":
                    callClaude(model, apiKey, prompt, chatHistory, future);
                    break;
                case "Google":
                    callGoogle(model, apiKey, prompt, chatHistory, future);
                    break;
                default:
                    future.completeExceptionally(new IllegalArgumentException("Unsupported provider: " + provider));
            }
        } catch (Exception e) {
            future.completeExceptionally(e);
        }
        
        return future;
    }
    
    /**
     * Sends a request to the specified LLM model with additional context information.
     * 
     * @param provider The LLM provider (OpenAI, Claude, Google)
     * @param model The specific model to use
     * @param apiKey The API key for the provider
     * @param prompt The user's prompt
     * @param chatHistory The conversation history
     * @param contextInfo The context information from Ghidra
     * @return A CompletableFuture containing the LLM's response
     */
    public static CompletableFuture<String> sendRequestWithContext(String provider, String model, String apiKey, 
                                                                String prompt, String chatHistory, String contextInfo) {
        CompletableFuture<String> future = new CompletableFuture<>();
        
        try {
            // Combine context information with the user prompt
            String promptWithContext = contextInfo + prompt;
            
            switch (provider) {
                case "OpenAI":
                    callOpenAIWithContext(model, apiKey, prompt, contextInfo, chatHistory, future);
                    break;
                case "Claude":
                    callClaudeWithContext(model, apiKey, prompt, contextInfo, chatHistory, future);
                    break;
                case "Google":
                    callGoogleWithContext(model, apiKey, prompt, contextInfo, chatHistory, future);
                    break;
                default:
                    future.completeExceptionally(new IllegalArgumentException("Unsupported provider: " + provider));
            }
        } catch (Exception e) {
            future.completeExceptionally(e);
        }
        
        return future;
    }
    
    private static void callOpenAI(String model, String apiKey, String prompt, String chatHistory,
                                  CompletableFuture<String> future) {
        JsonObject requestBody = new JsonObject();
        requestBody.addProperty("model", model);
        
        JsonArray messages = new JsonArray();
        
        // Add system message with tool instructions
        JsonObject systemMessage = new JsonObject();
        systemMessage.addProperty("role", "system");
        systemMessage.addProperty("content", getSystemPromptWithTools());
        messages.add(systemMessage);
        
        // Add chat history and new prompt
        if (chatHistory != null && !chatHistory.isEmpty()) {
            // Parse chat history and add to messages
            try {
                JsonArray historyArray = gson.fromJson(chatHistory, JsonArray.class);
                for (int i = 0; i < historyArray.size(); i++) {
                    messages.add(historyArray.get(i));
                }
            } catch (Exception e) {
                Msg.error(LLMService.class, "Error parsing chat history in callOpenAI: " + e.getMessage());
                // Decide how to handle history parse error: continue without history or fail?
                // For now, continuing without history.
            }
        }
        
        // Add user prompt
        JsonObject userMessage = new JsonObject();
        userMessage.addProperty("role", "user");
        userMessage.addProperty("content", prompt);
        messages.add(userMessage);
        
        requestBody.add("messages", messages);
        
        Request request = new Request.Builder()
            .url("https://api.openai.com/v1/chat/completions")
            .addHeader("Authorization", "Bearer " + apiKey)
            .addHeader("Content-Type", "application/json")
            .post(RequestBody.create(requestBody.toString(), JSON))
            .build();
        
        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                future.completeExceptionally(e);
            }
            
            @Override
            public void onResponse(Call call, Response response) throws IOException {
                try (ResponseBody responseBody = response.body()) {
                    if (!response.isSuccessful() || responseBody == null) {
                        future.completeExceptionally(new IOException("Unexpected response " + response));
                        return;
                    }
                    
                    String responseString = responseBody.string();
                    JsonObject jsonResponse = gson.fromJson(responseString, JsonObject.class);
                    
                    if (jsonResponse.has("choices") && jsonResponse.getAsJsonArray("choices").size() > 0) {
                        String content = jsonResponse.getAsJsonArray("choices")
                                                     .get(0)
                                                     .getAsJsonObject()
                                                     .getAsJsonObject("message")
                                                     .get("content")
                                                     .getAsString();
                        future.complete(content);
                    } else {
                        future.completeExceptionally(new IOException("Invalid response format"));
                    }
                }
            }
        });
    }
    
    private static void callClaude(String model, String apiKey, String prompt, String chatHistory,
                                  CompletableFuture<String> future) {
        JsonObject requestBody = new JsonObject();
        requestBody.addProperty("model", model);
        
        JsonArray messages = new JsonArray();
        
        // Add system message with tool instructions
        JsonObject systemMessage = new JsonObject();
        systemMessage.addProperty("role", "system");
        systemMessage.addProperty("content", getSystemPromptWithTools());
        messages.add(systemMessage);
        
        // Add chat history
        if (chatHistory != null && !chatHistory.isEmpty()) {
            try {
                JsonArray historyArray = gson.fromJson(chatHistory, JsonArray.class);
                for (int i = 0; i < historyArray.size(); i++) {
                    messages.add(historyArray.get(i));
                }
            } catch (Exception e) {
                Msg.error(LLMService.class, "Error parsing chat history in callClaude: " + e.getMessage());
                // Decide how to handle history parse error. Continuing without history.
            }
        }
        
        // Add user prompt
        JsonObject userMessage = new JsonObject();
        userMessage.addProperty("role", "user");
        userMessage.addProperty("content", prompt);
        messages.add(userMessage);
        
        requestBody.add("messages", messages);
        
        Request request = new Request.Builder()
            .url("https://api.anthropic.com/v1/messages")
            .addHeader("x-api-key", apiKey)
            .addHeader("anthropic-version", "2023-06-01")
            .addHeader("Content-Type", "application/json")
            .post(RequestBody.create(requestBody.toString(), JSON))
            .build();
        
        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                future.completeExceptionally(e);
            }
            
            @Override
            public void onResponse(Call call, Response response) throws IOException {
                try (ResponseBody responseBody = response.body()) {
                    if (!response.isSuccessful() || responseBody == null) {
                        future.completeExceptionally(new IOException("Unexpected response " + response));
                        return;
                    }
                    
                    String responseString = responseBody.string();
                    JsonObject jsonResponse = gson.fromJson(responseString, JsonObject.class);
                    
                    if (jsonResponse.has("content") && jsonResponse.getAsJsonArray("content").size() > 0) {
                        String content = jsonResponse.getAsJsonArray("content")
                                                     .get(0)
                                                     .getAsJsonObject()
                                                     .get("text")
                                                     .getAsString();
                        future.complete(content);
                    } else {
                        future.completeExceptionally(new IOException("Invalid response format"));
                    }
                }
            }
        });
    }
    
    private static void callGoogle(String model, String apiKey, String prompt, String chatHistory,
                                  CompletableFuture<String> future) {
        JsonObject requestBody = new JsonObject();
        
        JsonArray contents = new JsonArray();
        
        // Add system message with tool instructions (needed for Google Gemini)
        JsonObject systemMessage = new JsonObject();
        systemMessage.addProperty("role", "system"); // Although Google uses 'user'/'model', system role might be interpreted
        JsonArray systemParts = new JsonArray();
        JsonObject systemPart = new JsonObject();
        systemPart.addProperty("text", getSystemPromptWithTools());
        systemParts.add(systemPart);
        systemMessage.add("parts", systemParts);
        contents.add(systemMessage);
        
        // Add chat history
        if (chatHistory != null && !chatHistory.isEmpty()) {
             try {
                JsonArray historyArray = gson.fromJson(chatHistory, JsonArray.class);
                for (int i = 0; i < historyArray.size(); i++) {
                    // Ensure history messages are in the correct Google format
                    JsonObject historyMsg = historyArray.get(i).getAsJsonObject();
                    if (historyMsg.has("role") && historyMsg.has("content")) {
                        String role = historyMsg.get("role").getAsString();
                        String content = historyMsg.get("content").getAsString();
                        
                        JsonObject googleMsg = new JsonObject();
                        // Map roles: "user" -> "user", "assistant" -> "model"
                        googleMsg.addProperty("role", "assistant".equalsIgnoreCase(role) ? "model" : "user"); 
                        
                        JsonArray parts = new JsonArray();
                        JsonObject part = new JsonObject();
                        part.addProperty("text", content);
                        parts.add(part);
                        googleMsg.add("parts", parts);
                        
                        contents.add(googleMsg);
                    }
                }
            } catch (Exception e) {
                Msg.error(LLMService.class, "Error parsing chat history in callGoogle: " + e.getMessage());
                // Decide how to handle history parse error. Continuing without history.
            }
        }

        // Add user prompt
        JsonObject userMessage = new JsonObject();
        userMessage.addProperty("role", "user");
        // userMessage.addProperty("parts", prompt); // Incorrect structure for Google API
        JsonArray userParts = new JsonArray();
        JsonObject userPart = new JsonObject();
        userPart.addProperty("text", prompt);
        userParts.add(userPart);
        userMessage.add("parts", userParts);
        contents.add(userMessage);
        
        requestBody.add("contents", contents);
        
        String url = "https://generativelanguage.googleapis.com/v1beta/models/" + model + ":generateContent?key=" + apiKey;
        
        Request request = new Request.Builder()
            .url(url)
            .addHeader("Content-Type", "application/json")
            .post(RequestBody.create(requestBody.toString(), JSON))
            .build();
        
        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                future.completeExceptionally(e);
            }
            
            @Override
            public void onResponse(Call call, Response response) throws IOException {
                try (ResponseBody responseBody = response.body()) {
                    if (!response.isSuccessful() || responseBody == null) {
                        future.completeExceptionally(new IOException("Unexpected response " + response));
                        return;
                    }
                    
                    String responseString = responseBody.string();
                    JsonObject jsonResponse = gson.fromJson(responseString, JsonObject.class);
                    
                    if (jsonResponse.has("candidates") && jsonResponse.getAsJsonArray("candidates").size() > 0) {
                        String content = jsonResponse.getAsJsonArray("candidates")
                                                     .get(0)
                                                     .getAsJsonObject()
                                                     .getAsJsonObject("content")
                                                     .getAsJsonArray("parts")
                                                     .get(0)
                                                     .getAsJsonObject()
                                                     .get("text")
                                                     .getAsString();
                        future.complete(content);
                    } else {
                        future.completeExceptionally(new IOException("Invalid response format"));
                    }
                }
            }
        });
    }
    
    private static void callOpenAIWithContext(String model, String apiKey, String prompt, String contextInfo,
                                           String chatHistory, CompletableFuture<String> future) {
        JsonObject requestBody = new JsonObject();
        requestBody.addProperty("model", model);
        
        JsonArray messages = new JsonArray();
        
        // Add system message with tool instructions
        JsonObject systemMessage = new JsonObject();
        systemMessage.addProperty("role", "system");
        systemMessage.addProperty("content", getSystemPromptWithTools());
        messages.add(systemMessage);
        
        // Add chat history
        if (chatHistory != null && !chatHistory.isEmpty()) {
            try {
                JsonArray historyArray = gson.fromJson(chatHistory, JsonArray.class);
                for (int i = 0; i < historyArray.size(); i++) {
                    messages.add(historyArray.get(i));
                }
            } catch (Exception e) {
                Msg.error(LLMService.class, "Error parsing chat history: " + e.getMessage());
            }
        }
        
        // Add context as a separate system message
        if (contextInfo != null && !contextInfo.isEmpty()) {
            JsonObject contextMessage = new JsonObject();
            contextMessage.addProperty("role", "system");
            contextMessage.addProperty("content", "Current context: " + contextInfo);
            messages.add(contextMessage);
        }
        
        // Add user prompt
        JsonObject userMessage = new JsonObject();
        userMessage.addProperty("role", "user");
        userMessage.addProperty("content", prompt);
        messages.add(userMessage);
        
        requestBody.add("messages", messages);
        
        // For debugging
        Msg.debug(LLMService.class, "Sending OpenAI request with " + messages.size() + " messages");
        
        Request request = new Request.Builder()
            .url("https://api.openai.com/v1/chat/completions")
            .addHeader("Authorization", "Bearer " + apiKey)
            .addHeader("Content-Type", "application/json")
            .post(RequestBody.create(requestBody.toString(), JSON))
            .build();
        
        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                future.completeExceptionally(e);
            }
            
            @Override
            public void onResponse(Call call, Response response) throws IOException {
                try (ResponseBody responseBody = response.body()) {
                    if (!response.isSuccessful() || responseBody == null) {
                        future.completeExceptionally(new IOException("Unexpected response " + response));
                        return;
                    }
                    
                    String responseString = responseBody.string();
                    JsonObject jsonResponse = gson.fromJson(responseString, JsonObject.class);
                    
                    if (jsonResponse.has("choices") && jsonResponse.getAsJsonArray("choices").size() > 0) {
                        String content = jsonResponse.getAsJsonArray("choices")
                                                     .get(0)
                                                     .getAsJsonObject()
                                                     .getAsJsonObject("message")
                                                     .get("content")
                                                     .getAsString();
                        future.complete(content);
                    } else {
                        future.completeExceptionally(new IOException("Invalid response format"));
                    }
                }
            }
        });
    }
    
    private static void callClaudeWithContext(String model, String apiKey, String prompt, String contextInfo,
                                            String chatHistory, CompletableFuture<String> future) {
        JsonObject requestBody = new JsonObject();
        requestBody.addProperty("model", model);
        
        JsonArray messages = new JsonArray();
        
        // Add system message with tool instructions
        JsonObject systemMessage = new JsonObject();
        systemMessage.addProperty("role", "system");
        systemMessage.addProperty("content", getSystemPromptWithTools());
        messages.add(systemMessage);
        
        // Add chat history
        if (chatHistory != null && !chatHistory.isEmpty()) {
            try {
                JsonArray historyArray = gson.fromJson(chatHistory, JsonArray.class);
                for (int i = 0; i < historyArray.size(); i++) {
                    messages.add(historyArray.get(i));
                }
            } catch (Exception e) {
                Msg.error(LLMService.class, "Error parsing chat history: " + e.getMessage());
            }
        }
        
        // Add context as a separate system message
        if (contextInfo != null && !contextInfo.isEmpty()) {
            JsonObject contextMessage = new JsonObject();
            contextMessage.addProperty("role", "system");
            contextMessage.addProperty("content", "Current context: " + contextInfo);
            messages.add(contextMessage);
        }
        
        // Add user prompt
        JsonObject userMessage = new JsonObject();
        userMessage.addProperty("role", "user");
        userMessage.addProperty("content", prompt);
        messages.add(userMessage);
        
        requestBody.add("messages", messages);
        
        // For debugging
        Msg.debug(LLMService.class, "Sending Claude request with " + messages.size() + " messages");
        
        Request request = new Request.Builder()
            .url("https://api.anthropic.com/v1/messages")
            .addHeader("x-api-key", apiKey)
            .addHeader("anthropic-version", "2023-06-01")
            .addHeader("Content-Type", "application/json")
            .post(RequestBody.create(requestBody.toString(), JSON))
            .build();
        
        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                future.completeExceptionally(e);
            }
            
            @Override
            public void onResponse(Call call, Response response) throws IOException {
                try (ResponseBody responseBody = response.body()) {
                    if (!response.isSuccessful() || responseBody == null) {
                        future.completeExceptionally(new IOException("Unexpected response " + response));
                        return;
                    }
                    
                    String responseString = responseBody.string();
                    JsonObject jsonResponse = gson.fromJson(responseString, JsonObject.class);
                    
                    if (jsonResponse.has("content") && jsonResponse.getAsJsonArray("content").size() > 0) {
                        String content = jsonResponse.getAsJsonArray("content")
                                                    .get(0)
                                                    .getAsJsonObject()
                                                    .get("text")
                                                    .getAsString();
                        future.complete(content);
                    } else {
                        future.completeExceptionally(new IOException("Invalid response format"));
                    }
                }
            }
        });
    }
    
    private static void callGoogleWithContext(String model, String apiKey, String prompt, String contextInfo,
                                            String chatHistory, CompletableFuture<String> future) {
        JsonObject requestBody = new JsonObject();
        
        JsonArray contents = new JsonArray();
        
        // Add system message with tool instructions
        JsonObject systemMessage = new JsonObject();
        systemMessage.addProperty("role", "system");
        
        JsonArray systemParts = new JsonArray();
        JsonObject systemPart = new JsonObject();
        systemPart.addProperty("text", getSystemPromptWithTools());
        systemParts.add(systemPart);
        
        systemMessage.add("parts", systemParts);
        contents.add(systemMessage);
        
        // Add chat history
        if (chatHistory != null && !chatHistory.isEmpty()) {
            try {
                JsonArray historyArray = gson.fromJson(chatHistory, JsonArray.class);
                for (int i = 0; i < historyArray.size(); i++) {
                    contents.add(historyArray.get(i));
                }
            } catch (Exception e) {
                Msg.error(LLMService.class, "Error parsing chat history: " + e.getMessage());
            }
        }
        
        // Add context as a separate system message
        if (contextInfo != null && !contextInfo.isEmpty()) {
            JsonObject contextMessage = new JsonObject();
            contextMessage.addProperty("role", "system");
            
            JsonArray contextParts = new JsonArray();
            JsonObject contextPart = new JsonObject();
            contextPart.addProperty("text", "Current context: " + contextInfo);
            contextParts.add(contextPart);
            
            contextMessage.add("parts", contextParts);
            contents.add(contextMessage);
        }
        
        // Add user prompt
        JsonObject userMessage = new JsonObject();
        userMessage.addProperty("role", "user");
        
        JsonArray userParts = new JsonArray();
        JsonObject userPart = new JsonObject();
        userPart.addProperty("text", prompt);
        userParts.add(userPart);
        
        userMessage.add("parts", userParts);
        contents.add(userMessage);
        
        requestBody.add("contents", contents);
        
        // For debugging
        Msg.debug(LLMService.class, "Sending Google request with " + contents.size() + " messages");
        
        String url = "https://generativelanguage.googleapis.com/v1beta/models/" + model + ":generateContent?key=" + apiKey;
        
        Request request = new Request.Builder()
            .url(url)
            .addHeader("Content-Type", "application/json")
            .post(RequestBody.create(requestBody.toString(), JSON))
            .build();
        
        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                future.completeExceptionally(e);
            }
            
            @Override
            public void onResponse(Call call, Response response) throws IOException {
                try (ResponseBody responseBody = response.body()) {
                    if (!response.isSuccessful() || responseBody == null) {
                        future.completeExceptionally(new IOException("Unexpected response " + response));
                        return;
                    }
                    
                    String responseString = responseBody.string();
                    JsonObject jsonResponse = gson.fromJson(responseString, JsonObject.class);
                    
                    if (jsonResponse.has("candidates") && jsonResponse.getAsJsonArray("candidates").size() > 0) {
                        String content = jsonResponse.getAsJsonArray("candidates")
                                                     .get(0)
                                                     .getAsJsonObject()
                                                     .getAsJsonObject("content")
                                                     .getAsJsonArray("parts")
                                                     .get(0)
                                                     .getAsJsonObject()
                                                     .get("text")
                                                     .getAsString();
                        future.complete(content);
                    } else {
                        future.completeExceptionally(new IOException("Invalid response format"));
                    }
                }
            }
        });
    }
    
    /**
     * Get system prompt with tool instructions
     * 
     * @return The system prompt including tool instructions
     */
    public static String getSystemPromptWithTools() {
        StringBuilder sb = new StringBuilder();
        sb.append("You are a helpful reverse engineering assistant in Ghidra. ");
        sb.append("You have access to the following tools that can modify the current program:\n\n");
        
        // Code Modification Tools
        sb.append("## Code Modification Tools\n");
        sb.append("1. **Rename Function**: Rename the current function to a more meaningful name.\n");
        sb.append("   - Usage: `rename function to 'newName'`\n\n");
        
        sb.append("2. **Add Comments**: Add comments to the current function.\n");
        sb.append("   - Usage: `add [pre|eol|post|plate] comment 'Your comment text'`\n");
        sb.append("   - PRE: Comment appears before the instruction\n");
        sb.append("   - EOL: Comment appears at the end of the line\n");
        sb.append("   - POST: Comment appears after the instruction\n");
        sb.append("   - PLATE: Comment appears as a block above the function\n\n");
        
        sb.append("3. **Rename Variable**: Rename a variable to a more meaningful name.\n");
        sb.append("   - Usage: `rename variable 'oldName' to 'newName'`\n\n");
        
        sb.append("4. **Apply Data Type**: Change the data type of a variable.\n");
        sb.append("   - Usage: `apply type 'typeName' to variable 'varName'`\n");
        sb.append("   - Example: `apply type 'char *' to variable 'data'`\n\n");
        
        sb.append("5. **Modify Function Signature**: Update a function's signature.\n");
        sb.append("   - Usage: `modify function signature to 'returnType functionName(paramType1 paramName1, ...)'`\n");
        sb.append("   - Example: `modify function signature to 'int processData(char *buffer, size_t length)'`\n\n");
        
        // Navigation Tools
        sb.append("## Navigation and Analysis Tools\n");
        sb.append("1. **Find References**: Find all references to the current function.\n");
        sb.append("   - Usage: `find references` or `find references to current`\n");
        sb.append("   - To find references to a specific function: `find references to function 'functionName'`\n\n");
        
        sb.append("2. **Search Functions**: Search for functions by name pattern.\n");
        sb.append("   - Usage: `search functions 'pattern'`\n");
        sb.append("   - Example: `search functions 'main*'` to find all functions starting with 'main'\n\n");
        
        sb.append("3. **Go To Address**: Navigate to a specific address in the program.\n");
        sb.append("   - Usage: `go to address '0x1234'` or `jump to address '1234'`\n\n");
        
        sb.append("4. **Search Variables**: Search for variables by name pattern.\n");
        sb.append("   - Usage: `search variables 'pattern'`\n");
        sb.append("   - Example: `search variables 'count*'` to find all variables starting with 'count'\n\n");
        
        sb.append("5. **Find Variable References**: Find all references to a specific variable.\n");
        sb.append("   - Usage: `find references to variable 'varName'`\n\n");
        
        // Structure Tools
        sb.append("## Structure Tools\n");
        sb.append("1. **Create Structure**: Create a new structure definition.\n");
        sb.append("   - Usage: `create structure 'structName'`\n\n");
        
        sb.append("2. **Modify Structure**: Add a field to an existing structure.\n");
        sb.append("   - Usage: `modify structure 'structName' add field 'fieldName' of type 'typeName'`\n");
        sb.append("   - Example: `modify structure 'Point' add field 'z' of type 'int'`\n\n");
        
        sb.append("3. **Map Variable to Structure**: Map a variable to a structure type.\n");
        sb.append("   - Usage: `map variable 'varName' to structure 'structName'`\n");
        sb.append("   - Example: `map variable 'pPoint' to structure 'Point'`\n\n");
        
        // Pattern Recognition Tools
        sb.append("## Pattern Recognition Tools\n");
        sb.append("1. **Identify Algorithm**: Identify common algorithms in a function.\n");
        sb.append("   - Usage: `identify algorithm`\n");
        sb.append("   - For a specific function: `identify algorithm in function 'functionName'`\n\n");
        
        sb.append("2. **Find Similar Code**: Find functions with similar code patterns.\n");
        sb.append("   - Usage: `find similar code`\n");
        sb.append("   - For a specific function: `find similar code to function 'functionName'`\n\n");
        
        sb.append("3. **Detect Vulnerabilities**: Detect potential security vulnerabilities.\n");
        sb.append("   - Usage: `detect vulnerabilities`\n");
        sb.append("   - For a specific function: `detect vulnerabilities in function 'functionName'`\n\n");
        
        sb.append("4. **Identify VTable**: Identify and analyze potential VTable structures.\n");
        sb.append("   - Usage: `identify vtable` or `identify vtable at address '0x1234'`\n\n");
        
        // Analysis Tools
        sb.append("## Analysis Tools\n");
        sb.append("1. **Analyze Data Flow**: Analyze data flow for a function or variable.\n");
        sb.append("   - Usage: `analyze data flow` or `analyze data flow for variable 'varName'`\n\n");
        
        sb.append("2. **Generate Documentation**: Generate documentation for a function.\n");
        sb.append("   - Usage: `generate documentation`\n");
        sb.append("   - For a specific function: `generate documentation for function 'functionName'`\n\n");
        
        // Script Generation Tools
        sb.append("## Script Generation Tools\n");
        sb.append("1. **Generate Script**: Generate a script for automating tasks.\n");
        sb.append("   - Usage: `generate [python|java|ghidra] script 'scriptPurpose'`\n");
        sb.append("   - Example: `generate python script 'extract all strings from the binary'`\n\n");
        
        // Instructions on how to use tools
        sb.append("## How to Use Tools\n");
        sb.append("When a user asks you to perform an action that can be done with these tools, ");
        sb.append("DO NOT just provide a text response or code. Instead, respond with the appropriate tool command ");
        sb.append("in your message. For example:\n\n");
        
        sb.append("User: \"Please add a comment explaining what this function does\"\n");
        sb.append("You: \"I'll add a descriptive comment to the function. add plate comment 'This function processes input data and validates it against the schema before storing in the database.'\"\n\n");
        
        sb.append("You can use single quotes ('), double quotes (\"), or backticks (`) for the command text, like these examples:\n");
        sb.append("You: \"I'll add a descriptive comment to the function. add plate comment \"This function processes input data and validates it against the schema before storing in the database.\"\"\n");
        sb.append("You: \"I'll add a descriptive comment to the function. add plate comment `This function processes input data and validates it against the schema before storing in the database.`\"\n\n");
        
        sb.append("User: \"This function should be called processUserInput\"\n");
        sb.append("You: \"I'll rename the function to be more descriptive. rename function to 'processUserInput'\"\n\n");
        
        sb.append("User: \"Where is this function called from?\"\n");
        sb.append("You: \"Let me find all the places that call this function. find references\"\n\n");
        
        sb.append("User: \"Find all functions that might be related to network operations\"\n");
        sb.append("You: \"I'll search for functions with network-related names. search functions '*network*'\"\n\n");
        
        sb.append("User: \"Can you take me to address 0x1000?\"\n");
        sb.append("You: \"I'll navigate to that address. go to address '0x1000'\"\n\n");
        
        sb.append("User: \"Find all variables that might store a count\"\n");
        sb.append("You: \"I'll search for count-related variables. search variables '*count*'\"\n\n");
        
        sb.append("User: \"I want to create a structure for Point coordinates\"\n");
        sb.append("You: \"I'll create a new structure for that. create structure 'Point'\"\n\n");
        
        sb.append("User: \"The Point structure needs x and y coordinates\"\n");
        sb.append("You: \"I'll add those fields to the structure. modify structure 'Point' add field 'x' of type 'int'\"\n\n");
        
        sb.append("User: \"Can you help me identify if this function contains any common algorithms?\"\n");
        sb.append("You: \"Let me analyze the function for common algorithm patterns. identify algorithm\"\n\n");
        
        sb.append("User: \"Are there any potential security vulnerabilities in this function?\"\n");
        sb.append("You: \"Let me scan the function for potential vulnerabilities. detect vulnerabilities\"\n\n");
        
        sb.append("User: \"I need to create a script to extract all strings from this binary\"\n");
        sb.append("You: \"I'll generate a script for that purpose. generate python script 'extract all strings from the binary'\"\n\n");
        
        sb.append("User: \"How does the data flow through this function?\"\n");
        sb.append("You: \"Let me analyze the data flow in this function. analyze data flow\"\n\n");
        
        sb.append("User: \"Create documentation for this function\"\n");
        sb.append("You: \"I'll generate comprehensive documentation for this function. generate documentation\"\n\n");
        
        sb.append("User: \"This variable should be of type char*\"\n");
        sb.append("You: \"I'll change the data type. apply type 'char *' to variable 'buffer'\"\n\n");
        
        sb.append("User: \"This function should return an int and take a char* and size_t parameter\"\n");
        sb.append("You: \"I'll update the function signature. modify function signature to 'int processData(char *buffer, size_t length)'\"\n\n");
        
        sb.append("User: \"I think this variable is part of a Point structure\"\n");
        sb.append("You: \"I'll map the variable to that structure. map variable 'pPoint' to structure 'Point'\"\n\n");
        
        sb.append("All tool commands will be processed automatically, and you will receive feedback on the success or failure of the operation. ");
        sb.append("The user must confirm each action before it is executed.\n\n");
        
        sb.append("If you're unsure which tool to use or if a specific tool exists for a task, ");
        sb.append("you can ask the user for clarification or suggest the closest tool that might help.");
        
        return sb.toString();
    }
} 
