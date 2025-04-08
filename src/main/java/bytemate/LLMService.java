package bytemate;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;

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
        
        // Add system message
        JsonObject systemMessage = new JsonObject();
        systemMessage.addProperty("role", "system");
        systemMessage.addProperty("content", "You are a helpful reverse engineering assistant in Ghidra.");
        messages.add(systemMessage);
        
        // Add chat history and new prompt
        if (chatHistory != null && !chatHistory.isEmpty()) {
            // In a real implementation, parse chat history and add to messages
            // This is a simplified version
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
        
        // Add system message
        JsonObject systemMessage = new JsonObject();
        systemMessage.addProperty("role", "system");
        systemMessage.addProperty("content", "You are a helpful reverse engineering assistant in Ghidra.");
        messages.add(systemMessage);
        
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
        
        // Add user prompt
        JsonObject userMessage = new JsonObject();
        userMessage.addProperty("role", "user");
        userMessage.addProperty("parts", prompt);
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
        
        // Add system message with instructions to use the context
        JsonObject systemMessage = new JsonObject();
        systemMessage.addProperty("role", "system");
        systemMessage.addProperty("content", 
            "You are a helpful reverse engineering assistant in Ghidra. " +
            "When provided with context information about the current program and function, " +
            "use this information to provide more targeted and helpful responses."
        );
        messages.add(systemMessage);
        
        // Add chat history and new prompt
        if (chatHistory != null && !chatHistory.isEmpty()) {
            // In a real implementation, parse chat history and add to messages
            // This is a simplified version
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
        
        // Add system message with instructions to use the context
        JsonObject systemMessage = new JsonObject();
        systemMessage.addProperty("role", "system");
        systemMessage.addProperty("content", 
            "You are a helpful reverse engineering assistant in Ghidra. " +
            "When provided with context information about the current program and function, " +
            "use this information to provide more targeted and helpful responses."
        );
        messages.add(systemMessage);
        
        // Add user prompt with context
        JsonObject userMessage = new JsonObject();
        userMessage.addProperty("role", "user");
        
        // Combine context and prompt for Claude
        String promptWithContext = contextInfo + "\n\n" + prompt;
        userMessage.addProperty("content", promptWithContext);
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
    
    private static void callGoogleWithContext(String model, String apiKey, String prompt, String contextInfo,
                                           String chatHistory, CompletableFuture<String> future) {
        JsonObject requestBody = new JsonObject();
        
        JsonArray contents = new JsonArray();
        
        // Add system message
        JsonObject systemMessage = new JsonObject();
        systemMessage.addProperty("role", "system");
        
        JsonArray systemParts = new JsonArray();
        JsonObject systemTextObj = new JsonObject();
        systemTextObj.addProperty("text", 
            "You are a helpful reverse engineering assistant in Ghidra. " +
            "When provided with context information about the current program and function, " +
            "use this information to provide more targeted and helpful responses."
        );
        systemParts.add(systemTextObj);
        
        systemMessage.add("parts", systemParts);
        contents.add(systemMessage);
        
        // Add context as separate message
        if (contextInfo != null && !contextInfo.isEmpty()) {
            JsonObject contextMessage = new JsonObject();
            contextMessage.addProperty("role", "user");
            
            JsonArray contextParts = new JsonArray();
            JsonObject contextTextObj = new JsonObject();
            contextTextObj.addProperty("text", "Current context: " + contextInfo);
            contextParts.add(contextTextObj);
            
            contextMessage.add("parts", contextParts);
            contents.add(contextMessage);
        }
        
        // Add user prompt
        JsonObject userMessage = new JsonObject();
        userMessage.addProperty("role", "user");
        
        JsonArray userParts = new JsonArray();
        JsonObject userTextObj = new JsonObject();
        userTextObj.addProperty("text", prompt);
        userParts.add(userTextObj);
        
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
} 
