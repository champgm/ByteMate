package bytemate;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.prefs.Preferences;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

/**
 * Manages chat history persistence and formatting for API calls.
 */
public class ChatHistoryManager {
    
    private static final Gson gson = new GsonBuilder().setPrettyPrinting().create();
    private static final Preferences prefs = Preferences.userNodeForPackage(ChatHistoryManager.class);
    
    /**
     * Saves chat history to a file.
     * 
     * @param filename The filename to save to
     * @param history The chat history to save
     */
    public static void saveHistory(String filename, List<ChatMessage> history) {
        try {
            String json = gson.toJson(history);
            File file = new File(filename);
            file.getParentFile().mkdirs();
            try (FileWriter writer = new FileWriter(file)) {
                writer.write(json);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    /**
     * Loads chat history from a file.
     * 
     * @param filename The filename to load from
     * @return The loaded chat history, or an empty list if the file doesn't exist
     */
    public static List<ChatMessage> loadHistory(String filename) {
        List<ChatMessage> history = new ArrayList<>();
        
        try {
            File file = new File(filename);
            if (file.exists()) {
                try (FileReader reader = new FileReader(file)) {
                    history = gson.fromJson(reader, new TypeToken<List<ChatMessage>>() {}.getType());
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        
        return history;
    }
    
    /**
     * Formats chat history for the OpenAI API.
     * 
     * @param history The chat history to format
     * @return JSON string for the OpenAI API
     */
    public static String formatForOpenAI(List<ChatMessage> history) {
        StringBuilder sb = new StringBuilder("[");
        
        // Add system message
        sb.append("{\"role\":\"system\",\"content\":\"You are a helpful reverse engineering assistant in Ghidra.\"},");
        
        // Add conversation history
        for (ChatMessage message : history) {
            if ("User".equals(message.getSender())) {
                sb.append("{\"role\":\"user\",\"content\":\"").append(escapeJson(message.getMessage())).append("\"},");
            } else if ("Assistant".equals(message.getSender())) {
                sb.append("{\"role\":\"assistant\",\"content\":\"").append(escapeJson(message.getMessage())).append("\"},");
            }
        }
        
        // Remove trailing comma and close the array
        if (sb.charAt(sb.length() - 1) == ',') {
            sb.setLength(sb.length() - 1);
        }
        sb.append("]");
        
        return sb.toString();
    }
    
    /**
     * Formats chat history for the Claude API.
     * 
     * @param history The chat history to format
     * @return JSON string for the Claude API
     */
    public static String formatForClaude(List<ChatMessage> history) {
        StringBuilder sb = new StringBuilder("[");
        
        // Add system message
        sb.append("{\"role\":\"system\",\"content\":\"You are a helpful reverse engineering assistant in Ghidra.\"},");
        
        // Add conversation history
        for (ChatMessage message : history) {
            if ("User".equals(message.getSender())) {
                sb.append("{\"role\":\"user\",\"content\":\"").append(escapeJson(message.getMessage())).append("\"},");
            } else if ("Assistant".equals(message.getSender())) {
                sb.append("{\"role\":\"assistant\",\"content\":\"").append(escapeJson(message.getMessage())).append("\"},");
            }
        }
        
        // Remove trailing comma and close the array
        if (sb.charAt(sb.length() - 1) == ',') {
            sb.setLength(sb.length() - 1);
        }
        sb.append("]");
        
        return sb.toString();
    }
    
    /**
     * Formats chat history for the Google API.
     * 
     * @param history The chat history to format
     * @return JSON string for the Google API
     */
    public static String formatForGoogle(List<ChatMessage> history) {
        StringBuilder sb = new StringBuilder("[");
        
        // Add conversation history
        for (ChatMessage message : history) {
            if ("User".equals(message.getSender())) {
                sb.append("{\"role\":\"user\",\"parts\":[{\"text\":\"").append(escapeJson(message.getMessage())).append("\"}]},");
            } else if ("Assistant".equals(message.getSender())) {
                sb.append("{\"role\":\"model\",\"parts\":[{\"text\":\"").append(escapeJson(message.getMessage())).append("\"}]},");
            }
        }
        
        // Remove trailing comma and close the array
        if (sb.charAt(sb.length() - 1) == ',') {
            sb.setLength(sb.length() - 1);
        }
        sb.append("]");
        
        return sb.toString();
    }
    
    /**
     * Escapes special characters for JSON strings.
     * 
     * @param input The string to escape
     * @return The escaped string
     */
    private static String escapeJson(String input) {
        return input.replace("\\", "\\\\")
                   .replace("\"", "\\\"")
                   .replace("\n", "\\n")
                   .replace("\r", "\\r")
                   .replace("\t", "\\t");
    }
    
    /**
     * Saves API keys to user preferences.
     * 
     * @param provider The LLM provider
     * @param apiKey The API key to save
     */
    public static void saveApiKey(String provider, String apiKey) {
        prefs.put("apikey_" + provider, apiKey);
    }
    
    /**
     * Loads API key from user preferences.
     * 
     * @param provider The LLM provider
     * @return The API key, or an empty string if not found
     */
    public static String loadApiKey(String provider) {
        return prefs.get("apikey_" + provider, "");
    }
} 
