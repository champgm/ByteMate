package bytemate.tools;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.util.Msg;

/**
 * Defines the commands that can be requested by the LLM.
 * Each command is processed and mapped to the appropriate GhidraToolsService method.
 */
public class ToolCommands {
    
    // Command patterns - Updated to support single quotes, double quotes, and backticks
    private static final String RENAME_FUNCTION_PATTERN = "rename\\s+function\\s+(?:to\\s+)?[\"`']([^\"`']+)[\"`']";
    private static final String ADD_COMMENT_PATTERN = "add\\s+(pre|eol|post|plate)\\s+comment\\s+[\"`']([^\"`']+)[\"`']";
    private static final String FIND_REFERENCES_PATTERN = "find\\s+(?:all\\s+)?references\\s+(?:to\\s+)?([^\\s]+)";
    
    /**
     * Process a command from the LLM.
     * 
     * @param command The command text
     * @return A map containing the command type and parameters
     */
    public static Map<String, Object> processCommand(String command) {
        Map<String, Object> result = new HashMap<>();
        
        Msg.debug(ToolCommands.class, "Processing command: " + command);
        
        // Check for rename function command
        Pattern renamePattern = Pattern.compile(RENAME_FUNCTION_PATTERN, Pattern.CASE_INSENSITIVE);
        Matcher renameMatcher = renamePattern.matcher(command);
        if (renameMatcher.find()) {
            String newName = renameMatcher.group(1);
            Msg.info(ToolCommands.class, "Detected RENAME_FUNCTION command with newName: " + newName);
            result.put("type", "RENAME_FUNCTION");
            result.put("newName", newName);
            return result;
        }
        
        // Check for add comment command
        Pattern commentPattern = Pattern.compile(ADD_COMMENT_PATTERN, Pattern.CASE_INSENSITIVE);
        Matcher commentMatcher = commentPattern.matcher(command);
        if (commentMatcher.find()) {
            String commentType = commentMatcher.group(1).toUpperCase();
            String comment = commentMatcher.group(2);
            Msg.info(ToolCommands.class, "Detected ADD_COMMENT command with type: " + commentType + ", comment: " + comment);
            result.put("type", "ADD_COMMENT");
            result.put("commentType", commentType);
            result.put("comment", comment);
            return result;
        }
        
        // Check for find references command
        Pattern referencesPattern = Pattern.compile(FIND_REFERENCES_PATTERN, Pattern.CASE_INSENSITIVE);
        Matcher referencesMatcher = referencesPattern.matcher(command);
        if (referencesMatcher.find()) {
            String symbol = referencesMatcher.group(1);
            Msg.info(ToolCommands.class, "Detected FIND_REFERENCES command with symbol: " + symbol);
            result.put("type", "FIND_REFERENCES");
            result.put("symbol", symbol);
            return result;
        }
        
        // If no pattern matches, return unknown command
        Msg.warn(ToolCommands.class, "No matching command pattern found for: " + command);
        result.put("type", "UNKNOWN");
        result.put("original", command);
        return result;
    }
    
    /**
     * Determines if a message from the LLM contains a command.
     * 
     * @param message The message to check
     * @return true if the message contains a command, false otherwise
     */
    public static boolean containsCommand(String message) {
        if (message == null || message.isEmpty()) {
            Msg.debug(ToolCommands.class, "Message is null or empty, no commands");
            return false;
        }
        
        // Check if there are any potential commands in the message
        boolean hasCommand = message.toLowerCase().matches(".*rename\\s+function\\s+to.*") ||
                             message.toLowerCase().matches(".*add\\s+(pre|eol|post|plate)\\s+comment.*") ||
                             message.toLowerCase().matches(".*find\\s+references.*");
        
        Msg.debug(ToolCommands.class, "Message " + (hasCommand ? "contains" : "does not contain") + " command patterns");
        
        // More detailed debugging information
        if (hasCommand) {
            if (message.toLowerCase().matches(".*rename\\s+function\\s+to.*")) {
                Msg.debug(ToolCommands.class, "Found 'rename function' pattern");
            }
            if (message.toLowerCase().matches(".*add\\s+(pre|eol|post|plate)\\s+comment.*")) {
                Msg.debug(ToolCommands.class, "Found 'add comment' pattern");
            }
            if (message.toLowerCase().matches(".*find\\s+references.*")) {
                Msg.debug(ToolCommands.class, "Found 'find references' pattern");
            }
        }
        
        return hasCommand;
    }
    
    /**
     * Extracts commands from a message.
     * 
     * @param message The message to extract commands from
     * @return An array of command strings
     */
    public static String[] extractCommands(String message) {
        if (!containsCommand(message)) {
            Msg.debug(ToolCommands.class, "No commands to extract");
            return new String[0];
        }
       
        Msg.info(ToolCommands.class, "Extracting commands from message");
        
        // Split message into lines
        String[] lines = message.split("\\n");
        Msg.debug(ToolCommands.class, "Message contains " + lines.length + " lines");
        
        // Filter lines that contain commands
        String[] commandLines = java.util.Arrays.stream(lines)
            .filter(line -> {
                boolean isCommand = line.toLowerCase().matches(".*rename\\s+function\\s+to.*") ||
                                   line.toLowerCase().matches(".*add\\s+(pre|eol|post|plate)\\s+comment.*") ||
                                   line.toLowerCase().matches(".*find\\s+references.*");
                
                if (isCommand) {
                    Msg.debug(ToolCommands.class, "Found command in line: " + line);
                }
                return isCommand;
            })
            .toArray(String[]::new);
        
        Msg.info(ToolCommands.class, "Extracted " + commandLines.length + " command lines");
        return commandLines;
    }
} 
