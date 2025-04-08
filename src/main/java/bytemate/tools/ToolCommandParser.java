package bytemate.tools;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.concurrent.CompletableFuture;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Parser for detecting and executing tool commands in LLM responses.
 */
public class ToolCommandParser {
    
    // Regular expressions to match tool commands - Updated to support single quotes, double quotes, and backticks
    private static final Pattern RENAME_FUNCTION_PATTERN = 
        Pattern.compile("rename\\s+function\\s+to\\s+[\"`']([^\"`']*?)[\"`']", Pattern.CASE_INSENSITIVE);
    
    private static final Pattern ADD_COMMENT_PATTERN = 
        Pattern.compile("add\\s+(pre|eol|post|plate)\\s+comment\\s+[\"`']([^\"`']*?)[\"`']", Pattern.CASE_INSENSITIVE);
    
    /**
     * Parse the LLM response and execute any tool commands found.
     * 
     * @param response The LLM's response text
     * @param program The current Ghidra program
     * @param currentFunction The current function in focus
     * @return A CompletableFuture containing the result of the tool execution, or null if no tools were executed
     */
    public static CompletableFuture<String> parseAndExecuteCommands(String response, Program program, Function currentFunction) {
        if (response == null || response.isEmpty()) {
            return CompletableFuture.completedFuture("No response to parse");
        }
        
        Msg.info(ToolCommandParser.class, "Parsing LLM response for tool commands: " + response);
        
        // Check for rename function command
        Matcher renameMatcher = RENAME_FUNCTION_PATTERN.matcher(response);
        if (renameMatcher.find()) {
            String newName = renameMatcher.group(1);
            Msg.info(ToolCommandParser.class, "Detected rename function command. New name: " + newName);
            return GhidraToolsService.renameFunction(program, currentFunction, newName);
        }
        
        // Check for add comment command
        Matcher commentMatcher = ADD_COMMENT_PATTERN.matcher(response);
        if (commentMatcher.find()) {
            String commentType = commentMatcher.group(1);
            String comment = commentMatcher.group(2);
            Msg.info(ToolCommandParser.class, "Detected add comment command. Type: " + commentType + ", Comment: " + comment);
            return GhidraToolsService.addFunctionComment(program, currentFunction, commentType, comment);
        }
        
        // No tool commands found
        Msg.info(ToolCommandParser.class, "No tool commands detected in LLM response");
        return CompletableFuture.completedFuture("No tool commands found in the response");
    }
    
    /**
     * Check if the response contains any tool commands.
     * 
     * @param response The LLM's response text
     * @return True if the response contains tool commands, false otherwise
     */
    public static boolean containsToolCommands(String response) {
        if (response == null || response.isEmpty()) {
            return false;
        }
        
        return RENAME_FUNCTION_PATTERN.matcher(response).find() ||
               ADD_COMMENT_PATTERN.matcher(response).find();
    }
} 
