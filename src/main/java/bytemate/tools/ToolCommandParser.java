package bytemate.tools;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.concurrent.CompletableFuture;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.framework.plugintool.PluginTool;
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
    
    private static final Pattern FIND_REFERENCES_PATTERN = 
        Pattern.compile("find\\s+(?:all\\s+)?references\\s+(?:to\\s+)?(?:function\\s+)?(?:[\"`']([^\"`']*?)[\"`']|([\\w_]+))", 
                       Pattern.CASE_INSENSITIVE);
                       
    private static final Pattern SEARCH_FUNCTIONS_PATTERN =
        Pattern.compile("search\\s+(?:for\\s+)?functions?\\s+(?:with\\s+name\\s+)?[\"`']([^\"`']*?)[\"`']", 
                       Pattern.CASE_INSENSITIVE);
                       
    private static final Pattern GO_TO_ADDRESS_PATTERN =
        Pattern.compile("(?:go|jump|navigate)\\s+to\\s+address\\s+[\"`']?([0-9a-fA-Fx]+)[\"`']?", 
                       Pattern.CASE_INSENSITIVE);
                       
    // New patterns for additional tools
    private static final Pattern RENAME_VARIABLE_PATTERN = 
        Pattern.compile("rename\\s+variable\\s+[\"`']([^\"`']*?)[\"`']\\s+to\\s+[\"`']([^\"`']*?)[\"`']", Pattern.CASE_INSENSITIVE);
        
    private static final Pattern SEARCH_VARIABLES_PATTERN =
        Pattern.compile("search\\s+(?:for\\s+)?variables?\\s+(?:with\\s+name\\s+)?[\"`']([^\"`']*?)[\"`']", 
                       Pattern.CASE_INSENSITIVE);
                       
    private static final Pattern FIND_VAR_REFERENCES_PATTERN = 
        Pattern.compile("find\\s+(?:all\\s+)?references\\s+(?:to\\s+)?variable\\s+[\"`']([^\"`']*?)[\"`']", 
                       Pattern.CASE_INSENSITIVE);
                       
    private static final Pattern APPLY_DATA_TYPE_PATTERN =
        Pattern.compile("apply\\s+(?:data\\s+)?type\\s+[\"`']([^\"`']*?)[\"`']\\s+to\\s+(?:variable\\s+)?[\"`']([^\"`']*?)[\"`']", 
                       Pattern.CASE_INSENSITIVE);
                       
    private static final Pattern CREATE_STRUCTURE_PATTERN =
        Pattern.compile("create\\s+structure\\s+[\"`']([^\"`']*?)[\"`']", Pattern.CASE_INSENSITIVE);
                       
    private static final Pattern MODIFY_STRUCTURE_PATTERN =
        Pattern.compile("(?:modify|edit)\\s+structure\\s+[\"`']([^\"`']*?)[\"`']\\s+add\\s+field\\s+[\"`']([^\"`']*?)[\"`']\\s+of\\s+type\\s+[\"`']([^\"`']*?)[\"`']", 
                       Pattern.CASE_INSENSITIVE);
    
    // Additional tools - Function signatures
    private static final Pattern MODIFY_FUNCTION_SIGNATURE_PATTERN =
        Pattern.compile("(?:modify|edit|update)\\s+function\\s+signature\\s+(?:to\\s+)?[\"`']([^\"`']*?)[\"`']", 
                       Pattern.CASE_INSENSITIVE);
                       
    // Map variable to structure field
    private static final Pattern MAP_VARIABLE_TO_STRUCTURE_PATTERN =
        Pattern.compile("map\\s+variable\\s+[\"`']([^\"`']*?)[\"`']\\s+to\\s+structure\\s+[\"`']([^\"`']*?)[\"`'](?:\\.[\"`']([^\"`']*?)[\"`'])?", 
                       Pattern.CASE_INSENSITIVE);
    
    // Identify common algorithms
    private static final Pattern IDENTIFY_ALGORITHM_PATTERN =
        Pattern.compile("identify\\s+(?:algorithm|pattern)(?:\\s+in)?(?:\\s+function\\s+[\"`']([^\"`']*?)[\"`'])?", 
                       Pattern.CASE_INSENSITIVE);
    
    // Find similar code patterns
    private static final Pattern FIND_SIMILAR_CODE_PATTERN =
        Pattern.compile("find\\s+similar\\s+(?:code|functions)\\s+(?:to)?(?:\\s+function\\s+[\"`']([^\"`']*?)[\"`'])?", 
                       Pattern.CASE_INSENSITIVE);
    
    // Generate script
    private static final Pattern GENERATE_SCRIPT_PATTERN =
        Pattern.compile("generate\\s+(python|java|ghidra)\\s+script\\s+(?:to\\s+)?[\"`']([^\"`']*?)[\"`']", 
                       Pattern.CASE_INSENSITIVE);
    
    // Generate function documentation
    private static final Pattern GENERATE_DOCUMENTATION_PATTERN =
        Pattern.compile("generate\\s+documentation\\s+(?:for\\s+)?(?:function\\s+)?(?:[\"`']([^\"`']*?)[\"`'])?", 
                       Pattern.CASE_INSENSITIVE);
    
    // Analyze data flow
    private static final Pattern ANALYZE_DATA_FLOW_PATTERN =
        Pattern.compile("analyze\\s+data\\s+flow\\s+(?:for\\s+)?(?:variable\\s+[\"`']([^\"`']*?)[\"`'])?", 
                       Pattern.CASE_INSENSITIVE);
    
    // Detect vulnerabilities
    private static final Pattern DETECT_VULNERABILITIES_PATTERN =
        Pattern.compile("(?:detect|find)\\s+(?:potential\\s+)?vulnerabilities(?:\\s+in)?(?:\\s+function\\s+[\"`']([^\"`']*?)[\"`'])?", 
                       Pattern.CASE_INSENSITIVE);
    
    // Identify VTable
    private static final Pattern IDENTIFY_VTABLE_PATTERN =
        Pattern.compile("identify\\s+(?:vtable|class\\s+hierarchy)(?:\\s+at\\s+address\\s+[\"`']?([0-9a-fA-Fx]+)[\"`']?)?", 
                       Pattern.CASE_INSENSITIVE);

    /**
     * Parse the LLM response and execute any tool commands found.
     * 
     * @param response The LLM's response text
     * @param program The current Ghidra program
     * @param currentFunction The current function in focus
     * @param tool The Ghidra plugin tool (needed for some commands)
     * @return A CompletableFuture containing the result of the tool execution, or null if no tools were executed
     */
    public static CompletableFuture<String> parseAndExecuteCommands(String response, Program program, 
                                                                  Function currentFunction, PluginTool tool) {
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
        
        // Check for find references command
        Matcher refMatcher = FIND_REFERENCES_PATTERN.matcher(response);
        if (refMatcher.find()) {
            String functionName = refMatcher.group(1) != null ? refMatcher.group(1) : refMatcher.group(2);
            Msg.info(ToolCommandParser.class, "Detected find references command for: " + functionName);
            
            // If no specific function is mentioned, use the current function
            if (functionName == null || functionName.isEmpty() || functionName.equalsIgnoreCase("current")) {
                if (currentFunction != null) {
                    return GhidraToolsService.findCrossReferences(program, currentFunction, tool);
                } else {
                    return CompletableFuture.completedFuture("No function is currently selected to find references to");
                }
            } else {
                // Find the function by name and then find references
                return GhidraToolsService.findFunctionAndReferences(program, functionName, tool);
            }
        }
        
        // Check for search functions command
        Matcher searchMatcher = SEARCH_FUNCTIONS_PATTERN.matcher(response);
        if (searchMatcher.find()) {
            String namePattern = searchMatcher.group(1);
            Msg.info(ToolCommandParser.class, "Detected search functions command with pattern: " + namePattern);
            return GhidraToolsService.searchFunctions(program, namePattern);
        }
        
        // Check for go to address command
        Matcher goToMatcher = GO_TO_ADDRESS_PATTERN.matcher(response);
        if (goToMatcher.find()) {
            String address = goToMatcher.group(1);
            Msg.info(ToolCommandParser.class, "Detected go to address command with address: " + address);
            if (tool != null) {
                return GhidraToolsService.goToAddress(program, address, tool);
            } else {
                return CompletableFuture.completedFuture("Cannot navigate to address - plugin tool is not available");
            }
        }
        
        // Check for rename variable command
        Matcher renameVarMatcher = RENAME_VARIABLE_PATTERN.matcher(response);
        if (renameVarMatcher.find()) {
            String varName = renameVarMatcher.group(1);
            String newName = renameVarMatcher.group(2);
            Msg.info(ToolCommandParser.class, "Detected rename variable command. Variable: " + varName + ", New name: " + newName);
            return GhidraToolsService.renameVariable(program, currentFunction, varName, newName);
        }
        
        // Check for search variables command
        Matcher searchVarMatcher = SEARCH_VARIABLES_PATTERN.matcher(response);
        if (searchVarMatcher.find()) {
            String namePattern = searchVarMatcher.group(1);
            Msg.info(ToolCommandParser.class, "Detected search variables command with pattern: " + namePattern);
            return GhidraToolsService.searchVariables(program, currentFunction, namePattern);
        }
        
        // Check for find variable references command
        Matcher findVarRefMatcher = FIND_VAR_REFERENCES_PATTERN.matcher(response);
        if (findVarRefMatcher.find()) {
            String varName = findVarRefMatcher.group(1);
            Msg.info(ToolCommandParser.class, "Detected find variable references command for variable: " + varName);
            return GhidraToolsService.findVariableCrossReferences(program, currentFunction, varName, tool);
        }
        
        // Check for apply data type command
        Matcher applyTypeMatcher = APPLY_DATA_TYPE_PATTERN.matcher(response);
        if (applyTypeMatcher.find()) {
            String dataType = applyTypeMatcher.group(1);
            String varName = applyTypeMatcher.group(2);
            Msg.info(ToolCommandParser.class, "Detected apply data type command. Type: " + dataType + ", Variable: " + varName);
            return GhidraToolsService.applyDataType(program, currentFunction, varName, dataType);
        }
        
        // Check for create structure command
        Matcher createStructMatcher = CREATE_STRUCTURE_PATTERN.matcher(response);
        if (createStructMatcher.find()) {
            String structName = createStructMatcher.group(1);
            Msg.info(ToolCommandParser.class, "Detected create structure command. Name: " + structName);
            return GhidraToolsService.createStructure(program, structName);
        }
        
        // Check for modify structure command
        Matcher modifyStructMatcher = MODIFY_STRUCTURE_PATTERN.matcher(response);
        if (modifyStructMatcher.find()) {
            String structName = modifyStructMatcher.group(1);
            String fieldName = modifyStructMatcher.group(2);
            String fieldType = modifyStructMatcher.group(3);
            Msg.info(ToolCommandParser.class, "Detected modify structure command. Structure: " + structName + 
                     ", Field: " + fieldName + ", Type: " + fieldType);
            return GhidraToolsService.modifyStructure(program, structName, fieldName, fieldType);
        }
        
        // Check for modify function signature command
        Matcher modifyFuncSigMatcher = MODIFY_FUNCTION_SIGNATURE_PATTERN.matcher(response);
        if (modifyFuncSigMatcher.find()) {
            String signature = modifyFuncSigMatcher.group(1);
            Msg.info(ToolCommandParser.class, "Detected modify function signature command. Signature: " + signature);
            return GhidraToolsService.modifyFunctionSignature(program, currentFunction, signature);
        }
        
        // Check for map variable to structure command
        Matcher mapVarStructMatcher = MAP_VARIABLE_TO_STRUCTURE_PATTERN.matcher(response);
        if (mapVarStructMatcher.find()) {
            String varName = mapVarStructMatcher.group(1);
            String structName = mapVarStructMatcher.group(2);
            String fieldName = mapVarStructMatcher.group(3); // May be null
            Msg.info(ToolCommandParser.class, "Detected map variable to structure command. Var: " + varName + 
                     ", Struct: " + structName + (fieldName != null ? ", Field: " + fieldName : ""));
            return GhidraToolsService.mapVariableToStructure(program, currentFunction, varName, structName, fieldName);
        }
        
        // Check for identify algorithm command
        Matcher identifyAlgoMatcher = IDENTIFY_ALGORITHM_PATTERN.matcher(response);
        if (identifyAlgoMatcher.find()) {
            String functionName = identifyAlgoMatcher.group(1); // May be null
            Msg.info(ToolCommandParser.class, "Detected identify algorithm command" + 
                     (functionName != null ? " for function: " + functionName : ""));
            Function targetFunction = functionName != null ? null : currentFunction; // For now, only support current function
            return GhidraToolsService.identifyAlgorithm(program, targetFunction);
        }
        
        // Check for find similar code command
        Matcher findSimilarMatcher = FIND_SIMILAR_CODE_PATTERN.matcher(response);
        if (findSimilarMatcher.find()) {
            String functionName = findSimilarMatcher.group(1); // May be null
            Msg.info(ToolCommandParser.class, "Detected find similar code command" + 
                     (functionName != null ? " for function: " + functionName : ""));
            Function targetFunction = functionName != null ? null : currentFunction; // For now, only support current function
            return GhidraToolsService.findSimilarCode(program, targetFunction);
        }
        
        // Check for generate script command
        Matcher generateScriptMatcher = GENERATE_SCRIPT_PATTERN.matcher(response);
        if (generateScriptMatcher.find()) {
            String scriptLang = generateScriptMatcher.group(1);
            String scriptPurpose = generateScriptMatcher.group(2);
            Msg.info(ToolCommandParser.class, "Detected generate script command. Language: " + scriptLang + 
                     ", Purpose: " + scriptPurpose);
            return GhidraToolsService.generateScript(program, currentFunction, scriptLang, scriptPurpose);
        }
        
        // Check for generate documentation command
        Matcher genDocMatcher = GENERATE_DOCUMENTATION_PATTERN.matcher(response);
        if (genDocMatcher.find()) {
            String functionName = genDocMatcher.group(1); // May be null
            Msg.info(ToolCommandParser.class, "Detected generate documentation command" + 
                     (functionName != null ? " for function: " + functionName : ""));
            Function targetFunction = functionName != null ? null : currentFunction; // For now, only support current function
            return GhidraToolsService.generateDocumentation(program, targetFunction);
        }
        
        // Check for analyze data flow command
        Matcher dataFlowMatcher = ANALYZE_DATA_FLOW_PATTERN.matcher(response);
        if (dataFlowMatcher.find()) {
            String varName = dataFlowMatcher.group(1); // May be null
            Msg.info(ToolCommandParser.class, "Detected analyze data flow command" + 
                     (varName != null ? " for variable: " + varName : ""));
            return GhidraToolsService.analyzeDataFlow(program, currentFunction, varName);
        }
        
        // Check for detect vulnerabilities command
        Matcher vulnMatcher = DETECT_VULNERABILITIES_PATTERN.matcher(response);
        if (vulnMatcher.find()) {
            String functionName = vulnMatcher.group(1); // May be null
            Msg.info(ToolCommandParser.class, "Detected detect vulnerabilities command" + 
                     (functionName != null ? " for function: " + functionName : ""));
            Function targetFunction = functionName != null ? null : currentFunction; // For now, only support current function
            return GhidraToolsService.detectVulnerabilities(program, targetFunction);
        }
        
        // Check for identify vtable command
        Matcher vtableMatcher = IDENTIFY_VTABLE_PATTERN.matcher(response);
        if (vtableMatcher.find()) {
            String address = vtableMatcher.group(1); // May be null
            Msg.info(ToolCommandParser.class, "Detected identify vtable command" + 
                     (address != null ? " at address: " + address : ""));
            return GhidraToolsService.identifyVTable(program, address);
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
               ADD_COMMENT_PATTERN.matcher(response).find() ||
               FIND_REFERENCES_PATTERN.matcher(response).find() ||
               SEARCH_FUNCTIONS_PATTERN.matcher(response).find() ||
               GO_TO_ADDRESS_PATTERN.matcher(response).find() ||
               RENAME_VARIABLE_PATTERN.matcher(response).find() ||
               SEARCH_VARIABLES_PATTERN.matcher(response).find() ||
               FIND_VAR_REFERENCES_PATTERN.matcher(response).find() ||
               APPLY_DATA_TYPE_PATTERN.matcher(response).find() ||
               CREATE_STRUCTURE_PATTERN.matcher(response).find() ||
               MODIFY_STRUCTURE_PATTERN.matcher(response).find() ||
               MODIFY_FUNCTION_SIGNATURE_PATTERN.matcher(response).find() ||
               MAP_VARIABLE_TO_STRUCTURE_PATTERN.matcher(response).find() ||
               IDENTIFY_ALGORITHM_PATTERN.matcher(response).find() ||
               FIND_SIMILAR_CODE_PATTERN.matcher(response).find() ||
               GENERATE_SCRIPT_PATTERN.matcher(response).find() ||
               GENERATE_DOCUMENTATION_PATTERN.matcher(response).find() ||
               ANALYZE_DATA_FLOW_PATTERN.matcher(response).find() ||
               DETECT_VULNERABILITIES_PATTERN.matcher(response).find() ||
               IDENTIFY_VTABLE_PATTERN.matcher(response).find();
    }
} 
