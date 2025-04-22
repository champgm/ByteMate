package bytemate.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableUtilities;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

/**
 * Service class that provides functionality for Ghidra API operations
 * requested by the LLM assistant.
 */
public class GhidraToolsService {
    
    /**
     * Renames a function with confirmation dialog.
     * 
     * @param program The current program
     * @param function The function to rename
     * @param newName The new name for the function
     * @return A CompletableFuture containing the result message
     */
    public static CompletableFuture<String> renameFunction(Program program, Function function, String newName) {
        CompletableFuture<String> future = new CompletableFuture<>();
        
        if (program == null || function == null) {
            Msg.error(GhidraToolsService.class, "Program or function is null");
            future.complete("Error: No program or function selected");
            return future;
        }
        
        Msg.info(GhidraToolsService.class, "Preparing to rename function: " + function.getName() + " to: " + newName);
        
        SwingUtilities.invokeLater(() -> {
            // Show confirmation dialog
            int result = JOptionPane.showConfirmDialog(
                null,
                "Rename function '" + function.getName() + "' to '" + newName + "'?",
                "Confirm Rename",
                JOptionPane.YES_NO_OPTION
            );
            
            Msg.info(GhidraToolsService.class, "Rename dialog result: " + (result == JOptionPane.YES_OPTION ? "YES" : "NO"));
            
            if (result == JOptionPane.YES_OPTION) {
                int transactionID = program.startTransaction("Rename Function");
                boolean success = false;
                
                try {
                    Msg.info(GhidraToolsService.class, "Starting function rename transaction");
                    function.setName(newName, SourceType.USER_DEFINED);
                    Msg.info(GhidraToolsService.class, "Function renamed successfully");
                    success = true;
                } catch (DuplicateNameException e) {
                    Msg.error(GhidraToolsService.class, "Function name already exists: " + e.getMessage());
                    future.complete("Error: Function name already exists: " + newName);
                } catch (InvalidInputException e) {
                    Msg.error(GhidraToolsService.class, "Invalid function name: " + e.getMessage());
                    future.complete("Error: Invalid function name: " + newName);
                } finally {
                    Msg.info(GhidraToolsService.class, "Ending function rename transaction with success=" + success);
                    program.endTransaction(transactionID, success);
                    
                    if (success) {
                        future.complete("Successfully renamed function to: " + newName);
                    }
                }
            } else {
                Msg.info(GhidraToolsService.class, "Function rename cancelled by user");
                future.complete("Function rename cancelled by user");
            }
        });
        
        return future;
    }
    
    /**
     * Adds a comment to a function with confirmation dialog.
     * 
     * @param program The current program
     * @param function The function to comment
     * @param commentType The type of comment (PRE, EOL, POST, PLATE)
     * @param comment The comment text
     * @return A CompletableFuture containing the result message
     */
    public static CompletableFuture<String> addFunctionComment(Program program, Function function, 
                                                              String commentType, String comment) {
        CompletableFuture<String> future = new CompletableFuture<>();
        
        if (program == null || function == null) {
            Msg.error(GhidraToolsService.class, "Program or function is null");
            future.complete("Error: No program or function selected");
            return future;
        }
        
        Msg.info(GhidraToolsService.class, String.format(
            "Preparing to add %s comment to function: %s - Comment: %s",
            commentType, function.getName(), comment
        ));
        
        SwingUtilities.invokeLater(() -> {
            // Show confirmation dialog
            int result = JOptionPane.showConfirmDialog(
                null,
                "Add " + commentType + " comment to function '" + function.getName() + "'?",
                "Confirm Comment",
                JOptionPane.YES_NO_OPTION
            );
            
            Msg.info(GhidraToolsService.class, "Comment dialog result: " + (result == JOptionPane.YES_OPTION ? "YES" : "NO"));
            
            if (result == JOptionPane.YES_OPTION) {
                int transactionID = program.startTransaction("Add Function Comment");
                boolean success = false;
                
                try {
                    Msg.info(GhidraToolsService.class, "Starting comment transaction");
                    // Fix: Use Listing service to set PRE/EOL/POST comments at the function entry point
                    // function.setComment only handles PLATE comments.
                    Listing listing = program.getListing();
                    Address entryPoint = function.getEntryPoint();
                    int ghidraCommentType = CodeUnit.PLATE_COMMENT; // Default to PLATE
                    
                    switch (commentType.toUpperCase()) {
                        case "PRE":
                            ghidraCommentType = CodeUnit.PRE_COMMENT;
                            break;
                        case "EOL":
                            ghidraCommentType = CodeUnit.EOL_COMMENT;
                            break;
                        case "POST":
                            ghidraCommentType = CodeUnit.POST_COMMENT;
                            break;
                        case "PLATE":
                            ghidraCommentType = CodeUnit.PLATE_COMMENT;
                            break;
                        default:
                            Msg.warn(GhidraToolsService.class, "Invalid comment type specified: " + commentType + ". Defaulting to PLATE.");
                            break;
                    }
                    
                    String existingComment = listing.getComment(ghidraCommentType, entryPoint);
                    Msg.debug(GhidraToolsService.class, "Existing comment at " + entryPoint + ": " + (existingComment == null ? "null" : existingComment));
                    
                    listing.setComment(entryPoint, ghidraCommentType, comment);
                    Msg.info(GhidraToolsService.class, "Comment added successfully using Listing service");
                    success = true;
                } catch (Exception e) {
                    Msg.error(GhidraToolsService.class, "Error setting comment: " + e.getMessage(), e);
                    future.complete("Error: Could not set comment: " + e.getMessage());
                } finally {
                    Msg.info(GhidraToolsService.class, "Ending comment transaction with success=" + success);
                    program.endTransaction(transactionID, success);
                    
                    if (success) {
                        future.complete("Successfully added " + commentType + " comment to function: " + function.getName());
                    }
                }
            } else {
                Msg.info(GhidraToolsService.class, "Comment addition cancelled by user");
                future.complete("Comment addition cancelled by user");
            }
        });
        
        return future;
    }
    
    /**
     * Adds a comment to a specific address with confirmation dialog.
     * 
     * @param program The current program
     * @param address The address to comment
     * @param commentType The type of comment (PRE, EOL, POST, PLATE)
     * @param comment The comment text
     * @return A CompletableFuture containing the result message
     */
    public static CompletableFuture<String> addAddressComment(Program program, Address address, 
                                                             String commentType, String comment) {
        CompletableFuture<String> future = new CompletableFuture<>();
        
        if (program == null || address == null) {
            Msg.error(GhidraToolsService.class, "Program or address is null");
            future.complete("Error: No program or address selected");
            return future;
        }
        
        Msg.info(GhidraToolsService.class, String.format(
            "Preparing to add %s comment to address: %s - Comment: %s",
            commentType, address.toString(), comment
        ));
        
        SwingUtilities.invokeLater(() -> {
            // Show confirmation dialog
            int result = JOptionPane.showConfirmDialog(
                null,
                "Add " + commentType + " comment to address " + address + "?",
                "Confirm Comment",
                JOptionPane.YES_NO_OPTION
            );
            
            Msg.info(GhidraToolsService.class, "Comment dialog result: " + (result == JOptionPane.YES_OPTION ? "YES" : "NO"));
            
            if (result == JOptionPane.YES_OPTION) {
                int transactionID = program.startTransaction("Add Address Comment");
                boolean success = false;
                
                try {
                    Listing listing = program.getListing();
                    CodeUnit codeUnit = listing.getCodeUnitAt(address);
                    
                    if (codeUnit != null) {
                        int commentTypeCode = CodeUnit.PLATE_COMMENT; // Default
                        
                        // Convert string comment type to CodeUnit int constant
                        switch (commentType.toUpperCase()) {
                            case "PRE":
                                commentTypeCode = CodeUnit.PRE_COMMENT;
                                break;
                            case "POST":
                                commentTypeCode = CodeUnit.POST_COMMENT;
                                break;
                            case "EOL":
                                commentTypeCode = CodeUnit.EOL_COMMENT;
                                break;
                            case "PLATE":
                                commentTypeCode = CodeUnit.PLATE_COMMENT;
                                break;
                        }
                        
                        Msg.debug(GhidraToolsService.class, "Comment type code: " + commentTypeCode);
                        String existingComment = codeUnit.getComment(commentTypeCode);
                        Msg.debug(GhidraToolsService.class, "Existing comment: " + (existingComment == null ? "null" : existingComment));
                        
                        codeUnit.setComment(commentTypeCode, comment);
                        Msg.info(GhidraToolsService.class, "Comment added successfully");
                        success = true;
                    } else {
                        Msg.error(GhidraToolsService.class, "No code unit found at address " + address);
                        future.complete("Error: No code unit found at address " + address);
                    }
                } catch (Exception e) {
                    Msg.error(GhidraToolsService.class, "Error setting comment: " + e.getMessage(), e);
                    future.complete("Error: Could not set comment: " + e.getMessage());
                } finally {
                    Msg.info(GhidraToolsService.class, "Ending comment transaction with success=" + success);
                    program.endTransaction(transactionID, success);
                    
                    if (success) {
                        future.complete("Successfully added " + commentType + " comment to address: " + address);
                    }
                }
            } else {
                Msg.info(GhidraToolsService.class, "Comment addition cancelled by user");
                future.complete("Comment addition cancelled by user");
            }
        });
        
        return future;
    }
    
    /**
     * Finds cross-references to a function.
     * 
     * @param program The current program
     * @param function The function to find references to
     * @param tool The Ghidra plugin tool
     * @return A CompletableFuture containing the result message
     */
    public static CompletableFuture<String> findCrossReferences(Program program, Function function, PluginTool tool) {
        CompletableFuture<String> future = new CompletableFuture<>();
        
        if (program == null || function == null) {
            Msg.error(GhidraToolsService.class, "Program or function is null");
            future.complete("Error: No program or function selected");
            return future;
        }
        
        Msg.info(GhidraToolsService.class, "Finding cross-references to function: " + function.getName());
        
        SwingUtilities.invokeLater(() -> {
            try {
                // Get references to the function
                ReferenceManager refManager = program.getReferenceManager();
                Address functionAddress = function.getEntryPoint();
                
                // Use iterator instead of trying to get as array
                List<Reference> references = new ArrayList<>();
                refManager.getReferencesTo(functionAddress).forEach(ref -> references.add(ref));
                
                if (references.isEmpty()) {
                    future.complete("No references found to function: " + function.getName());
                    return;
                }
                
                StringBuilder resultBuilder = new StringBuilder();
                resultBuilder.append("References to function ").append(function.getName()).append(":\n");
                
                int maxToShow = Math.min(references.size(), 10);
                for (int i = 0; i < maxToShow; i++) {
                    Reference ref = references.get(i);
                    resultBuilder.append("- From: ").append(ref.getFromAddress());
                    
                    // Try to get the function containing the reference
                    Function fromFunction = program.getListing().getFunctionContaining(ref.getFromAddress());
                    if (fromFunction != null) {
                        resultBuilder.append(" (in function ").append(fromFunction.getName()).append(")");
                    }
                    
                    resultBuilder.append("\n");
                }
                
                if (references.size() > 10) {
                    resultBuilder.append("... and ").append(references.size() - 10).append(" more references.");
                }
                
                future.complete(resultBuilder.toString());
                
            } catch (Exception e) {
                Msg.error(GhidraToolsService.class, "Error finding cross-references: " + e.getMessage(), e);
                future.complete("Error finding cross-references: " + e.getMessage());
            }
        });
        
        return future;
    }
    
    /**
     * Searches for functions by name pattern.
     * 
     * @param program The current program
     * @param namePattern The pattern to search for
     * @return A CompletableFuture containing the result message
     */
    public static CompletableFuture<String> searchFunctions(Program program, String namePattern) {
        CompletableFuture<String> future = new CompletableFuture<>();
        
        if (program == null) {
            Msg.error(GhidraToolsService.class, "Program is null");
            future.complete("Error: No program selected");
            return future;
        }
        
        Msg.info(GhidraToolsService.class, "Searching for functions matching pattern: " + namePattern);
        
        SwingUtilities.invokeLater(() -> {
            try {
                FunctionManager functionManager = program.getFunctionManager();
                List<Function> matchingFunctions = new ArrayList<>();
                
                // Convert simple wildcard pattern to regex
                String regexPattern = namePattern
                    .replace(".", "\\.")
                    .replace("*", ".*")
                    .replace("?", ".");
                
                // Get all functions and filter by name
                functionManager.getFunctions(true).forEach(function -> {
                    if (function.getName().matches(regexPattern)) {
                        matchingFunctions.add(function);
                    }
                });
                
                if (matchingFunctions.isEmpty()) {
                    future.complete("No functions found matching pattern: " + namePattern);
                    return;
                }
                
                StringBuilder resultBuilder = new StringBuilder();
                resultBuilder.append("Functions matching pattern ").append(namePattern).append(":\n");
                
                int maxToShow = Math.min(matchingFunctions.size(), 15);
                for (int i = 0; i < maxToShow; i++) {
                    Function func = matchingFunctions.get(i);
                    resultBuilder.append("- ").append(func.getName())
                               .append(" at ").append(func.getEntryPoint())
                               .append("\n");
                }
                
                if (matchingFunctions.size() > 15) {
                    resultBuilder.append("... and ").append(matchingFunctions.size() - 15).append(" more matches.");
                }
                
                future.complete(resultBuilder.toString());
                
            } catch (Exception e) {
                Msg.error(GhidraToolsService.class, "Error searching for functions: " + e.getMessage(), e);
                future.complete("Error searching for functions: " + e.getMessage());
            }
        });
        
        return future;
    }
    
    /**
     * Navigates to a specific address.
     * 
     * @param program The current program
     * @param addressString The address to navigate to as a string
     * @param tool The Ghidra plugin tool
     * @return A CompletableFuture containing the result message
     */
    public static CompletableFuture<String> goToAddress(Program program, String addressString, PluginTool tool) {
        CompletableFuture<String> future = new CompletableFuture<>();
        
        if (program == null) {
            Msg.error(GhidraToolsService.class, "Program is null");
            future.complete("Error: No program selected");
            return future;
        }
        
        Msg.info(GhidraToolsService.class, "Navigating to address: " + addressString);
        
        SwingUtilities.invokeLater(() -> {
            try {
                // Parse the address
                AddressFactory addressFactory = program.getAddressFactory();
                Address address = addressFactory.getAddress(addressString);
                
                if (address == null) {
                    future.complete("Error: Could not parse address: " + addressString);
                    return;
                }
                
                // Use GoToService to navigate to the address
                GoToService goToService = tool.getService(GoToService.class);
                if (goToService != null) {
                    // Fix: Primary logic using GoToService
                    boolean success = goToService.goTo(address);
                    if (success) {
                        future.complete("Successfully navigated to address: " + addressString);
                    } else {
                        future.complete("Failed to navigate to address: " + addressString + " (GoToService)");
                    }
                } else {
                    // Fix: Fallback logic - If GoToService is unavailable, report error.
                    // The previous fallback attempt was flawed.
                    // Navigating precisely without GoToService might be complex or impossible depending on context.
                    Msg.error(GhidraToolsService.class, "GoToService not available");
                    future.complete("Error: Could not navigate to address - GoToService not available");
                    /* // Removed flawed fallback
                    ProgramManager programManager = tool.getService(ProgramManager.class);
                    if (programManager != null) {
                        // Use goTo instead of setCurrentLocation as it doesn't exist
                        ProgramLocation location = new ProgramLocation(program, address);
                        programManager.setCurrentProgram(program);
                        boolean success = goToService.goTo(location); // Incorrect: goToService is null here
                        future.complete(success ? 
                            "Successfully navigated to address: " + addressString :
                            "Failed to navigate to address: " + addressString);
                    } else {
                        future.complete("Error: Could not navigate to address - navigation services not available");
                    }
                    */
                }
            } catch (Exception e) {
                Msg.error(GhidraToolsService.class, "Error navigating to address: " + e.getMessage(), e);
                future.complete("Error navigating to address: " + e.getMessage());
            }
        });
        
        return future;
    }
    
    /**
     * Renames a variable in the specified function with confirmation dialog.
     * 
     * @param program The current program
     * @param function The function containing the variable
     * @param varName The name of the variable to rename
     * @param newName The new name for the variable
     * @return A CompletableFuture containing the result message
     */
    public static CompletableFuture<String> renameVariable(Program program, Function function, 
                                                          String varName, String newName) {
        CompletableFuture<String> future = new CompletableFuture<>();
        
        if (program == null || function == null) {
            Msg.error(GhidraToolsService.class, "Program or function is null");
            future.complete("Error: No program or function selected");
            return future;
        }
        
        Msg.info(GhidraToolsService.class, String.format(
            "Preparing to rename variable: %s to: %s in function: %s",
            varName, newName, function.getName()
        ));
        
        SwingUtilities.invokeLater(() -> {
            // Find the variable
            Variable[] vars = function.getAllVariables();
            Variable targetVar = null;
            
            for (Variable var : vars) {
                if (var.getName().equals(varName)) {
                    targetVar = var;
                    break;
                }
            }
            
            if (targetVar == null) {
                Msg.error(GhidraToolsService.class, "Variable not found: " + varName);
                future.complete("Error: Variable not found: " + varName);
                return;
            }
            
            // Show confirmation dialog
            int result = JOptionPane.showConfirmDialog(
                null,
                "Rename variable '" + varName + "' to '" + newName + "' in function '" + function.getName() + "'?",
                "Confirm Rename",
                JOptionPane.YES_NO_OPTION
            );
            
            Msg.info(GhidraToolsService.class, "Rename dialog result: " + (result == JOptionPane.YES_OPTION ? "YES" : "NO"));
            
            if (result == JOptionPane.YES_OPTION) {
                int transactionID = program.startTransaction("Rename Variable");
                boolean success = false;
                
                try {
                    Msg.info(GhidraToolsService.class, "Starting variable rename transaction");
                    targetVar.setName(newName, SourceType.USER_DEFINED);
                    Msg.info(GhidraToolsService.class, "Variable renamed successfully");
                    success = true;
                } catch (DuplicateNameException e) {
                    Msg.error(GhidraToolsService.class, "Variable name already exists: " + e.getMessage());
                    future.complete("Error: Variable name already exists: " + newName);
                } catch (InvalidInputException e) {
                    Msg.error(GhidraToolsService.class, "Invalid variable name: " + e.getMessage());
                    future.complete("Error: Invalid variable name: " + newName);
                } finally {
                    Msg.info(GhidraToolsService.class, "Ending variable rename transaction with success=" + success);
                    program.endTransaction(transactionID, success);
                    
                    if (success) {
                        future.complete("Successfully renamed variable from '" + varName + "' to '" + newName + "' in function '" + function.getName() + "'");
                    }
                }
            } else {
                Msg.info(GhidraToolsService.class, "Variable rename cancelled by user");
                future.complete("Variable rename cancelled by user");
            }
        });
        
        return future;
    }
    
    /**
     * Searches for variables by name pattern in the specified function.
     * 
     * @param program The current program
     * @param function The function to search in (can be null to search across all functions)
     * @param namePattern The pattern to search for
     * @return A CompletableFuture containing the result message
     */
    public static CompletableFuture<String> searchVariables(Program program, Function function, 
                                                           String namePattern) {
        CompletableFuture<String> future = new CompletableFuture<>();
        
        if (program == null) {
            Msg.error(GhidraToolsService.class, "Program is null");
            future.complete("Error: No program selected");
            return future;
        }
        
        Msg.info(GhidraToolsService.class, String.format(
            "Searching for variables matching pattern: %s in function: %s",
            namePattern, function != null ? function.getName() : "all functions"
        ));
        
        SwingUtilities.invokeLater(() -> {
            try {
                // Convert simple wildcard pattern to regex
                String regexPattern = namePattern
                    .replace(".", "\\.")
                    .replace("*", ".*")
                    .replace("?", ".");
                
                StringBuilder resultBuilder = new StringBuilder();
                List<Variable> matchingVariables = new ArrayList<>();
                
                if (function != null) {
                    // Search in the specified function
                    Variable[] vars = function.getAllVariables();
                    for (Variable var : vars) {
                        if (var.getName().matches(regexPattern)) {
                            matchingVariables.add(var);
                        }
                    }
                    
                    resultBuilder.append("Variables matching '").append(namePattern)
                                .append("' in function '").append(function.getName()).append("':\n");
                } else {
                    // Search across all functions
                    FunctionManager functionManager = program.getFunctionManager();
                    functionManager.getFunctions(true).forEach(func -> {
                        Variable[] vars = func.getAllVariables();
                        for (Variable var : vars) {
                            if (var.getName().matches(regexPattern)) {
                                matchingVariables.add(var);
                            }
                        }
                    });
                    
                    resultBuilder.append("Variables matching '").append(namePattern)
                                .append("' across all functions:\n");
                }
                
                if (matchingVariables.isEmpty()) {
                    resultBuilder.append("No variables found matching the pattern.");
                    future.complete(resultBuilder.toString());
                    return;
                }
                
                // Display the results
                int maxToShow = Math.min(matchingVariables.size(), 15);
                for (int i = 0; i < maxToShow; i++) {
                    Variable var = matchingVariables.get(i);
                    Function containingFunction = var.getFunction();
                    
                    resultBuilder.append("- ").append(var.getName())
                               .append(" (").append(var.getDataType().getName()).append(")")
                               .append(" in function '").append(containingFunction.getName()).append("'")
                               .append("\n");
                }
                
                if (matchingVariables.size() > 15) {
                    resultBuilder.append("... and ").append(matchingVariables.size() - 15)
                                .append(" more matches.");
                }
                
                future.complete(resultBuilder.toString());
                
            } catch (Exception e) {
                Msg.error(GhidraToolsService.class, "Error searching for variables: " + e.getMessage(), e);
                future.complete("Error searching for variables: " + e.getMessage());
            }
        });
        
        return future;
    }
    
    /**
     * Finds cross-references to a variable in a function.
     * 
     * @param function The function containing the variable
     * @param varName The name of the variable to find references to
     * @param tool The Ghidra plugin tool
     * @return A CompletableFuture containing the result message
     */
    public static CompletableFuture<String> findVariableCrossReferences(Program program, Function function, 
                                                                       String varName, PluginTool tool) {
        CompletableFuture<String> future = new CompletableFuture<>();
        
        if (program == null || function == null) {
            Msg.error(GhidraToolsService.class, "Program or function is null");
            future.complete("Error: No program or function selected");
            return future;
        }
        
        Msg.info(GhidraToolsService.class, String.format(
            "Finding cross-references to variable: %s in function: %s",
            varName, function.getName()
        ));
        
        SwingUtilities.invokeLater(() -> {
            try {
                // Find the variable
                Variable[] vars = function.getAllVariables();
                Variable targetVar = null;
                
                for (Variable var : vars) {
                    if (var.getName().equals(varName)) {
                        targetVar = var;
                        break;
                    }
                }
                
                if (targetVar == null) {
                    Msg.error(GhidraToolsService.class, "Variable not found: " + varName);
                    future.complete("Error: Variable not found: " + varName);
                    return;
                }
                
                // Get variable references
                // We need to use decompiler to get accurate references to variables
                DecompInterface decompiler = new DecompInterface();
                decompiler.openProgram(program);
                DecompileOptions options = new DecompileOptions();
                decompiler.setOptions(options);
                
                DecompileResults results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
                if (!results.decompileCompleted()) {
                    Msg.error(GhidraToolsService.class, "Decompilation failed: " + results.getErrorMessage());
                    future.complete("Error: Could not decompile function to find variable references");
                    return;
                }
                
                // Manually find references by looking for the variable name in the decompiled code
                String decompCode = results.getDecompiledFunction().getC();
                String[] lines = decompCode.split("\n");
                List<ProgramLocation> references = new ArrayList<>();
                
                // Build simple reference list 
                for (int i = 0; i < lines.length; i++) {
                    if (lines[i].contains(targetVar.getName())) {
                        // Create a program location at the function entry point for each reference
                        // (This is a simplified approach as we can't easily map line numbers to addresses)
                        references.add(new ProgramLocation(program, function.getEntryPoint()));
                    }
                }
                
                if (references.isEmpty()) {
                    future.complete("No references found to variable '" + varName + "' in function '" + function.getName() + "'");
                    return;
                }
                
                StringBuilder resultBuilder = new StringBuilder();
                resultBuilder.append("References to variable '").append(varName)
                            .append("' in function '").append(function.getName()).append("':\n");
                
                int maxToShow = Math.min(references.size(), 10);
                for (int i = 0; i < maxToShow; i++) {
                    ProgramLocation loc = references.get(i);
                    resultBuilder.append("- At address: ").append(loc.getAddress()).append("\n");
                }
                
                if (references.size() > 10) {
                    resultBuilder.append("... and ").append(references.size() - 10).append(" more references.");
                }
                
                future.complete(resultBuilder.toString());
                
            } catch (Exception e) {
                Msg.error(GhidraToolsService.class, "Error finding variable references: " + e.getMessage(), e);
                future.complete("Error finding variable references: " + e.getMessage());
            }
        });
        
        return future;
    }
    
    /**
     * Applies a data type to a variable in a function.
     * 
     * @param program The current program
     * @param function The function containing the variable
     * @param varName The name of the variable to change the type of
     * @param dataTypeName The name of the data type to apply
     * @return A CompletableFuture containing the result message
     */
    public static CompletableFuture<String> applyDataType(Program program, Function function, 
                                                         String varName, String dataTypeName) {
        CompletableFuture<String> future = new CompletableFuture<>();
        
        if (program == null || function == null) {
            Msg.error(GhidraToolsService.class, "Program or function is null");
            future.complete("Error: No program or function selected");
            return future;
        }
        
        Msg.info(GhidraToolsService.class, String.format(
            "Applying data type: %s to variable: %s in function: %s",
            dataTypeName, varName, function.getName()
        ));
        
        SwingUtilities.invokeLater(() -> {
            // Find the variable
            Variable[] vars = function.getAllVariables();
            Variable targetVar = null;
            
            for (Variable var : vars) {
                if (var.getName().equals(varName)) {
                    targetVar = var;
                    break;
                }
            }
            
            if (targetVar == null) {
                Msg.error(GhidraToolsService.class, "Variable not found: " + varName);
                future.complete("Error: Variable not found: " + varName);
                return;
            }
            
            // Find the data type
            DataTypeManager dataTypeManager = program.getDataTypeManager();
            DataType dataType = dataTypeManager.getDataType(dataTypeName);
            
            if (dataType == null) {
                // Try to find by name without path
                // Use the iterator directly instead of converting to array
                Iterable<DataType> dataTypes = () -> dataTypeManager.getAllDataTypes();
                for (DataType dt : dataTypes) {
                    if (dt.getName().equals(dataTypeName)) {
                        dataType = dt;
                        break;
                    }
                }
                
                if (dataType == null) {
                    Msg.error(GhidraToolsService.class, "Data type not found: " + dataTypeName);
                    future.complete("Error: Data type not found: " + dataTypeName);
                    return;
                }
            }
            
            // Show confirmation dialog
            int result = JOptionPane.showConfirmDialog(
                null,
                "Apply data type '" + dataTypeName + "' to variable '" + varName + 
                "' in function '" + function.getName() + "'?",
                "Confirm Data Type Change",
                JOptionPane.YES_NO_OPTION
            );
            
            Msg.info(GhidraToolsService.class, "Data type dialog result: " + (result == JOptionPane.YES_OPTION ? "YES" : "NO"));
            
            if (result == JOptionPane.YES_OPTION) {
                int transactionID = program.startTransaction("Apply Data Type");
                boolean success = false;
                
                try {
                    Msg.info(GhidraToolsService.class, "Starting data type change transaction");
                    
                    // Store the old data type for the message
                    String oldDataTypeName = targetVar.getDataType().getName();
                    
                    // Apply the new data type
                    targetVar.setDataType(dataType, SourceType.USER_DEFINED);
                    
                    Msg.info(GhidraToolsService.class, "Data type applied successfully");
                    success = true;
                    
                    future.complete("Successfully changed data type of variable '" + varName + 
                                   "' from '" + oldDataTypeName + "' to '" + dataTypeName + 
                                   "' in function '" + function.getName() + "'");
                    
                } catch (Exception e) {
                    Msg.error(GhidraToolsService.class, "Error applying data type: " + e.getMessage(), e);
                    future.complete("Error: Could not apply data type: " + e.getMessage());
                } finally {
                    Msg.info(GhidraToolsService.class, "Ending data type change transaction with success=" + success);
                    program.endTransaction(transactionID, success);
                }
            } else {
                Msg.info(GhidraToolsService.class, "Data type change cancelled by user");
                future.complete("Data type change cancelled by user");
            }
        });
        
        return future;
    }
    
    /**
     * Creates a new structure data type.
     * 
     * @param program The current program
     * @param structName The name of the structure to create
     * @return A CompletableFuture containing the result message
     */
    public static CompletableFuture<String> createStructure(Program program, String structName) {
        CompletableFuture<String> future = new CompletableFuture<>();
        
        if (program == null) {
            Msg.error(GhidraToolsService.class, "Program is null");
            future.complete("Error: No program selected");
            return future;
        }
        
        Msg.info(GhidraToolsService.class, "Creating structure: " + structName);
        
        SwingUtilities.invokeLater(() -> {
            // Check if structure already exists
            DataTypeManager dataTypeManager = program.getDataTypeManager();
            DataType existingType = dataTypeManager.getDataType("/" + structName);
            
            if (existingType != null) {
                Msg.error(GhidraToolsService.class, "Structure already exists: " + structName);
                future.complete("Error: Structure already exists: " + structName);
                return;
            }
            
            // Show confirmation dialog
            int result = JOptionPane.showConfirmDialog(
                null,
                "Create new structure '" + structName + "'?",
                "Confirm Structure Creation",
                JOptionPane.YES_NO_OPTION
            );
            
            Msg.info(GhidraToolsService.class, "Structure creation dialog result: " + (result == JOptionPane.YES_OPTION ? "YES" : "NO"));
            
            if (result == JOptionPane.YES_OPTION) {
                int transactionID = program.startTransaction("Create Structure");
                boolean success = false;
                
                try {
                    Msg.info(GhidraToolsService.class, "Starting structure creation transaction");
                    
                    // Create the structure
                    StructureDataType struct = new StructureDataType(structName, 0);
                    dataTypeManager.addDataType(struct, null);
                    
                    Msg.info(GhidraToolsService.class, "Structure created successfully");
                    success = true;
                    
                    future.complete("Successfully created new structure: " + structName);
                    
                } catch (Exception e) {
                    Msg.error(GhidraToolsService.class, "Error creating structure: " + e.getMessage(), e);
                    future.complete("Error: Could not create structure: " + e.getMessage());
                } finally {
                    Msg.info(GhidraToolsService.class, "Ending structure creation transaction with success=" + success);
                    program.endTransaction(transactionID, success);
                }
            } else {
                Msg.info(GhidraToolsService.class, "Structure creation cancelled by user");
                future.complete("Structure creation cancelled by user");
            }
        });
        
        return future;
    }
    
    /**
     * Modifies an existing structure by adding a new field.
     * 
     * @param program The current program
     * @param structName The name of the structure to modify
     * @param fieldName The name of the field to add
     * @param fieldTypeName The data type of the field to add
     * @return A CompletableFuture containing the result message
     */
    public static CompletableFuture<String> modifyStructure(Program program, String structName, 
                                                           String fieldName, String fieldTypeName) {
        CompletableFuture<String> future = new CompletableFuture<>();
        
        if (program == null) {
            Msg.error(GhidraToolsService.class, "Program is null");
            future.complete("Error: No program selected");
            return future;
        }
        
        Msg.info(GhidraToolsService.class, String.format(
            "Modifying structure: %s, adding field: %s of type: %s",
            structName, fieldName, fieldTypeName
        ));
        
        SwingUtilities.invokeLater(() -> {
            // Find the structure
            DataTypeManager dataTypeManager = program.getDataTypeManager();
            DataType dataType = dataTypeManager.getDataType("/" + structName);
            
            if (dataType == null) {
                // Try to find by name without path
                // Use the iterator directly instead of converting to array
                Iterable<DataType> dataTypes = () -> dataTypeManager.getAllDataTypes();
                for (DataType dt : dataTypes) {
                    if (dt.getName().equals(structName) && dt instanceof Structure) {
                        dataType = dt;
                        break;
                    }
                }
                
                if (dataType == null) {
                    Msg.error(GhidraToolsService.class, "Structure not found: " + structName);
                    future.complete("Error: Structure not found: " + structName);
                    return;
                }
            }
            
            if (!(dataType instanceof Structure)) {
                Msg.error(GhidraToolsService.class, "Data type is not a structure: " + structName);
                future.complete("Error: Data type is not a structure: " + structName);
                return;
            }
            
            // Find the field data type
            DataType fieldDataType = dataTypeManager.getDataType("/" + fieldTypeName);
            
            if (fieldDataType == null) {
                // Try to find by name without path
                // Use the iterator directly instead of converting to array
                Iterable<DataType> dataTypes = () -> dataTypeManager.getAllDataTypes();
                for (DataType dt : dataTypes) {
                    if (dt.getName().equals(fieldTypeName)) {
                        fieldDataType = dt;
                        break;
                    }
                }
                
                if (fieldDataType == null) {
                    Msg.error(GhidraToolsService.class, "Field data type not found: " + fieldTypeName);
                    future.complete("Error: Field data type not found: " + fieldTypeName);
                    return;
                }
            }
            
            // Show confirmation dialog
            int result = JOptionPane.showConfirmDialog(
                null,
                "Add field '" + fieldName + "' of type '" + fieldTypeName + "' to structure '" + structName + "'?",
                "Confirm Structure Modification",
                JOptionPane.YES_NO_OPTION
            );
            
            Msg.info(GhidraToolsService.class, "Structure modification dialog result: " + (result == JOptionPane.YES_OPTION ? "YES" : "NO"));
            
            if (result == JOptionPane.YES_OPTION) {
                int transactionID = program.startTransaction("Modify Structure");
                boolean success = false;
                
                try {
                    Msg.info(GhidraToolsService.class, "Starting structure modification transaction");
                    
                    // Cast to Structure and add the field
                    Structure struct = (Structure) dataType;
                    struct.add(fieldDataType, fieldDataType.getLength(), fieldName, "Added by ByteMate");
                    
                    Msg.info(GhidraToolsService.class, "Structure modified successfully");
                    success = true;
                    
                    future.complete("Successfully added field '" + fieldName + 
                                   "' of type '" + fieldTypeName + 
                                   "' to structure '" + structName + "'");
                    
                } catch (Exception e) {
                    Msg.error(GhidraToolsService.class, "Error modifying structure: " + e.getMessage(), e);
                    future.complete("Error: Could not modify structure: " + e.getMessage());
                } finally {
                    Msg.info(GhidraToolsService.class, "Ending structure modification transaction with success=" + success);
                    program.endTransaction(transactionID, success);
                }
            } else {
                Msg.info(GhidraToolsService.class, "Structure modification cancelled by user");
                future.complete("Structure modification cancelled by user");
            }
        });
        
        return future;
    }
    
    /**
     * Modifies a function signature.
     * 
     * @param program The current program
     * @param function The function to modify
     * @param signature The new signature string
     * @return A CompletableFuture containing the result message
     */
    public static CompletableFuture<String> modifyFunctionSignature(Program program, Function function, 
                                                                  String signature) {
        CompletableFuture<String> future = new CompletableFuture<>();
        
        if (program == null || function == null) {
            Msg.error(GhidraToolsService.class, "Program or function is null");
            future.complete("Error: No program or function selected");
            return future;
        }
        
        Msg.info(GhidraToolsService.class, String.format(
            "Modifying function signature for: %s to: %s",
            function.getName(), signature
        ));
        
        SwingUtilities.invokeLater(() -> {
            // Show confirmation dialog
            int result = JOptionPane.showConfirmDialog(
                null,
                "Change signature of function '" + function.getName() + "' to '" + signature + "'?",
                "Confirm Function Signature Change",
                JOptionPane.YES_NO_OPTION
            );
            
            Msg.info(GhidraToolsService.class, "Function signature dialog result: " + (result == JOptionPane.YES_OPTION ? "YES" : "NO"));
            
            if (result == JOptionPane.YES_OPTION) {
                int transactionID = program.startTransaction("Modify Function Signature");
                boolean success = false;
                
                try {
                    Msg.info(GhidraToolsService.class, "Starting function signature modification transaction");
                    
                    // Parse the signature string and apply it to the function
                    // NOTE: This is a simplified implementation that doesn't handle all cases
                    // A proper implementation would parse the signature string to extract
                    // return type, parameter types, etc. using Ghidra's built-in parsers
                    
                    // Get the decompiler interface to parse the signature
                    DecompInterface decompiler = new DecompInterface();
                    decompiler.openProgram(program);
                    
                    // For now, just update the comment with the signature
                    // as a placeholder until a full parser is implemented
                    String oldComment = function.getComment();
                    String newComment = "FUNCTION SIGNATURE: " + signature;
                    
                    if (oldComment != null && !oldComment.isEmpty()) {
                        if (!oldComment.contains("FUNCTION SIGNATURE:")) {
                            newComment = oldComment + "\n" + newComment;
                        } else {
                            // Replace existing signature comment
                            newComment = oldComment.replaceAll("FUNCTION SIGNATURE:.*", newComment);
                        }
                    }
                    
                    function.setComment(newComment);
                    
                    Msg.info(GhidraToolsService.class, "Function signature modified (placeholder implementation)");
                    success = true;
                    
                    future.complete("Function signature modified (placeholder implementation). Added as comment: " + signature);
                    
                } catch (Exception e) {
                    Msg.error(GhidraToolsService.class, "Error modifying function signature: " + e.getMessage(), e);
                    future.complete("Error: Could not modify function signature: " + e.getMessage());
                } finally {
                    Msg.info(GhidraToolsService.class, "Ending function signature modification transaction with success=" + success);
                    program.endTransaction(transactionID, success);
                }
            } else {
                Msg.info(GhidraToolsService.class, "Function signature modification cancelled by user");
                future.complete("Function signature modification cancelled by user");
            }
        });
        
        return future;
    }
    
    /**
     * Maps a variable to a structure type.
     * 
     * @param program The current program
     * @param function The function containing the variable
     * @param varName The variable name to map
     * @param structName The structure name to map to
     * @param fieldName The specific field name to map (optional)
     * @return A CompletableFuture containing the result message
     */
    public static CompletableFuture<String> mapVariableToStructure(Program program, Function function, 
                                                                 String varName, String structName, 
                                                                 String fieldName) {
        CompletableFuture<String> future = new CompletableFuture<>();
        
        if (program == null || function == null) {
            Msg.error(GhidraToolsService.class, "Program or function is null");
            future.complete("Error: No program or function selected");
            return future;
        }
        
        Msg.info(GhidraToolsService.class, String.format(
            "Mapping variable: %s to structure: %s%s",
            varName, structName, fieldName != null ? "." + fieldName : ""
        ));
        
        SwingUtilities.invokeLater(() -> {
            try {
                // Find the variable
                Variable[] vars = function.getAllVariables();
                Variable targetVar = null;
                
                for (Variable var : vars) {
                    if (var.getName().equals(varName)) {
                        targetVar = var;
                        break;
                    }
                }
                
                if (targetVar == null) {
                    Msg.error(GhidraToolsService.class, "Variable not found: " + varName);
                    future.complete("Error: Variable not found: " + varName);
                    return;
                }
                
                // Find the structure data type
                DataTypeManager dataTypeManager = program.getDataTypeManager();
                DataType dataType = dataTypeManager.getDataType("/" + structName);
                
                if (dataType == null) {
                    // Try to find by name without path
                    // Use the iterator directly instead of converting to array
                    Iterable<DataType> dataTypes = () -> dataTypeManager.getAllDataTypes();
                    for (DataType dt : dataTypes) {
                        if (dt.getName().equals(structName) && dt instanceof Structure) {
                            dataType = dt;
                            break;
                        }
                    }
                    
                    if (dataType == null) {
                        Msg.error(GhidraToolsService.class, "Structure not found: " + structName);
                        future.complete("Error: Structure not found: " + structName);
                        return;
                    }
                }
                
                if (!(dataType instanceof Structure)) {
                    Msg.error(GhidraToolsService.class, "Data type is not a structure: " + structName);
                    future.complete("Error: Data type is not a structure: " + structName);
                    return;
                }
                
                // For field mapping, we would need to extract a pointer or substructure
                // This is a simplified implementation
                final DataType finalType = dataType;
                
                // Show confirmation dialog
                int result = JOptionPane.showConfirmDialog(
                    null,
                    "Map variable '" + varName + "' to structure type '" + structName + "'?",
                    "Confirm Variable to Structure Mapping",
                    JOptionPane.YES_NO_OPTION
                );
                
                Msg.info(GhidraToolsService.class, "Variable mapping dialog result: " + (result == JOptionPane.YES_OPTION ? "YES" : "NO"));
                
                if (result == JOptionPane.YES_OPTION) {
                    int transactionID = program.startTransaction("Map Variable to Structure");
                    boolean success = false;
                    
                    try {
                        Msg.info(GhidraToolsService.class, "Starting variable mapping transaction");
                        
                        // Get the old data type name for the message
                        String oldTypeName = targetVar.getDataType().getName();
                        
                        // Apply the structure type to the variable
                        targetVar.setDataType(finalType, SourceType.USER_DEFINED);
                        
                        Msg.info(GhidraToolsService.class, "Variable mapped to structure successfully");
                        success = true;
                        
                        future.complete("Successfully mapped variable '" + varName + 
                                       "' from type '" + oldTypeName + 
                                       "' to structure '" + structName + "'");
                        
                    } catch (Exception e) {
                        Msg.error(GhidraToolsService.class, "Error mapping variable to structure: " + e.getMessage(), e);
                        future.complete("Error: Could not map variable to structure: " + e.getMessage());
                    } finally {
                        Msg.info(GhidraToolsService.class, "Ending variable mapping transaction with success=" + success);
                        program.endTransaction(transactionID, success);
                    }
                } else {
                    Msg.info(GhidraToolsService.class, "Variable mapping cancelled by user");
                    future.complete("Variable mapping cancelled by user");
                }
                
            } catch (Exception e) {
                Msg.error(GhidraToolsService.class, "Error in variable mapping process: " + e.getMessage(), e);
                future.complete("Error in variable mapping process: " + e.getMessage());
            }
        });
        
        return future;
    }
    
    /**
     * Identifies common algorithms in the function.
     * 
     * @param program The current program
     * @param function The function to analyze
     * @return A CompletableFuture containing the result message
     */
    public static CompletableFuture<String> identifyAlgorithm(Program program, Function function) {
        CompletableFuture<String> future = new CompletableFuture<>();
        
        if (program == null || function == null) {
            Msg.error(GhidraToolsService.class, "Program or function is null");
            future.complete("Error: No program or function selected");
            return future;
        }
        
        Msg.info(GhidraToolsService.class, "Identifying algorithms in function: " + function.getName());
        
        SwingUtilities.invokeLater(() -> {
            try {
                // This would be a complex algorithm pattern recognition implementation
                // For now, we'll provide a simplified placeholder that analyzes the decompiled output
                
                // Get the decompiler interface for the function
                DecompInterface decompiler = new DecompInterface();
                decompiler.openProgram(program);
                DecompileOptions options = new DecompileOptions();
                decompiler.setOptions(options);
                
                DecompileResults results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
                if (!results.decompileCompleted()) {
                    Msg.error(GhidraToolsService.class, "Decompilation failed: " + results.getErrorMessage());
                    future.complete("Error: Could not decompile function to identify algorithms");
                    return;
                }
                
                String decompCode = results.getDecompiledFunction().getC();
                
                // Very simple pattern matching for common algorithms
                // In a real implementation, this would be much more sophisticated
                StringBuilder identifiedAlgorithms = new StringBuilder();
                
                if (decompCode.contains("MD5") || decompCode.contains("md5")) {
                    identifiedAlgorithms.append("- MD5 hash algorithm\n");
                }
                
                if (decompCode.contains("SHA") || decompCode.contains("sha")) {
                    identifiedAlgorithms.append("- SHA hash algorithm\n");
                }
                
                if (decompCode.contains("quicksort") || decompCode.contains("qsort")) {
                    identifiedAlgorithms.append("- Quicksort algorithm\n");
                }
                
                if (decompCode.contains("bubble") && decompCode.contains("sort")) {
                    identifiedAlgorithms.append("- Bubble sort algorithm\n");
                }
                
                if (decompCode.contains("memcpy") || (decompCode.contains("mem") && decompCode.contains("cpy"))) {
                    identifiedAlgorithms.append("- Memory copy operation\n");
                }
                
                if (decompCode.contains("strcpy") || (decompCode.contains("str") && decompCode.contains("cpy"))) {
                    identifiedAlgorithms.append("- String copy operation\n");
                }
                
                if (decompCode.contains("AES") || decompCode.contains("aes")) {
                    identifiedAlgorithms.append("- AES encryption/decryption\n");
                }
                
                if (decompCode.contains("DES") || decompCode.contains("des")) {
                    identifiedAlgorithms.append("- DES encryption/decryption\n");
                }
                
                if (decompCode.contains("RC4") || decompCode.contains("rc4")) {
                    identifiedAlgorithms.append("- RC4 encryption/decryption\n");
                }
                
                if (identifiedAlgorithms.length() > 0) {
                    future.complete("Identified potential algorithms in function '" + function.getName() + "':\n" + 
                                    identifiedAlgorithms.toString() + 
                                    "\nNote: This is a simplified pattern matching. Results may not be accurate.");
                } else {
                    future.complete("No common algorithms identified in function '" + function.getName() + "'.\n" + 
                                    "Note: This is a simplified implementation with limited pattern recognition.");
                }
                
            } catch (Exception e) {
                Msg.error(GhidraToolsService.class, "Error identifying algorithms: " + e.getMessage(), e);
                future.complete("Error identifying algorithms: " + e.getMessage());
            }
        });
        
        return future;
    }
    
    /**
     * Finds similar code patterns across the program.
     * 
     * @param program The current program
     * @param function The function to use as a reference
     * @return A CompletableFuture containing the result message
     */
    public static CompletableFuture<String> findSimilarCode(Program program, Function function) {
        CompletableFuture<String> future = new CompletableFuture<>();
        
        if (program == null || function == null) {
            Msg.error(GhidraToolsService.class, "Program or function is null");
            future.complete("Error: No program or function selected");
            return future;
        }
        
        Msg.info(GhidraToolsService.class, "Searching for code similar to function: " + function.getName());
        
        SwingUtilities.invokeLater(() -> {
            try {
                // This would be a complex code similarity analysis implementation
                // For now, we'll provide a simplified placeholder that looks for functions
                // with similar instruction counts and common instruction sequences
                
                // Get function information
                long instructionCount = function.getBody().getNumAddresses();
                
                // Get the decompiler interface for the function
                DecompInterface decompiler = new DecompInterface();
                decompiler.openProgram(program);
                DecompileOptions options = new DecompileOptions();
                decompiler.setOptions(options);
                
                DecompileResults results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
                if (!results.decompileCompleted()) {
                    Msg.error(GhidraToolsService.class, "Decompilation failed: " + results.getErrorMessage());
                    future.complete("Error: Could not decompile function to find similar code");
                    return;
                }
                
                String decompCode = results.getDecompiledFunction().getC().toLowerCase();
                
                // Extract some "signature" tokens from the function
                // In a real implementation, this would be more sophisticated
                List<String> signatureTokens = new ArrayList<>();
                if (decompCode.contains("if ")) signatureTokens.add("if statement");
                if (decompCode.contains("for ")) signatureTokens.add("for loop");
                if (decompCode.contains("while ")) signatureTokens.add("while loop");
                if (decompCode.contains("switch ")) signatureTokens.add("switch statement");
                if (decompCode.contains("memcpy")) signatureTokens.add("memory copy");
                if (decompCode.contains("malloc")) signatureTokens.add("memory allocation");
                if (decompCode.contains("free")) signatureTokens.add("memory deallocation");
                if (decompCode.contains("strcpy")) signatureTokens.add("string copy");
                if (decompCode.contains("strcat")) signatureTokens.add("string concatenation");
                
                // Search for similar functions
                FunctionManager functionManager = program.getFunctionManager();
                int similarityThreshold = 70; // Percent similarity required
                List<Function> similarFunctions = new ArrayList<>();
                
                functionManager.getFunctions(true).forEach(otherFunc -> {
                    // Skip the reference function itself
                    if (otherFunc.equals(function)) {
                        return;
                    }
                    
                    // Compare size first as a quick filter
                    long otherSize = otherFunc.getBody().getNumAddresses();
                    double sizeSimilarity = Math.min(instructionCount, otherSize) * 100.0 / Math.max(instructionCount, otherSize);
                    
                    if (sizeSimilarity < 50) {
                        return; // Size difference too large
                    }
                    
                    // For closer matches, do more detailed analysis
                    try {
                        DecompileResults otherResults = decompiler.decompileFunction(otherFunc, 30, TaskMonitor.DUMMY);
                        if (!otherResults.decompileCompleted()) {
                            return;
                        }
                        
                        String otherCode = otherResults.getDecompiledFunction().getC().toLowerCase();
                        
                        // Count matching tokens
                        int matchingTokens = 0;
                        for (String token : signatureTokens) {
                            if (otherCode.contains(token.split(" ")[0])) {
                                matchingTokens++;
                            }
                        }
                        
                        double tokenSimilarity = 0;
                        if (!signatureTokens.isEmpty()) {
                            tokenSimilarity = matchingTokens * 100.0 / signatureTokens.size();
                        }
                        
                        // Final similarity score
                        double similarity = (sizeSimilarity * 0.3) + (tokenSimilarity * 0.7);
                        
                        if (similarity >= similarityThreshold) {
                            similarFunctions.add(otherFunc);
                        }
                        
                    } catch (Exception e) {
                        Msg.debug(GhidraToolsService.class, "Error analyzing function " + otherFunc.getName() + ": " + e.getMessage());
                    }
                });
                
                if (similarFunctions.isEmpty()) {
                    future.complete("No functions found with similar code patterns to '" + function.getName() + "'.\n" + 
                                   "Note: This is a simplified implementation with limited pattern recognition.");
                    return;
                }
                
                // Build the result message
                StringBuilder resultBuilder = new StringBuilder();
                resultBuilder.append("Functions with similar code patterns to '").append(function.getName()).append("':\n");
                
                int maxToShow = Math.min(similarFunctions.size(), 10);
                for (int i = 0; i < maxToShow; i++) {
                    Function similarFunc = similarFunctions.get(i);
                    resultBuilder.append("- ").append(similarFunc.getName())
                               .append(" at ").append(similarFunc.getEntryPoint())
                               .append("\n");
                }
                
                if (similarFunctions.size() > 10) {
                    resultBuilder.append("... and ").append(similarFunctions.size() - 10)
                               .append(" more similar functions.\n");
                }
                
                resultBuilder.append("\nNote: This is a simplified implementation with limited pattern recognition. ")
                           .append("Results may not be accurate.");
                
                future.complete(resultBuilder.toString());
                
            } catch (Exception e) {
                Msg.error(GhidraToolsService.class, "Error finding similar code: " + e.getMessage(), e);
                future.complete("Error finding similar code: " + e.getMessage());
            }
        });
        
        return future;
    }
    
    /**
     * Generates a script to automate tasks.
     * 
     * @param program The current program
     * @param function The current function (may be used for context)
     * @param scriptLang The script language (python, java, ghidra)
     * @param scriptPurpose The purpose of the script
     * @return A CompletableFuture containing the result message
     */
    public static CompletableFuture<String> generateScript(Program program, Function function, 
                                                         String scriptLang, String scriptPurpose) {
        CompletableFuture<String> future = new CompletableFuture<>();
        
        if (program == null) {
            Msg.error(GhidraToolsService.class, "Program is null");
            future.complete("Error: No program selected");
            return future;
        }
        
        Msg.info(GhidraToolsService.class, String.format(
            "Generating %s script for: %s",
            scriptLang, scriptPurpose
        ));
        
        SwingUtilities.invokeLater(() -> {
            // Note: In a real implementation, this would likely involve an external LLM call
            // to generate the script based on the context. Here we provide a simplified
            // template-based implementation.
            
            String scriptTemplate = "";
            String scriptName = "ByteMate_" + System.currentTimeMillis() + "." + (scriptLang.equals("ghidra") ? "java" : scriptLang);
            
            // Create script based on language
            if (scriptLang.equalsIgnoreCase("python")) {
                scriptTemplate = generatePythonScript(program, function, scriptPurpose);
            } else if (scriptLang.equalsIgnoreCase("java") || scriptLang.equalsIgnoreCase("ghidra")) {
                scriptTemplate = generateJavaScript(program, function, scriptPurpose);
            } else {
                future.complete("Unsupported script language: " + scriptLang);
                return;
            }
            
            // Show confirmation dialog
            int result = JOptionPane.showConfirmDialog(
                null,
                "Generate " + scriptLang + " script for purpose: '" + scriptPurpose + "'?",
                "Confirm Script Generation",
                JOptionPane.YES_NO_OPTION
            );
            
            Msg.info(GhidraToolsService.class, "Script generation dialog result: " + (result == JOptionPane.YES_OPTION ? "YES" : "NO"));
            
            if (result == JOptionPane.YES_OPTION) {
                int transactionID = program.startTransaction("Generate Script");
                boolean success = false;
                
                try {
                    Msg.info(GhidraToolsService.class, "Starting script generation transaction");
                    
                    // In a real implementation, we would actually write the script to disk
                    // in the Ghidra scripts directory. For now, we'll just return the script content.
                    
                    Msg.info(GhidraToolsService.class, "Script generated successfully");
                    success = true;
                    
                    future.complete("Generated " + scriptLang + " script for: " + scriptPurpose + "\n\n" +
                                   "Script Name: " + scriptName + "\n\n" +
                                   "Script Content:\n```\n" + scriptTemplate + "\n```\n\n" +
                                   "Note: This is a template script. You would need to save this to your Ghidra scripts directory.");
                    
                } catch (Exception e) {
                    Msg.error(GhidraToolsService.class, "Error generating script: " + e.getMessage(), e);
                    future.complete("Error: Could not generate script: " + e.getMessage());
                } finally {
                    Msg.info(GhidraToolsService.class, "Ending script generation transaction with success=" + success);
                    program.endTransaction(transactionID, success);
                }
            } else {
                Msg.info(GhidraToolsService.class, "Script generation cancelled by user");
                future.complete("Script generation cancelled by user");
            }
        });
        
        return future;
    }
    
    /**
     * Helper method to generate a Python script based on the purpose.
     */
    private static String generatePythonScript(Program program, Function function, String scriptPurpose) {
        StringBuilder sb = new StringBuilder();
        
        // Standard Ghidra Python script header
        sb.append("# ByteMate generated script\n");
        sb.append("# Purpose: ").append(scriptPurpose).append("\n");
        sb.append("# Date: ").append(new java.util.Date()).append("\n\n");
        
        sb.append("# @category ByteMate\n");
        sb.append("# @keybinding \n");
        sb.append("# @menupath \n");
        sb.append("# @toolbar \n\n");
        
        sb.append("from ghidra.program.model.listing import *\n");
        sb.append("from ghidra.program.model.symbol import *\n");
        sb.append("from ghidra.util import *\n\n");
        
        // Script body based on purpose (simplified templates)
        if (scriptPurpose.toLowerCase().contains("rename")) {
            // Script to rename functions based on patterns
            sb.append("def run():\n");
            sb.append("    # Get current program\n");
            sb.append("    program = getCurrentProgram()\n");
            sb.append("    functionManager = program.getFunctionManager()\n\n");
            
            sb.append("    # Process all functions\n");
            sb.append("    for function in functionManager.getFunctions(True):\n");
            sb.append("        name = function.getName()\n");
            sb.append("        # Add your renaming logic here\n");
            sb.append("        # Example: rename sub_* functions with certain patterns\n");
            sb.append("        if name.startswith('sub_'):\n");
            sb.append("            # Analyze function and rename based on characteristics\n");
            sb.append("            # Example condition - detect string functions\n");
            sb.append("            body = function.getBody()\n");
            sb.append("            # You would need more sophisticated logic here\n");
            sb.append("            # This is just a placeholder\n");
            sb.append("            pass\n\n");
            
            sb.append("    print('Function renaming complete')\n\n");
        } else if (scriptPurpose.toLowerCase().contains("export") || scriptPurpose.toLowerCase().contains("extract")) {
            // Script to extract data from the binary
            sb.append("def run():\n");
            sb.append("    # Get current program\n");
            sb.append("    program = getCurrentProgram()\n");
            sb.append("    memory = program.getMemory()\n\n");
            
            sb.append("    # Example: extract all strings\n");
            sb.append("    # This is a simplified placeholder\n");
            sb.append("    stringReferences = []\n");
            sb.append("    listing = program.getListing()\n");
            sb.append("    for string in listing.getDefinedData(True):\n");
            sb.append("        if string.getDataType().getName() == 'string':\n");
            sb.append("            stringReferences.append(string)\n\n");
            
            sb.append("    # Process extracted data\n");
            sb.append("    for string in stringReferences:\n");
            sb.append("        print(f\"String at {string.getAddress()}: {string.getValue()}\")\n\n");
            
            sb.append("    print('Data extraction complete')\n\n");
        } else if (scriptPurpose.toLowerCase().contains("analyze") || scriptPurpose.toLowerCase().contains("identify")) {
            // Script to analyze code patterns
            sb.append("def run():\n");
            sb.append("    # Get current program\n");
            sb.append("    program = getCurrentProgram()\n");
            sb.append("    functionManager = program.getFunctionManager()\n\n");
            
            sb.append("    # Example: analyze functions to identify patterns\n");
            sb.append("    for function in functionManager.getFunctions(True):\n");
            sb.append("        # Simplified pattern detection\n");
            sb.append("        # You would need more sophisticated logic here\n");
            sb.append("        print(f\"Analyzing function: {function.getName()}\")\n");
            sb.append("        # Add your analysis logic here\n\n");
            
            sb.append("    print('Analysis complete')\n\n");
        } else {
            // Generic script template
            sb.append("def run():\n");
            sb.append("    # Get current program\n");
            sb.append("    program = getCurrentProgram()\n");
            sb.append("    # Add your code here\n");
            sb.append("    print('Script executed successfully')\n\n");
        }
        
        // Call the run function
        sb.append("# Main execution\n");
        sb.append("run()\n");
        
        return sb.toString();
    }
    
    /**
     * Helper method to generate a Java script based on the purpose.
     */
    private static String generateJavaScript(Program program, Function function, String scriptPurpose) {
        StringBuilder sb = new StringBuilder();
        
        // Standard Ghidra Java script header
        sb.append("// ByteMate generated script\n");
        sb.append("// Purpose: ").append(scriptPurpose).append("\n");
        sb.append("// Date: ").append(new java.util.Date()).append("\n\n");
        
        sb.append("// @category ByteMate\n");
        sb.append("// @keybinding \n");
        sb.append("// @menupath \n");
        sb.append("// @toolbar \n\n");
        
        sb.append("import ghidra.app.script.GhidraScript;\n");
        sb.append("import ghidra.program.model.listing.*;\n");
        sb.append("import ghidra.program.model.symbol.*;\n");
        sb.append("import ghidra.util.exception.CancelledException;\n");
        sb.append("import java.util.*;\n\n");
        
        sb.append("public class ByteMateGeneratedScript extends GhidraScript {\n\n");
        sb.append("    @Override\n");
        sb.append("    protected void run() throws Exception {\n");
        
        // Script body based on purpose (simplified templates)
        if (scriptPurpose.toLowerCase().contains("rename")) {
            // Script to rename functions based on patterns
            sb.append("        // Get function manager\n");
            sb.append("        FunctionManager functionManager = currentProgram.getFunctionManager();\n\n");
            
            sb.append("        // Process all functions\n");
            sb.append("        for (Function function : functionManager.getFunctions(true)) {\n");
            sb.append("            String name = function.getName();\n");
            sb.append("            // Add your renaming logic here\n");
            sb.append("            // Example: rename sub_* functions with certain patterns\n");
            sb.append("            if (name.startsWith(\"sub_\")) {\n");
            sb.append("                // Analyze function and rename based on characteristics\n");
            sb.append("                // You would need more sophisticated logic here\n");
            sb.append("                // This is just a placeholder\n");
            sb.append("            }\n");
            sb.append("        }\n\n");
            
            sb.append("        println(\"Function renaming complete\");\n");
        } else if (scriptPurpose.toLowerCase().contains("export") || scriptPurpose.toLowerCase().contains("extract")) {
            // Script to extract data from the binary
            sb.append("        // Get memory and listing\n");
            sb.append("        Listing listing = currentProgram.getListing();\n\n");
            
            sb.append("        // Example: extract all strings\n");
            sb.append("        // This is a simplified placeholder\n");
            sb.append("        List<Data> stringData = new ArrayList<>();\n");
            sb.append("        for (Data data : listing.getDefinedData(true)) {\n");
            sb.append("            if (data.getDataType().getName().equals(\"string\")) {\n");
            sb.append("                stringData.add(data);\n");
            sb.append("            }\n");
            sb.append("        }\n\n");
            
            sb.append("        // Process extracted data\n");
            sb.append("        for (Data string : stringData) {\n");
            sb.append("            println(\"String at \" + string.getAddress() + \": \" + string.getValue());\n");
            sb.append("        }\n\n");
            
            sb.append("        println(\"Data extraction complete\");\n");
        } else if (scriptPurpose.toLowerCase().contains("analyze") || scriptPurpose.toLowerCase().contains("identify")) {
            // Script to analyze code patterns
            sb.append("        // Get function manager\n");
            sb.append("        FunctionManager functionManager = currentProgram.getFunctionManager();\n\n");
            
            sb.append("        // Example: analyze functions to identify patterns\n");
            sb.append("        for (Function function : functionManager.getFunctions(true)) {\n");
            sb.append("            // Simplified pattern detection\n");
            sb.append("            // You would need more sophisticated logic here\n");
            sb.append("            println(\"Analyzing function: \" + function.getName());\n");
            sb.append("            // Add your analysis logic here\n");
            sb.append("        }\n\n");
            
            sb.append("        println(\"Analysis complete\");\n");
        } else {
            // Generic script template
            sb.append("        // Add your code here\n");
            sb.append("        println(\"Script executed successfully\");\n");
        }
        
        // Close the class
        sb.append("    }\n");
        sb.append("}\n");
        
        return sb.toString();
    }
    
    /**
     * Generates documentation for a function.
     * 
     * @param program The current program
     * @param function The function to document
     * @return A CompletableFuture containing the result message
     */
    public static CompletableFuture<String> generateDocumentation(Program program, Function function) {
        CompletableFuture<String> future = new CompletableFuture<>();
        
        if (program == null || function == null) {
            Msg.error(GhidraToolsService.class, "Program or function is null");
            future.complete("Error: No program or function selected");
            return future;
        }
        
        Msg.info(GhidraToolsService.class, "Generating documentation for function: " + function.getName());
        
        SwingUtilities.invokeLater(() -> {
            try {
                // Get decompiled code
                DecompInterface decompiler = new DecompInterface();
                decompiler.openProgram(program);
                DecompileOptions options = new DecompileOptions();
                decompiler.setOptions(options);
                
                DecompileResults results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
                if (!results.decompileCompleted()) {
                    Msg.error(GhidraToolsService.class, "Decompilation failed: " + results.getErrorMessage());
                    future.complete("Error: Could not decompile function to generate documentation");
                    return;
                }
                
                String decompCode = results.getDecompiledFunction().getC();
                
                // Build function documentation
                StringBuilder docBuilder = new StringBuilder();
                docBuilder.append("# Function Documentation: ").append(function.getName()).append("\n\n");
                
                docBuilder.append("## Overview\n");
                docBuilder.append("- **Address**: ").append(function.getEntryPoint()).append("\n");
                docBuilder.append("- **Size**: ").append(function.getBody().getNumAddresses()).append(" bytes\n");
                
                // Get function parameters without using Parameter[] type
                docBuilder.append("- **Parameters**: ").append(function.getParameterCount()).append("\n");
                if (function.getParameterCount() > 0) {
                    docBuilder.append("  - ");
                    for (int i = 0; i < function.getParameterCount(); i++) {
                        Variable param = function.getParameter(i);
                        docBuilder.append(param.getDataType().getName()).append(" ").append(param.getName());
                        if (i < function.getParameterCount() - 1) docBuilder.append(", ");
                    }
                    docBuilder.append("\n");
                }
                
                // Get function return type
                docBuilder.append("- **Return Type**: ").append(function.getReturnType().getName()).append("\n\n");
                
                // Find callers
                ReferenceManager refManager = program.getReferenceManager();
                // Convert iterator to list
                List<Reference> references = new ArrayList<>();
                refManager.getReferencesTo(function.getEntryPoint()).forEach(ref -> references.add(ref));
                
                docBuilder.append("## Called By\n");
                if (references.isEmpty()) {
                    docBuilder.append("- No callers found\n\n");
                } else {
                    int callersToShow = Math.min(references.size(), 5);
                    for (int i = 0; i < callersToShow; i++) {
                        Reference ref = references.get(i);
                        Function callingFunction = program.getListing().getFunctionContaining(ref.getFromAddress());
                        if (callingFunction != null) {
                            docBuilder.append("- ").append(callingFunction.getName())
                                     .append(" at ").append(ref.getFromAddress()).append("\n");
                        }
                    }
                    if (references.size() > 5) {
                        docBuilder.append("- ... and ").append(references.size() - 5).append(" more callers\n");
                    }
                    docBuilder.append("\n");
                }
                
                // Find callees - use listing instead of getInstructions which may not be available
                docBuilder.append("## Calls\n");
                List<Function> callees = new ArrayList<>();
                
                // Get the address set for the function body
                Listing listing = program.getListing();
                listing.getInstructions(function.getBody(), true).forEach(inst -> {
                    Reference[] refs = inst.getReferencesFrom();
                    for (Reference ref : refs) {
                        if (ref.getReferenceType().isCall()) {
                            Function calledFunction = program.getListing().getFunctionAt(ref.getToAddress());
                            if (calledFunction != null) {
                                callees.add(calledFunction);
                            }
                        }
                    }
                });
                
                if (callees.isEmpty()) {
                    docBuilder.append("- No function calls found\n\n");
                } else {
                    for (Function callee : callees) {
                        docBuilder.append("- ").append(callee.getName())
                                 .append(" at ").append(callee.getEntryPoint()).append("\n");
                    }
                    docBuilder.append("\n");
                }
                
                // Extract local variables
                Variable[] localVars = function.getLocalVariables();
                if (localVars.length > 0) {
                    docBuilder.append("## Local Variables\n");
                    for (Variable var : localVars) {
                        docBuilder.append("- ").append(var.getDataType().getName())
                                 .append(" ").append(var.getName());
                        if (var.getComment() != null) {
                            docBuilder.append(" // ").append(var.getComment());
                        }
                        docBuilder.append("\n");
                    }
                    docBuilder.append("\n");
                }
                
                // Include decompiled code
                docBuilder.append("## Decompiled Code\n");
                docBuilder.append("```c\n");
                docBuilder.append(decompCode);
                docBuilder.append("\n```\n\n");
                
                // Show confirmation dialog
                int result = JOptionPane.showConfirmDialog(
                    null,
                    "Generate documentation for function '" + function.getName() + "'?",
                    "Confirm Documentation Generation",
                    JOptionPane.YES_NO_OPTION
                );
                
                Msg.info(GhidraToolsService.class, "Documentation dialog result: " + (result == JOptionPane.YES_OPTION ? "YES" : "NO"));
                
                if (result == JOptionPane.YES_OPTION) {
                    int transactionID = program.startTransaction("Generate Function Documentation");
                    boolean success = false;
                    
                    try {
                        Msg.info(GhidraToolsService.class, "Starting documentation generation transaction");
                        
                        // In a real implementation, we would potentially update comments
                        // in the function or save the documentation to a file.
                        // For now, just return the documentation as text.
                        
                        Msg.info(GhidraToolsService.class, "Documentation generated successfully");
                        success = true;
                        
                        future.complete(docBuilder.toString());
                        
                    } catch (Exception e) {
                        Msg.error(GhidraToolsService.class, "Error generating documentation: " + e.getMessage(), e);
                        future.complete("Error: Could not generate documentation: " + e.getMessage());
                    } finally {
                        Msg.info(GhidraToolsService.class, "Ending documentation generation transaction with success=" + success);
                        program.endTransaction(transactionID, success);
                    }
                } else {
                    Msg.info(GhidraToolsService.class, "Documentation generation cancelled by user");
                    future.complete("Documentation generation cancelled by user");
                }
                
            } catch (Exception e) {
                Msg.error(GhidraToolsService.class, "Error generating documentation: " + e.getMessage(), e);
                future.complete("Error generating documentation: " + e.getMessage());
            }
        });
        
        return future;
    }
    
    /**
     * Analyzes data flow for a variable.
     * 
     * @param program The current program
     * @param function The function containing the variable
     * @param varName The name of the variable to analyze (optional)
     * @return A CompletableFuture containing the result message
     */
    public static CompletableFuture<String> analyzeDataFlow(Program program, Function function, String varName) {
        CompletableFuture<String> future = new CompletableFuture<>();
        
        if (program == null || function == null) {
            Msg.error(GhidraToolsService.class, "Program or function is null");
            future.complete("Error: No program or function selected");
            return future;
        }
        
        Msg.info(GhidraToolsService.class, String.format(
            "Analyzing data flow in function: %s%s",
            function.getName(), varName != null ? " for variable: " + varName : ""
        ));
        
        SwingUtilities.invokeLater(() -> {
            try {
                // This would be a complex data flow analysis implementation
                // For now, we'll provide a simplified placeholder that analyzes decompiled output
                
                // First use the decompiler to get high-level representation
                DecompInterface decompiler = new DecompInterface();
                decompiler.openProgram(program);
                DecompileOptions options = new DecompileOptions();
                decompiler.setOptions(options);
                
                DecompileResults results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
                if (!results.decompileCompleted()) {
                    Msg.error(GhidraToolsService.class, "Decompilation failed: " + results.getErrorMessage());
                    future.complete("Error: Could not decompile function to analyze data flow");
                    return;
                }
                
                String decompCode = results.getDecompiledFunction().getC();
                
                // If a specific variable was given, focus on that
                Variable targetVar = null;
                if (varName != null) {
                    Variable[] vars = function.getAllVariables();
                    for (Variable var : vars) {
                        if (var.getName().equals(varName)) {
                            targetVar = var;
                            break;
                        }
                    }
                    
                    if (targetVar == null) {
                        Msg.error(GhidraToolsService.class, "Variable not found: " + varName);
                        future.complete("Error: Variable not found: " + varName);
                        return;
                    }
                }
                
                // Build data flow analysis (placeholder implementation)
                StringBuilder flowBuilder = new StringBuilder();
                flowBuilder.append("# Data Flow Analysis");
                
                if (targetVar != null) {
                    flowBuilder.append(" for Variable: ").append(targetVar.getName());
                }
                flowBuilder.append("\n\n");
                
                // Add metadata
                flowBuilder.append("## Function: ").append(function.getName()).append("\n");
                flowBuilder.append("- **Address**: ").append(function.getEntryPoint()).append("\n");
                flowBuilder.append("- **Return Type**: ").append(function.getReturnType().getName()).append("\n\n");
                
                if (targetVar != null) {
                    // Analyze specific variable
                    flowBuilder.append("## Analysis of '").append(targetVar.getName()).append("'\n");
                    flowBuilder.append("- **Type**: ").append(targetVar.getDataType().getName()).append("\n");
                    
                    // Do a simple string search in the decompiled code
                    flowBuilder.append("- **Occurrences**: ");
                    String[] lines = decompCode.split("\n");
                    int occurrences = 0;
                    List<String> usageLines = new ArrayList<>();
                    
                    for (String line : lines) {
                        if (line.contains(targetVar.getName())) {
                            occurrences++;
                            usageLines.add(line.trim());
                        }
                    }
                    
                    flowBuilder.append(occurrences).append("\n\n");
                    
                    // Identify variable usage patterns (very simplified)
                    flowBuilder.append("## Usage Patterns\n");
                    boolean isInput = false;
                    boolean isOutput = false;
                    boolean isModified = false;
                    boolean isReturned = false;
                    boolean isPassedToFunction = false;
                    
                    for (String line : usageLines) {
                        if (line.matches(".*" + targetVar.getName() + "\\s*=.*")) {
                            isModified = true;
                            if (line.matches(".*=\\s*[^;]*\\(.*\\).*")) {
                                isInput = true;
                            }
                        }
                        
                        if (line.matches(".*return\\s+[^;]*" + targetVar.getName() + ".*")) {
                            isReturned = true;
                            isOutput = true;
                        }
                        
                        if (line.matches(".*\\([^)]*" + targetVar.getName() + "[^)]*\\).*")) {
                            isPassedToFunction = true;
                        }
                    }
                    
                    flowBuilder.append("- **Role**: ");
                    if (isInput) flowBuilder.append("Input ");
                    if (isOutput) flowBuilder.append("Output ");
                    if (!isInput && !isOutput) flowBuilder.append("Internal ");
                    flowBuilder.append("\n");
                    
                    flowBuilder.append("- **Behaviors**:\n");
                    if (isModified) flowBuilder.append("  - Modified within function\n");
                    if (isReturned) flowBuilder.append("  - Returned from function\n");
                    if (isPassedToFunction) flowBuilder.append("  - Passed to other functions\n");
                    
                    flowBuilder.append("\n## Usage Examples\n");
                    int maxExamples = Math.min(usageLines.size(), 5);
                    for (int i = 0; i < maxExamples; i++) {
                        flowBuilder.append("- `").append(usageLines.get(i)).append("`\n");
                    }
                    
                    if (usageLines.size() > 5) {
                        flowBuilder.append("- ... and ").append(usageLines.size() - 5).append(" more occurrences\n");
                    }
                    
                } else {
                    // General data flow for the function
                    flowBuilder.append("## General Data Flow\n");
                    
                    // Identify input/output variables
                    Variable[] allVars = function.getAllVariables();
                    // Use getParameterCount and getParameter instead of getParameters
                    int paramCount = function.getParameterCount();
                    
                    flowBuilder.append("### Inputs\n");
                    for (int i = 0; i < paramCount; i++) {
                        Variable param = function.getParameter(i);
                        flowBuilder.append("- ").append(param.getDataType().getName())
                                 .append(" ").append(param.getName()).append("\n");
                    }
                    
                    // Find functions called that might affect data flow
                    flowBuilder.append("\n### Function Calls\n");
                    List<String> calledFunctionNames = new ArrayList<>();
                    
                    // Use program.getListing() to get instructions instead of directly from function
                    Listing listing = program.getListing();
                    listing.getInstructions(function.getBody(), true).forEach(inst -> {
                        Reference[] refs = inst.getReferencesFrom();
                        for (Reference ref : refs) {
                            if (ref.getReferenceType().isCall()) {
                                Function calledFunction = program.getListing().getFunctionAt(ref.getToAddress());
                                if (calledFunction != null) {
                                    calledFunctionNames.add(calledFunction.getName());
                                }
                            }
                        }
                    });
                    
                    if (calledFunctionNames.isEmpty()) {
                        flowBuilder.append("- No function calls found\n");
                    } else {
                        for (String name : calledFunctionNames) {
                            flowBuilder.append("- ").append(name).append("\n");
                        }
                    }
                    
                    // Simplistic output identification
                    flowBuilder.append("\n### Outputs\n");
                    flowBuilder.append("- Return type: ").append(function.getReturnType().getName()).append("\n");
                    
                    // Identify variables that might be outputs by looking for reference parameters
                    for (int i = 0; i < paramCount; i++) {
                        Variable param = function.getParameter(i);
                        if (param.getDataType().getName().contains("*") ||
                            param.getDataType().getName().contains("&")) {
                            flowBuilder.append("- Potential output parameter: ")
                                     .append(param.getName()).append("\n");
                        }
                    }
                }
                
                flowBuilder.append("\n## Notes\n");
                flowBuilder.append("- This is a simplified analysis. A full data flow analysis would trace values through the code.\n");
                flowBuilder.append("- For more accurate results, consider using Ghidra's built-in data flow analysis tools manually.\n");
                
                future.complete(flowBuilder.toString());
                
            } catch (Exception e) {
                Msg.error(GhidraToolsService.class, "Error analyzing data flow: " + e.getMessage(), e);
                future.complete("Error analyzing data flow: " + e.getMessage());
            }
        });
        
        return future;
    }
    
    /**
     * Detects potential vulnerabilities in a function.
     * 
     * @param program The current program
     * @param function The function to analyze for vulnerabilities
     * @return A CompletableFuture containing the result message
     */
    public static CompletableFuture<String> detectVulnerabilities(Program program, Function function) {
        CompletableFuture<String> future = new CompletableFuture<>();
        
        if (program == null || function == null) {
            Msg.error(GhidraToolsService.class, "Program or function is null");
            future.complete("Error: No program or function selected");
            return future;
        }
        
        Msg.info(GhidraToolsService.class, "Detecting vulnerabilities in function: " + function.getName());
        
        SwingUtilities.invokeLater(() -> {
            try {
                // This would be a complex vulnerability detection implementation
                // For now, we'll provide a simplified placeholder that looks for common risky functions
                
                // Get decompiled code for analysis
                DecompInterface decompiler = new DecompInterface();
                decompiler.openProgram(program);
                DecompileOptions options = new DecompileOptions();
                decompiler.setOptions(options);
                
                DecompileResults results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
                if (!results.decompileCompleted()) {
                    Msg.error(GhidraToolsService.class, "Decompilation failed: " + results.getErrorMessage());
                    future.complete("Error: Could not decompile function to detect vulnerabilities");
                    return;
                }
                
                String decompCode = results.getDecompiledFunction().getC().toLowerCase();
                
                // List of potentially vulnerable functions and patterns
                String[][] vulnerablePatterns = {
                    {"strcpy", "String copy without bounds checking", "CWE-120", "Use strncpy or equivalent instead"},
                    {"strcat", "String concatenation without bounds checking", "CWE-120", "Use strncat or equivalent instead"},
                    {"sprintf", "Format string potentially vulnerable", "CWE-134", "Use snprintf or equivalent instead"},
                    {"gets", "Unbounded read from stdin", "CWE-242", "Use fgets or equivalent instead"},
                    {"memcpy", "Memory copy operation that might overflow", "CWE-119", "Ensure bounds are properly checked"},
                    {"malloc", "Memory allocation without validation", "CWE-789", "Validate allocation size and check return value"},
                    {"free", "Memory free operation that might be double-freed", "CWE-415", "Ensure proper tracking of memory allocations"},
                    {"system", "Command execution vulnerability", "CWE-78", "Avoid system() or sanitize inputs thoroughly"},
                    {"exec", "Command execution vulnerability", "CWE-78", "Avoid exec functions or sanitize inputs thoroughly"},
                    {"printf.*%s", "Format string vulnerability", "CWE-134", "Ensure format string is hardcoded"},
                    {"scanf", "Input validation vulnerability", "CWE-20", "Validate input and use bounded input functions"},
                };
                
                List<String[]> detectedVulnerabilities = new ArrayList<>();
                
                // Check for vulnerable patterns
                for (String[] pattern : vulnerablePatterns) {
                    if (decompCode.contains(pattern[0]) || decompCode.matches(".*" + pattern[0] + ".*")) {
                        detectedVulnerabilities.add(pattern);
                    }
                }
                
                // Check for integer overflow
                if (decompCode.contains("+=") || decompCode.contains("++") ||
                    decompCode.contains("*=") || decompCode.contains("*") ||
                    (decompCode.contains("add") && decompCode.contains("overflow"))) {
                    if (!decompCode.contains("check") && !decompCode.contains("bounds") &&
                        !decompCode.contains("limit") && !decompCode.contains("valid")) {
                        detectedVulnerabilities.add(new String[] {
                            "int-overflow", "Potential integer overflow/underflow", "CWE-190",
                            "Check for arithmetic overflow/underflow conditions"
                        });
                    }
                }
                
                // Buffer operations without bounds checks
                if ((decompCode.contains("buffer") || decompCode.contains("array") || decompCode.contains("[")) &&
                    !decompCode.contains("check") && !decompCode.contains("bounds") && 
                    !decompCode.contains("limit") && !decompCode.contains("size")) {
                    detectedVulnerabilities.add(new String[] {
                        "buffer-access", "Potential buffer access without bounds checking", "CWE-120",
                        "Validate array indices and ensure proper bounds checking"
                    });
                }
                
                // Format the results
                StringBuilder resultBuilder = new StringBuilder();
                resultBuilder.append("# Vulnerability Analysis for Function: ").append(function.getName()).append("\n\n");
                
                if (detectedVulnerabilities.isEmpty()) {
                    resultBuilder.append("No common vulnerabilities detected in basic pattern analysis.\n\n");
                } else {
                    resultBuilder.append("## Potential Vulnerabilities\n");
                    resultBuilder.append("*Note: These are potential issues based on pattern matching and require manual verification.*\n\n");
                    
                    for (String[] vuln : detectedVulnerabilities) {
                        resultBuilder.append("### ").append(vuln[1]).append("\n");
                        resultBuilder.append("- **Pattern**: ").append(vuln[0]).append("\n");
                        resultBuilder.append("- **CWE**: ").append(vuln[2]).append("\n");
                        resultBuilder.append("- **Recommendation**: ").append(vuln[3]).append("\n\n");
                    }
                }
                
                // Additional notes for better understanding
                resultBuilder.append("## Analysis Notes\n");
                resultBuilder.append("- This is a basic pattern-matching analysis and may produce false positives.\n");
                resultBuilder.append("- Manual code review is still recommended for thorough vulnerability assessment.\n");
                resultBuilder.append("- Consider using specialized security analysis tools for production software.\n");
                
                future.complete(resultBuilder.toString());
                
            } catch (Exception e) {
                Msg.error(GhidraToolsService.class, "Error detecting vulnerabilities: " + e.getMessage(), e);
                future.complete("Error detecting vulnerabilities: " + e.getMessage());
            }
        });
        
        return future;
    }
    
    /**
     * Identifies VTable structures and class hierarchies.
     * 
     * @param program The current program
     * @param addressString The address to check for a VTable (optional)
     * @return A CompletableFuture containing the result message
     */
    public static CompletableFuture<String> identifyVTable(Program program, String addressString) {
        CompletableFuture<String> future = new CompletableFuture<>();
        
        if (program == null) {
            Msg.error(GhidraToolsService.class, "Program is null");
            future.complete("Error: No program selected");
            return future;
        }
        
        Msg.info(GhidraToolsService.class, "Identifying VTables" + 
                (addressString != null ? " at address: " + addressString : ""));
        
        SwingUtilities.invokeLater(() -> {
            try {
                Address targetAddress = null;
                
                // Parse the address if provided
                if (addressString != null) {
                    try {
                        AddressFactory addressFactory = program.getAddressFactory();
                        targetAddress = addressFactory.getAddress(addressString);
                    } catch (Exception e) {
                        Msg.error(GhidraToolsService.class, "Invalid address: " + addressString);
                        future.complete("Error: Invalid address: " + addressString);
                        return;
                    }
                }
                
                StringBuilder resultBuilder = new StringBuilder();
                resultBuilder.append("# VTable Analysis");
                if (targetAddress != null) {
                    resultBuilder.append(" at ").append(addressString);
                }
                resultBuilder.append("\n\n");
                
                // This would be a complex VTable analysis implementation
                // For now, we'll provide a simplified placeholder
                
                // Heuristics for VTable identification:
                // 1. Look for tables of function pointers
                // 2. Look for references to these tables (potential objects)
                
                resultBuilder.append("## Identified VTable Candidates\n");
                
                // For a specific address, analyze just that
                if (targetAddress != null) {
                    boolean isVTable = analyzeVTableCandidate(program, targetAddress, resultBuilder);
                    if (!isVTable) {
                        resultBuilder.append("The address ").append(addressString)
                                   .append(" does not appear to be a VTable based on heuristic analysis.\n");
                    }
                } else {
                    // General search - in a real implementation, this would be more sophisticated
                    resultBuilder.append("*Note: Generic VTable detection not implemented in this simplified version.\n");
                    resultBuilder.append("Please specify an address to analyze for VTable characteristics.*\n\n");
                    
                    resultBuilder.append("## VTable Detection Criteria\n");
                    resultBuilder.append("For a thorough VTable analysis, look for:\n");
                    resultBuilder.append("1. Tables of function pointers in read-only memory sections\n");
                    resultBuilder.append("2. Objects with pointers to these tables in constructors\n");
                    resultBuilder.append("3. Inheritance patterns in the code\n");
                    resultBuilder.append("4. Virtual function call patterns (accessing functions via offsets from a table)\n\n");
                    
                    resultBuilder.append("## Manual Analysis Recommendation\n");
                    resultBuilder.append("To identify VTables manually:\n");
                    resultBuilder.append("1. Look for C++ constructor functions (they often set up VTable pointers)\n");
                    resultBuilder.append("2. Find places where an object pointer's first member is set to an address\n");
                    resultBuilder.append("3. Follow those addresses to see if they point to tables of function pointers\n");
                }
                
                future.complete(resultBuilder.toString());
                
            } catch (Exception e) {
                Msg.error(GhidraToolsService.class, "Error identifying VTable: " + e.getMessage(), e);
                future.complete("Error identifying VTable: " + e.getMessage());
            }
        });
        
        return future;
    }
    
    /**
     * Helper method to analyze a potential VTable candidate.
     * 
     * @param program The current program
     * @param address The address to analyze
     * @param builder StringBuilder to append results to
     * @return True if the address appears to be a VTable, false otherwise
     */
    private static boolean analyzeVTableCandidate(Program program, Address address, StringBuilder builder) {
        try {
            Listing listing = program.getListing();
            int pointerSize = program.getDefaultPointerSize();
            int maxFunctions = 10; // Maximum number of functions to check
            boolean isVTable = true;
            List<Function> vtableFunctions = new ArrayList<>();
            
            // Check for a sequence of pointers to code
            for (int i = 0; i < maxFunctions; i++) {
                Address currentAddress = address.add(i * pointerSize);
                if (!listing.isUndefined(currentAddress, currentAddress.add(pointerSize - 1))) {
                    // This might be data that's already defined as something else
                    if (i == 0) {
                        // First entry isn't even a pointer - probably not a VTable
                        isVTable = false;
                        break;
                    } else {
                        // We found some potential functions, but the table ends here
                        break;
                    }
                }
                
                // Try to get the pointer value
                byte[] bytes = new byte[pointerSize];
                if (program.getMemory().getBytes(currentAddress, bytes) != pointerSize) {
                    // Couldn't read memory
                    if (i == 0) {
                        isVTable = false;
                    }
                    break;
                }
                
                // Convert bytes to address
                Address targetAddress = null;
                if (pointerSize == 4) {
                    int value = 0;
                    for (int j = 0; j < 4; j++) {
                        value |= (bytes[j] & 0xFF) << (j * 8);
                    }
                    targetAddress = program.getAddressFactory().getAddress(Integer.toHexString(value));
                } else if (pointerSize == 8) {
                    // 64-bit pointer handling would go here
                    // This is simplified for brevity
                }
                
                if (targetAddress == null) {
                    if (i == 0) {
                        isVTable = false;
                    }
                    break;
                }
                
                // Check if the target is a function
                Function func = listing.getFunctionAt(targetAddress);
                if (func == null) {
                    // Not pointing to a function
                    if (i == 0) {
                        // First entry doesn't point to function - probably not a VTable
                        isVTable = false;
                        break;
                    }
                } else {
                    vtableFunctions.add(func);
                }
            }
            
            if (isVTable && !vtableFunctions.isEmpty()) {
                builder.append("VTable candidate found at: ").append(address).append("\n\n");
                builder.append("Function entries:\n");
                
                for (int i = 0; i < vtableFunctions.size(); i++) {
                    Function func = vtableFunctions.get(i);
                    builder.append("- [").append(i).append("] ");
                    builder.append(func.getName()).append(" at ").append(func.getEntryPoint()).append("\n");
                }
                
                // Check for references to this VTable (potential constructors)
                builder.append("\nReferences to this VTable:\n");
                ReferenceManager refManager = program.getReferenceManager();
                // Convert iterator to list
                List<Reference> references = new ArrayList<>();
                refManager.getReferencesTo(address).forEach(ref -> references.add(ref));
                
                if (references.isEmpty()) {
                    builder.append("- No references found\n");
                } else {
                    int refsToShow = Math.min(references.size(), 5);
                    for (int i = 0; i < refsToShow; i++) {
                        Reference ref = references.get(i);
                        Function containingFunction = program.getListing().getFunctionContaining(ref.getFromAddress());
                        if (containingFunction != null) {
                            builder.append("- From function: ").append(containingFunction.getName());
                            builder.append(" at ").append(ref.getFromAddress()).append("\n");
                            
                            // Check if this might be a constructor
                            if (containingFunction.getName().contains("_construct") ||
                                containingFunction.getName().contains("_init") ||
                                containingFunction.getName().contains("New")) {
                                builder.append("  (Potential constructor/initialization function)\n");
                            }
                        } else {
                            builder.append("- From address: ").append(ref.getFromAddress()).append("\n");
                        }
                    }
                }
                
                builder.append("\nNote: This analysis is based on simple heuristics and might not be accurate.\n");
                builder.append("A more thorough analysis would include identifying class hierarchy and virtual function call patterns.\n");
                
                return true;
            } else {
                return false;
            }
            
        } catch (Exception e) {
            builder.append("Error analyzing potential VTable: ").append(e.getMessage()).append("\n");
            return false;
        }
    }
    
    /**
     * Finds a function by name and then finds cross-references to it.
     * 
     * @param program The current program
     * @param functionName The name of the function to find and get references to
     * @param tool The Ghidra plugin tool
     * @return A CompletableFuture containing the result message
     */
    public static CompletableFuture<String> findFunctionAndReferences(Program program, String functionName, PluginTool tool) {
        CompletableFuture<String> future = new CompletableFuture<>();
        
        if (program == null) {
            Msg.error(GhidraToolsService.class, "Program is null");
            future.complete("Error: No program selected");
            return future;
        }
        
        Msg.info(GhidraToolsService.class, "Finding function by name: " + functionName + " and then finding references");
        
        SwingUtilities.invokeLater(() -> {
            try {
                // Find the function by name
                FunctionManager functionManager = program.getFunctionManager();
                Function targetFunction = null;
                
                // Iterate through all functions
                for (Function function : functionManager.getFunctions(true)) {
                    if (function.getName().equals(functionName)) {
                        targetFunction = function;
                        break;
                    }
                }
                
                if (targetFunction == null) {
                    // Try with case-insensitive comparison
                    for (Function function : functionManager.getFunctions(true)) {
                        if (function.getName().equalsIgnoreCase(functionName)) {
                            targetFunction = function;
                            break;
                        }
                    }
                }
                
                if (targetFunction == null) {
                    // Try with partial match
                    for (Function function : functionManager.getFunctions(true)) {
                        if (function.getName().contains(functionName)) {
                            targetFunction = function;
                            break;
                        }
                    }
                }
                
                if (targetFunction == null) {
                    future.complete("Error: Could not find function with name '" + functionName + "'");
                    return;
                }
                
                // Found the function, now find references to it
                Function function = targetFunction;
                ReferenceManager refManager = program.getReferenceManager();
                Address functionAddress = function.getEntryPoint();
                
                // Use iterator instead of trying to get as array
                List<Reference> references = new ArrayList<>();
                refManager.getReferencesTo(functionAddress).forEach(ref -> references.add(ref));
                
                if (references.isEmpty()) {
                    future.complete("No references found to function: " + function.getName());
                    return;
                }
                
                StringBuilder resultBuilder = new StringBuilder();
                resultBuilder.append("References to function ").append(function.getName()).append(":\n");
                
                int maxToShow = Math.min(references.size(), 10);
                for (int i = 0; i < maxToShow; i++) {
                    Reference ref = references.get(i);
                    resultBuilder.append("- From: ").append(ref.getFromAddress());
                    
                    // Try to get the function containing the reference
                    Function fromFunction = program.getListing().getFunctionContaining(ref.getFromAddress());
                    if (fromFunction != null) {
                        resultBuilder.append(" (in function ").append(fromFunction.getName()).append(")");
                    }
                    
                    resultBuilder.append("\n");
                }
                
                if (references.size() > 10) {
                    resultBuilder.append("... and ").append(references.size() - 10).append(" more references.");
                }
                
                future.complete(resultBuilder.toString());
                
            } catch (Exception e) {
                Msg.error(GhidraToolsService.class, "Error finding function references: " + e.getMessage(), e);
                future.complete("Error finding function references: " + e.getMessage());
            }
        });
        
        return future;
    }
}
