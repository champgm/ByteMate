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
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

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
                    // Since Function.setComment only takes a single string parameter,
                    // we need to prefix the comment with the type information
                    String formattedComment = "[" + commentType.toUpperCase() + "] " + comment;
                    String existingComment = function.getComment();
                    Msg.debug(GhidraToolsService.class, "Existing comment: " + (existingComment == null ? "null" : existingComment));
                    
                    function.setComment(formattedComment);
                    Msg.info(GhidraToolsService.class, "Comment added successfully");
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
} 
