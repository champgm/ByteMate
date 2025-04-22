/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package bytemate;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.text.BadLocationException;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import docking.widgets.label.GLabel;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.util.ProgramLocation;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import resources.Icons;

// Tools import
import bytemate.tools.GhidraToolsService;
import bytemate.tools.ToolCommandParser;

/**
 * ByteMate Plugin with ByteMate window
 */
//@formatter:off
@PluginInfo(
  status = PluginStatus.STABLE,
  packageName = ExamplesPluginPackage.NAME,
  category = PluginCategoryNames.EXAMPLES,
  shortDescription = "ByteMate LLM Assistant",
  description = "Plugin that adds an LLM-powered assistant for reverse engineering tasks."
)
//@formatter:on
public class ByteMatePlugin extends ProgramPlugin {

  ByteMateProvider provider;

  /**
   * Plugin constructor.
   * 
   * @param tool The plugin tool that this plugin is added to.
   */
  public ByteMatePlugin(PluginTool tool) {
    super(tool);

    // Add debug output to verify plugin loading
    System.out.println("ByteMatePlugin is being loaded!");
    Msg.info(this, "ByteMatePlugin is being loaded!");

    // Create the provider
    String pluginName = getName();
    provider = new ByteMateProvider(this, pluginName);

    // Create the menu action
    createActions();

    // Set help
    String topicName = this.getClass().getPackage().getName();
    String anchorName = "HelpAnchor";
    provider.setHelpLocation(new HelpLocation(topicName, anchorName));
  }

  private void createActions() {
    DockingAction action = new DockingAction("ByteMate", getName()) {
      @Override
      public void actionPerformed(ActionContext context) {
        System.out.println("ByteMatePlugin: actionPerformed was called");
        // Make the provider visible when the action is triggered
        tool.showComponentProvider(provider, true);
      }
    };

    // Add this action to the Window menu
    action.setMenuBarData(new MenuData(new String[] { "Window", "ByteMate" }, null, "ByteMateGroup"));
    action.setEnabled(true);
    action.markHelpUnnecessary();

    // Register the action with the tool
    tool.addAction(action);

    // Add debug output to verify action registration
    System.out.println("ByteMatePlugin: Added ByteMate action to Window menu PRINTLN ");
    Msg.info(this, "ByteMatePlugin: Added ByteMate action to Window menu MSGINFO");
  }

  @Override
  public void init() {
    super.init();
  }
  
  @Override
  protected void programActivated(Program program) {
    super.programActivated(program);
    provider.updateProgramContext(program);
  }
  
  @Override
  protected void programDeactivated(Program program) {
    super.programDeactivated(program);
    provider.clearProgramContext();
  }
  
  @Override
  protected void locationChanged(ProgramLocation loc) {
    super.locationChanged(loc);
    if (loc != null && currentProgram != null) {
      provider.updateFunctionContext(loc);
    }
  }

  // ByteMate provider to display the chat interface
  private static class ByteMateProvider extends ComponentProvider {

    private JPanel mainPanel;
    private JTextPane chatPane;
    private JTextArea inputArea;
    private JButton sendButton;
    private JComboBox<String> modelSelector;
    private JButton settingsButton;
    private JPanel contextPanel;
    private JLabel functionContextLabel;
    private JLabel programContextLabel;
    private List<ChatMessage> chatHistory = new ArrayList<>();
    private Map<String, Map<String, String>> modelConfigs = new HashMap<>();
    
    // Context tracking
    private Program currentProgram;
    private Function currentFunction;
    private String currentDecompiledCode;
    
    // Command tracking
    private boolean processingCommand = false;
    private JCheckBox enableToolsCheckbox;
    
    // Store reference to parent plugin and its tool
    private ByteMatePlugin plugin;
    private PluginTool pluginTool;

    // LLM Provider options
    private static final String[] PROVIDERS = {"OpenAI", "Claude", "Google"};
    private static final String[] OPENAI_MODELS = {"gpt-4o", "gpt-4-turbo", "gpt-3.5-turbo"};
    private static final String[] CLAUDE_MODELS = {"claude-3-opus", "claude-3-sonnet", "claude-3-haiku"};
    private static final String[] GOOGLE_MODELS = {"gemini-pro", "gemini-ultra"};
    
    private String currentProvider = PROVIDERS[0];
    private String[] currentModels = OPENAI_MODELS;
    private String currentModel = OPENAI_MODELS[0];

    public ByteMateProvider(Plugin plugin, String owner) {
      super(plugin.getTool(), "ByteMate", owner);
      this.plugin = (ByteMatePlugin) plugin;
      this.pluginTool = plugin.getTool();
      initializeModelConfigs();
      buildPanel();
      loadSettings(); // Load saved settings
      setVisible(true);
    }

    private void initializeModelConfigs() {
      // Initialize with default values - these would be persisted in user preferences
      for (String provider : PROVIDERS) {
        modelConfigs.put(provider, new HashMap<>());
        modelConfigs.get(provider).put("api_key", "");
      }
    }

    // Build the UI
    private void buildPanel() {
      mainPanel = new JPanel(new BorderLayout());
      mainPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
      
      // Top panel with model selector and settings
      JPanel topPanel = new JPanel(new BorderLayout());
      
      JPanel selectorPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
      modelSelector = new JComboBox<>(OPENAI_MODELS);
      
      JComboBox<String> providerSelector = new JComboBox<>(PROVIDERS);
      providerSelector.addActionListener(e -> {
        currentProvider = (String) providerSelector.getSelectedItem();
        updateModelSelector();
      });
      
      selectorPanel.add(new JLabel("Provider:"));
      selectorPanel.add(providerSelector);
      selectorPanel.add(new JLabel("Model:"));
      selectorPanel.add(modelSelector);
      
      // Add tools checkbox
      enableToolsCheckbox = new JCheckBox("Enable Tools", true);
      enableToolsCheckbox.setToolTipText("Allow the LLM to perform actions on the codebase");
      selectorPanel.add(enableToolsCheckbox);
      
      // Add View Tools button
      JButton viewToolsButton = new JButton("View Tools");
      viewToolsButton.setToolTipText("View available tools that the LLM can use");
      viewToolsButton.addActionListener(e -> showAvailableTools());
      selectorPanel.add(viewToolsButton);
      
      JPanel actionPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
      
      JButton clearButton = new JButton("Clear Chat");
      clearButton.addActionListener(e -> {
        int result = JOptionPane.showConfirmDialog(
            mainPanel,
            "Are you sure you want to clear the chat history?",
            "Confirm Clear",
            JOptionPane.YES_NO_OPTION
        );
        
        if (result == JOptionPane.YES_OPTION) {
          chatHistory.clear();
          updateChatDisplay();
          saveSettings(); // Save empty chat history
        }
      });
      
      settingsButton = new JButton("Settings");
      settingsButton.addActionListener(e -> showSettingsDialog());
      
      actionPanel.add(clearButton);
      actionPanel.add(settingsButton);
      
      topPanel.add(selectorPanel, BorderLayout.WEST);
      topPanel.add(actionPanel, BorderLayout.EAST);
      
      // Context panel to show current function
      contextPanel = new JPanel(new BorderLayout());
      contextPanel.setBorder(BorderFactory.createTitledBorder("Current Context"));
      
      programContextLabel = new JLabel("Program: Not loaded");
      programContextLabel.setBorder(new EmptyBorder(2, 5, 2, 5));
      
      functionContextLabel = new JLabel("Function: None selected");
      functionContextLabel.setBorder(new EmptyBorder(2, 5, 2, 5));
      
      JPanel contextLabelsPanel = new JPanel(new GridBagLayout());
      GridBagConstraints gbc = new GridBagConstraints();
      gbc.gridx = 0;
      gbc.gridy = 0;
      gbc.fill = GridBagConstraints.HORIZONTAL;
      gbc.weightx = 1.0;
      gbc.insets = new Insets(2, 2, 2, 2);
      
      contextLabelsPanel.add(programContextLabel, gbc);
      
      gbc.gridy = 1;
      contextLabelsPanel.add(functionContextLabel, gbc);
      
      contextPanel.add(contextLabelsPanel, BorderLayout.CENTER);
      
      topPanel.add(contextPanel, BorderLayout.SOUTH);
      
      // Chat display area
      chatPane = new JTextPane();
      chatPane.setEditable(false);
      JScrollPane chatScrollPane = new JScrollPane(chatPane);
      chatScrollPane.setPreferredSize(new Dimension(600, 400));
      
      // Add context menu to chat pane
      JPopupMenu chatContextMenu = new JPopupMenu();
      JMenuItem copyItem = new JMenuItem("Copy");
      copyItem.addActionListener(e -> {
        if (chatPane.getSelectedText() != null) {
          chatPane.copy();
        }
      });
      
      JMenuItem copyCodeItem = new JMenuItem("Copy Code Block");
      copyCodeItem.addActionListener(e -> {
        String selectedText = chatPane.getSelectedText();
        if (selectedText != null) {
          // Try to extract a code block if it exists
          extractAndCopyCodeBlock(selectedText);
        } else {
          // Try to find and copy the closest code block to the cursor
          int caretPosition = chatPane.getCaretPosition();
          StyledDocument doc = chatPane.getStyledDocument();
          String text;
          try {
            text = doc.getText(0, doc.getLength());
            extractAndCopyNearestCodeBlock(text, caretPosition);
          } catch (BadLocationException ex) {
            Msg.error(this, "Error extracting text: " + ex.getMessage());
          }
        }
      });
      
      chatContextMenu.add(copyItem);
      chatContextMenu.add(copyCodeItem);
      chatPane.setComponentPopupMenu(chatContextMenu);
      
      // Input area
      inputArea = new JTextArea(4, 50);
      inputArea.setLineWrap(true);
      inputArea.setWrapStyleWord(true);
      JScrollPane inputScrollPane = new JScrollPane(inputArea);
      
      // Send button
      sendButton = new JButton("Send");
      sendButton.addActionListener(e -> sendMessage());
      
      // Input panel with text area and send button
      JPanel inputPanel = new JPanel(new BorderLayout());
      inputPanel.add(inputScrollPane, BorderLayout.CENTER);
      inputPanel.add(sendButton, BorderLayout.EAST);
      
      // Add all components to the main panel
      mainPanel.add(topPanel, BorderLayout.NORTH);
      mainPanel.add(chatScrollPane, BorderLayout.CENTER);
      mainPanel.add(inputPanel, BorderLayout.SOUTH);
    }
    
    private void updateModelSelector() {
      modelSelector.removeAllItems();
      
      switch (currentProvider) {
        case "OpenAI":
          currentModels = OPENAI_MODELS;
          break;
        case "Claude":
          currentModels = CLAUDE_MODELS;
          break;
        case "Google":
          currentModels = GOOGLE_MODELS;
          break;
      }
      
      for (String model : currentModels) {
        modelSelector.addItem(model);
      }
      
      currentModel = currentModels[0];
    }
    
    private void showSettingsDialog() {
      JDialog settingsDialog = new JDialog();
      settingsDialog.setTitle("ByteMate Settings");
      settingsDialog.setSize(400, 250);
      settingsDialog.setLocationRelativeTo(mainPanel);
      settingsDialog.setModal(true);
      
      JPanel settingsPanel = new JPanel(new GridBagLayout());
      settingsPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
      GridBagConstraints gbc = new GridBagConstraints();
      gbc.fill = GridBagConstraints.HORIZONTAL;
      gbc.insets = new Insets(5, 5, 5, 5);
      
      JTabbedPane tabbedPane = new JTabbedPane();
      
      for (String provider : PROVIDERS) {
        JPanel providerPanel = new JPanel(new GridBagLayout());
        providerPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        
        JLabel apiKeyLabel = new JLabel("API Key:");
        JPasswordField apiKeyField = new JPasswordField(20);
        apiKeyField.setText(modelConfigs.get(provider).get("api_key"));
        
        gbc.gridx = 0;
        gbc.gridy = 0;
        providerPanel.add(apiKeyLabel, gbc);
        
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        providerPanel.add(apiKeyField, gbc);
        
        tabbedPane.addTab(provider, providerPanel);
      }
      
      JButton saveButton = new JButton("Save");
      saveButton.addActionListener(e -> {
        // Save settings
        for (int i = 0; i < PROVIDERS.length; i++) {
          JPanel panel = (JPanel) tabbedPane.getComponentAt(i);
          JPasswordField apiKeyField = (JPasswordField) panel.getComponent(1);
          modelConfigs.get(PROVIDERS[i]).put("api_key", new String(apiKeyField.getPassword()));
        }
        
        // Save settings to persistent storage
        saveSettings();
        
        settingsDialog.dispose();
      });
      
      JButton cancelButton = new JButton("Cancel");
      cancelButton.addActionListener(e -> settingsDialog.dispose());
      
      JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
      buttonPanel.add(saveButton);
      buttonPanel.add(cancelButton);
      
      settingsDialog.setLayout(new BorderLayout());
      settingsDialog.add(tabbedPane, BorderLayout.CENTER);
      settingsDialog.add(buttonPanel, BorderLayout.SOUTH);
      
      settingsDialog.setVisible(true);
    }
    
    private void sendMessage() {
      String userInput = inputArea.getText().trim();
      if (userInput.isEmpty()) {
        return;
      }
      
      // Add user message to chat
      addMessageToChat("User", userInput);
      
      // Clear input area
      inputArea.setText("");
      
      // Process with the selected LLM
      SwingUtilities.invokeLater(() -> {
        // Check if API key is configured
        String apiKey = modelConfigs.get(currentProvider).get("api_key");
        if (apiKey == null || apiKey.isEmpty()) {
          addMessageToChat("System", "Please configure your " + currentProvider + " API key in settings.");
          return;
        }
        
        // Show "thinking" indicator
        addMessageToChat("Assistant", "Thinking...");
        
        // Convert chat history to a format suitable for the API
        String chatHistoryStr = formatChatHistoryForAPI();
        
        // Prepare context information
        String contextInfo = getContextInformation();
        
        // Make API call with context
        LLMService.sendRequestWithContext(currentProvider, currentModel, apiKey, userInput, chatHistoryStr, contextInfo)
          .thenAccept(response -> {
            SwingUtilities.invokeLater(() -> {
              // Remove the "thinking" message
              chatHistory.remove(chatHistory.size() - 1);
              updateChatDisplay();
              
              // Add the actual response
              addMessageToChat("Assistant", response);
              
              // Check if tools are enabled and the response contains a command
              if (enableToolsCheckbox.isSelected()) {
                // Use only the ToolCommandParser logic
                if (ToolCommandParser.containsToolCommands(response)) {
                  // If the original parser missed it, try the new parser
                  Msg.info(this, "LLM response contains tool commands, attempting to parse and execute.");
                  ToolCommandParser.parseAndExecuteCommands(response, currentProgram, currentFunction, pluginTool)
                    .thenAccept(result -> {
                      Msg.info(this, "Tool execution result: " + result);
                      addMessageToChat("System", "Tool Result: " + result);
                    }).exceptionally(ex -> {
                      Msg.error(this, "Error executing tool command: " + ex.getMessage(), ex);
                      addMessageToChat("System", "Error executing tool command: " + ex.getMessage());
                      return null;
                    });
                }
              }
            });
          })
          .exceptionally(exception -> {
            SwingUtilities.invokeLater(() -> {
              // Remove the "thinking" message
              chatHistory.remove(chatHistory.size() - 1);
              updateChatDisplay();
              
              // Show error message
              addMessageToChat("System", "Error: " + exception.getMessage());
            });
            return null;
          });
      });
    }
    
    private String formatChatHistoryForAPI() {
      // Use the ChatHistoryManager to format the chat history for the selected provider
      List<ChatMessage> historyToSend = new ArrayList<>();
      
      // Exclude the last message (which is the "thinking" message)
      for (int i = 0; i < chatHistory.size() - 1; i++) {
        ChatMessage message = chatHistory.get(i);
        if (!"System".equals(message.getSender())) {
          historyToSend.add(message);
        }
      }
      
      switch (currentProvider) {
        case "OpenAI":
          return ChatHistoryManager.formatForOpenAI(historyToSend);
        case "Claude":
          return ChatHistoryManager.formatForClaude(historyToSend);
        case "Google":
          return ChatHistoryManager.formatForGoogle(historyToSend);
        default:
          return "";
      }
    }
    
    private String getContextInformation() {
      StringBuilder contextBuilder = new StringBuilder();
      contextBuilder.append("--- CONTEXT INFORMATION ---\n");
      
      // Add program context
      if (currentProgram != null) {
        contextBuilder.append("Program: ").append(currentProgram.getName()).append("\n");
        contextBuilder.append("Architecture: ").append(currentProgram.getLanguage().getProcessor().toString()).append("\n");
        contextBuilder.append("Compiler: ").append(currentProgram.getCompiler()).append("\n");
      }
      
      // Add function context
      if (currentFunction != null) {
        contextBuilder.append("\nCurrent Function:\n");
        contextBuilder.append("Name: ").append(currentFunction.getName()).append("\n");
        contextBuilder.append("Signature: ").append(currentFunction.getSignature().toString()).append("\n");
        contextBuilder.append("Address: ").append(currentFunction.getEntryPoint().toString()).append("\n");
        
        // Add decompiled code if available
        if (currentDecompiledCode != null && !currentDecompiledCode.isEmpty()) {
          contextBuilder.append("\nDecompiled Code:\n");
          contextBuilder.append("```c\n").append(currentDecompiledCode).append("\n```\n");
        }
      }
      
      contextBuilder.append("--- END CONTEXT ---\n\n");
      return contextBuilder.toString();
    }
    
    private void saveSettings() {
      // Save API keys using ChatHistoryManager
      for (String provider : PROVIDERS) {
        ChatHistoryManager.saveApiKey(provider, modelConfigs.get(provider).get("api_key"));
      }
      
      // Save current chat history
      String userDir = System.getProperty("user.home");
      String savePath = userDir + File.separator + ".bytemate" + File.separator + "chat_history.json";
      ChatHistoryManager.saveHistory(savePath, chatHistory);
    }
    
    private void loadSettings() {
      // Load API keys using ChatHistoryManager
      for (String provider : PROVIDERS) {
        String apiKey = ChatHistoryManager.loadApiKey(provider);
        modelConfigs.get(provider).put("api_key", apiKey);
      }
      
      // Load chat history
      String userDir = System.getProperty("user.home");
      String savePath = userDir + File.separator + ".bytemate" + File.separator + "chat_history.json";
      List<ChatMessage> loadedHistory = ChatHistoryManager.loadHistory(savePath);
      if (!loadedHistory.isEmpty()) {
        chatHistory = loadedHistory;
        updateChatDisplay();
      }
    }
    
    private void addMessageToChat(String sender, String message) {
      ChatMessage chatMessage = new ChatMessage(sender, message);
      chatHistory.add(chatMessage);
      updateChatDisplay();
    }
    
    private void updateChatDisplay() {
      chatPane.setText("");
      StyledDocument doc = chatPane.getStyledDocument();
      
      for (ChatMessage message : chatHistory) {
        SimpleAttributeSet senderStyle = new SimpleAttributeSet();
        StyleConstants.setForeground(senderStyle, message.getSender().equals("User") ? 
                                    new Color(0, 100, 200) : 
                                    message.getSender().equals("System") ? 
                                    Color.RED : new Color(0, 150, 0));
        StyleConstants.setBold(senderStyle, true);
        
        SimpleAttributeSet messageStyle = new SimpleAttributeSet();
        
        try {
          doc.insertString(doc.getLength(), message.getSender() + ":\n", senderStyle);
          doc.insertString(doc.getLength(), message.getMessage() + "\n\n", messageStyle);
        } catch (BadLocationException e) {
          Msg.error(this, "Error updating chat display: " + e.getMessage());
        }
      }
      
      // Scroll to bottom
      chatPane.setCaretPosition(doc.getLength());
    }

    private void extractAndCopyCodeBlock(String text) {
      // Simple code block extraction based on markdown code blocks (```...```)
      int startIdx = text.indexOf("```");
      if (startIdx != -1) {
        int endIdx = text.indexOf("```", startIdx + 3);
        if (endIdx != -1) {
          // Skip the language identifier line if present
          int contentStart = text.indexOf('\n', startIdx + 3);
          if (contentStart != -1 && contentStart < endIdx) {
            String codeBlock = text.substring(contentStart + 1, endIdx).trim();
            copyToClipboard(codeBlock);
            return;
          }
        }
      }
      
      // If no code block markers found, just copy the text as is
      copyToClipboard(text);
    }
    
    private void extractAndCopyNearestCodeBlock(String text, int caretPosition) {
      // Find the nearest code block to the caret position
      int blockStart = text.lastIndexOf("```", caretPosition);
      if (blockStart != -1) {
        int blockEnd = text.indexOf("```", blockStart + 3);
        if (blockEnd != -1 && blockEnd > caretPosition) {
          // Skip the language identifier line if present
          int contentStart = text.indexOf('\n', blockStart + 3);
          if (contentStart != -1 && contentStart < blockEnd) {
            String codeBlock = text.substring(contentStart + 1, blockEnd).trim();
            copyToClipboard(codeBlock);
            return;
          }
        }
      }
      
      // If no code block found after the caret, try to find one before
      int blockEnd = text.lastIndexOf("```", caretPosition);
      if (blockEnd != -1) {
        int previousBlockStart = text.lastIndexOf("```", blockEnd - 1);
        if (previousBlockStart != -1) {
          // Skip the language identifier line if present
          int contentStart = text.indexOf('\n', previousBlockStart + 3);
          if (contentStart != -1 && contentStart < blockEnd) {
            String codeBlock = text.substring(contentStart + 1, blockEnd).trim();
            copyToClipboard(codeBlock);
            return;
          }
        }
      }
      
      // No code block found, show a message
      JOptionPane.showMessageDialog(mainPanel, "No code block found near cursor", "Copy Failed", JOptionPane.INFORMATION_MESSAGE);
    }
    
    private void copyToClipboard(String text) {
      if (text != null && !text.isEmpty()) {
        java.awt.Toolkit.getDefaultToolkit()
            .getSystemClipboard()
            .setContents(new java.awt.datatransfer.StringSelection(text), null);
      }
    }

    // Update program context when program is activated
    public void updateProgramContext(Program program) {
      this.currentProgram = program;
      if (program != null) {
        programContextLabel.setText("Program: " + program.getName());
      } else {
        programContextLabel.setText("Program: Not loaded");
        clearFunctionContext();
      }
    }
    
    // Clear program context when program is deactivated
    public void clearProgramContext() {
      this.currentProgram = null;
      programContextLabel.setText("Program: Not loaded");
      clearFunctionContext();
    }
    
    // Clear function context
    private void clearFunctionContext() {
      this.currentFunction = null;
      this.currentDecompiledCode = null;
      functionContextLabel.setText("Function: None selected");
    }
    
    // Update function context when location changes
    public void updateFunctionContext(ProgramLocation location) {
      if (location == null || currentProgram == null) {
        clearFunctionContext();
        return;
      }
      
      // Get function containing the current location
      FunctionManager functionManager = currentProgram.getFunctionManager();
      Function function = functionManager.getFunctionContaining(location.getAddress());
      
      if (function != null) {
        this.currentFunction = function;
        functionContextLabel.setText("Function: " + function.getName());
        
        // Get decompiled code
        getDecompiledCode(function);
      } else {
        clearFunctionContext();
      }
    }
    
    // Get decompiled code for a function
    private void getDecompiledCode(Function function) {
      if (function == null) {
        currentDecompiledCode = null;
        return;
      }
      
      SwingUtilities.invokeLater(() -> {
        try {
          DecompInterface decompiler = new DecompInterface();
          DecompileOptions options = new DecompileOptions();
          decompiler.setOptions(options);
          
          // Initialize and set program
          decompiler.openProgram(currentProgram);
          
          // Decompile the function
          DecompileResults results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
          
          if (results.decompileCompleted()) {
            // Get the decompiled C code
            currentDecompiledCode = results.getDecompiledFunction().getC();
          } else {
            currentDecompiledCode = "// Decompilation failed";
          }
          
          decompiler.dispose();
        } catch (Exception e) {
          Msg.error(this, "Error decompiling function: " + e.getMessage());
          currentDecompiledCode = "// Error during decompilation: " + e.getMessage();
        }
      });
    }

    /**
     * Shows a dialog with available tools that the LLM can use
     */
    private void showAvailableTools() {
        JDialog toolsDialog = new JDialog();
        toolsDialog.setTitle("Available LLM Tools");
        toolsDialog.setSize(600, 400);
        toolsDialog.setLocationRelativeTo(mainPanel);
        toolsDialog.setModal(true);
        
        JPanel contentPanel = new JPanel(new BorderLayout());
        contentPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        
        // Create tabbed pane for tool categories
        JTabbedPane tabbedPane = new JTabbedPane();
        
        // Code Modification panel
        JPanel codeModPanel = new JPanel();
        codeModPanel.setLayout(new BoxLayout(codeModPanel, BoxLayout.Y_AXIS));
        
        addToolInfo(codeModPanel, "Rename Function", 
                   "Rename the current function to a specified name.", 
                   "Example: \"rename function to 'processInput'\"");
        
        addToolInfo(codeModPanel, "Add Comments", 
                   "Add comments to the current function or specific addresses.", 
                   "Example: \"add plate comment 'This function validates user input'\"");
        
        // Navigation panel (planned)
        JPanel navPanel = new JPanel();
        navPanel.setLayout(new BoxLayout(navPanel, BoxLayout.Y_AXIS));
        
        addToolInfo(navPanel, "Find References (Coming Soon)", 
                   "Find all references to a symbol in the codebase.", 
                   "Example: \"find references to getData\"");
        
        // Analysis panel (planned)
        JPanel analysisPanel = new JPanel();
        analysisPanel.setLayout(new BoxLayout(analysisPanel, BoxLayout.Y_AXIS));
        
        addToolInfo(analysisPanel, "Data Type Definition (Coming Soon)", 
                   "Create or modify data type definitions.", 
                   "Example: \"define structure UserData with fields: id(int), name(char[32])\"");
        
        addToolInfo(analysisPanel, "Function Signature (Coming Soon)", 
                   "Modify function signatures based on analysis.", 
                   "Example: \"update function signature to 'int process(char *input, size_t len)'\"");
        
        // Add panels to tabbed pane
        tabbedPane.addTab("Code Modification", new JScrollPane(codeModPanel));
        tabbedPane.addTab("Navigation", new JScrollPane(navPanel));
        tabbedPane.addTab("Analysis", new JScrollPane(analysisPanel));
        
        // Add description at top
        JTextArea descriptionArea = new JTextArea(
            "These are the tools available to the LLM assistant. When enabled, the LLM can perform these actions " +
            "by including commands in its responses. All actions require user confirmation before execution."
        );
        descriptionArea.setWrapStyleWord(true);
        descriptionArea.setLineWrap(true);
        descriptionArea.setEditable(false);
        descriptionArea.setBackground(null);
        descriptionArea.setBorder(new EmptyBorder(0, 0, 10, 0));
        
        contentPanel.add(descriptionArea, BorderLayout.NORTH);
        contentPanel.add(tabbedPane, BorderLayout.CENTER);
        
        // Add close button
        JButton closeButton = new JButton("Close");
        closeButton.addActionListener(e -> toolsDialog.dispose());
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonPanel.add(closeButton);
        contentPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        toolsDialog.setContentPane(contentPanel);
        toolsDialog.setVisible(true);
    }
    
    /**
     * Adds tool information to a panel
     * 
     * @param panel The panel to add the tool info to
     * @param toolName The name of the tool
     * @param description The description of the tool
     * @param example An example of using the tool
     */
    private void addToolInfo(JPanel panel, String toolName, String description, String example) {
        JPanel toolPanel = new JPanel(new BorderLayout());
        toolPanel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY),
            new EmptyBorder(10, 5, 10, 5)
        ));
        
        // Tool name in bold
        JLabel nameLabel = new JLabel(toolName);
        nameLabel.setFont(nameLabel.getFont().deriveFont(Font.BOLD));
        
        // Description
        JTextArea descArea = new JTextArea(description);
        descArea.setWrapStyleWord(true);
        descArea.setLineWrap(true);
        descArea.setEditable(false);
        descArea.setBackground(null);
        
        // Example in italics
        JTextArea exampleArea = new JTextArea(example);
        exampleArea.setFont(exampleArea.getFont().deriveFont(Font.ITALIC));
        exampleArea.setWrapStyleWord(true);
        exampleArea.setLineWrap(true);
        exampleArea.setEditable(false);
        exampleArea.setBackground(null);
        exampleArea.setForeground(new Color(100, 100, 100));
        
        JPanel textPanel = new JPanel();
        textPanel.setLayout(new BoxLayout(textPanel, BoxLayout.Y_AXIS));
        textPanel.add(descArea);
        textPanel.add(Box.createVerticalStrut(5));
        textPanel.add(exampleArea);
        
        toolPanel.add(nameLabel, BorderLayout.NORTH);
        toolPanel.add(textPanel, BorderLayout.CENTER);
        
        toolPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, toolPanel.getPreferredSize().height));
        panel.add(toolPanel);
        panel.add(Box.createVerticalStrut(10));
    }

    @Override
    public JComponent getComponent() {
      return mainPanel;
    }
  }
}
