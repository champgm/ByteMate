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
import java.awt.Dimension;
import java.awt.Font;

import javax.swing.*;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resources.Icons;

/**
 * ByteMate Plugin with Hello World window
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "ByteMate Hello World Plugin",
	description = "Plugin that adds a Hello World window to the Window menu."
)
//@formatter:on
public class ByteMatePlugin extends ProgramPlugin {

	MyProvider provider;
	HelloWorldProvider helloWorldProvider;

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

		// Customize provider (or remove if a provider is not desired)
		String pluginName = getName();
		provider = new MyProvider(this, pluginName);

		// Create our Hello World provider
		helloWorldProvider = new HelloWorldProvider(this, pluginName);

		// Create the menu action
		createActions();

		// Customize help (or remove if help is not desired)
		String topicName = this.getClass().getPackage().getName();
		String anchorName = "HelpAnchor";
		provider.setHelpLocation(new HelpLocation(topicName, anchorName));
	}

	private void createActions() {
		DockingAction action = new DockingAction("Hello World", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				helloWorldProvider.setVisible(true);
			}
		};

		// Add this action to the Window menu
		action.setMenuBarData(new MenuData(new String[] { "Window", "Hello World" }, null, "ByteMateGroup"));
		action.setEnabled(true);
		action.markHelpUnnecessary();
		
		// Register the action with the tool
		tool.addAction(action);
		
		// Add debug output to verify action registration
		System.out.println("ByteMatePlugin: Added Hello World action to Window menu");
		Msg.info(this, "ByteMatePlugin: Added Hello World action to Window menu");
	}

	@Override
	public void init() {
		super.init();
	}

	// If provider is desired, it is recommended to move it to its own file
	private static class MyProvider extends ComponentProvider {

		private JPanel panel;
		private DockingAction action;

		public MyProvider(Plugin plugin, String owner) {
			super(plugin.getTool(), "ByteMate Provider", owner);
			buildPanel();
			createActions();
		}

		// Customize GUI
		private void buildPanel() {
			panel = new JPanel(new BorderLayout());
			JTextArea textArea = new JTextArea(5, 25);
			textArea.setEditable(false);
			panel.add(new JScrollPane(textArea));
			setVisible(true);
		}

		// Customize actions
		private void createActions() {
			action = new DockingAction("My Action", getOwner()) {
				@Override
				public void actionPerformed(ActionContext context) {
					Msg.showInfo(getClass(), panel, "Custom Action", "Hello!");
				}
			};
			action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
			action.setEnabled(true);
			action.markHelpUnnecessary();
			dockingTool.addLocalAction(this, action);
		}

		@Override
		public JComponent getComponent() {
			return panel;
		}
	}

	// Hello World window provider
	private static class HelloWorldProvider extends ComponentProvider {

		private JPanel panel;

		public HelloWorldProvider(Plugin plugin, String owner) {
			super(plugin.getTool(), "Hello World", owner);
			buildPanel();
			setVisible(false); // Initially not visible
		}

		// Create the Hello World panel
		private void buildPanel() {
			panel = new JPanel(new BorderLayout());
			
			// Create Hello World label with larger font
			JLabel helloLabel = new JLabel("Hello World", JLabel.CENTER);
			helloLabel.setFont(new Font(helloLabel.getFont().getName(), Font.BOLD, 24));
			
			panel.add(helloLabel, BorderLayout.CENTER);
			
			// Set the window size to 200x200
			panel.setPreferredSize(new Dimension(200, 200));
		}

		@Override
		public JComponent getComponent() {
			return panel;
		}
	}
}
