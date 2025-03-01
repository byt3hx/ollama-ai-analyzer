#Author: Chan aka bytehx
#Date: 19 feb 2025
from burp import IBurpExtender, IContextMenuFactory, ITab, IHttpService
from javax.swing import JPanel, JButton, JTextField, JTextArea, JScrollPane, JLabel, JCheckBox, BoxLayout, JComboBox
from javax.swing import JPopupMenu, JMenuItem, JSplitPane, BorderFactory, JOptionPane, SwingConstants, JTabbedPane
from javax.swing import SwingUtilities, JComponent, KeyStroke, AbstractAction, Action, UIManager, JToolBar
from java.awt import BorderLayout, Dimension, Font, GridLayout, FlowLayout, Insets, Component, Color
from java.awt.event import KeyEvent, InputEvent, ActionListener
from java.util import ArrayList
from java.io import InputStreamReader, BufferedReader, OutputStreamWriter, ByteArrayOutputStream, File, FileInputStream, FileOutputStream
import subprocess
import threading
import sys
import os
import json
import re
import tempfile
import uuid
import base64
import time


def safe_print(text):
    try:
        if isinstance(text, bytes):
            text = text.decode('utf-8', 'replace')
        sys.stdout.write((text + "\n").encode('utf-8', 'replace').decode('utf-8', 'replace'))
        sys.stdout.flush()
    except:
        try:
            print(str(text).encode('ascii', 'replace').decode('ascii', 'replace'))
        except:
            print("Could not print message due to encoding issues")

def safe_write(filepath, content):
    try:
        with open(filepath, 'wb') as f:
            if isinstance(content, unicode):
                f.write(content.encode('utf-8', 'replace'))
            else:
                f.write(str(content).encode('utf-8', 'replace'))
    except Exception as e:
        safe_print("Error writing to file: " + str(e))
        raise

class StyledButton(JButton):
    def __init__(self, text, bg_color=None, fg_color=None, **kwargs):
        JButton.__init__(self, text, **kwargs)
        
        if bg_color:
            self.setBackground(bg_color)
        if fg_color:
            self.setForeground(fg_color)
            
        self.setFocusPainted(False)
        self.setBorderPainted(True)
        self.setContentAreaFilled(True)
        self.setOpaque(True)
        
        self.setMargin(Insets(6, 12, 6, 12))
        
        current_font = self.getFont()
        self.setFont(Font(current_font.getName(), Font.BOLD, current_font.getSize()))

class TabComponent(JPanel):
    def __init__(self, tabbedPane, tabIndex, title, closeAction):
        self.setLayout(FlowLayout(FlowLayout.LEFT, 0, 0))
        self.setOpaque(False)
        
        self.titleLabel = JLabel(title)
        self.titleLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 5))
        self.add(self.titleLabel)
        
        closeButton = JButton("x")
        closeButton.setToolTipText("Close this tab")
        closeButton.setMargin(Insets(0, 2, 0, 2))
        closeButton.setContentAreaFilled(False)
        closeButton.setBorderPainted(False)
        closeButton.setFocusable(False)
        closeButton.addActionListener(CloseTabAction(tabbedPane, tabIndex, closeAction))
        self.add(closeButton)

class CloseTabAction(ActionListener):
    def __init__(self, tabbedPane, tabIndex, callback):
        self.tabbedPane = tabbedPane
        self.tabIndex = tabIndex
        self.callback = callback
        
    def actionPerformed(self, e):
        if self.callback:
            self.callback(self.tabIndex)

class RequestPanel(JPanel):
    def __init__(self, helpers, callbacks, tabManager, tabIndex):
        self.setLayout(BorderLayout())
        self._helpers = helpers
        self._callbacks = callbacks
        self._tabManager = tabManager
        self._tabIndex = tabIndex
        
        self._splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._splitPane.setResizeWeight(0.5)  
        
        self._requestPanel = JPanel(BorderLayout())
        self._requestPanel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createEmptyBorder(3, 3, 3, 3),
            BorderFactory.createTitledBorder("Request")
        ))
        
        self._requestArea = JTextArea()
        self._requestArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        requestScroll = JScrollPane(self._requestArea)
        self._requestPanel.add(requestScroll, BorderLayout.CENTER)
        
        requestToolbar = JToolBar()
        requestToolbar.setFloatable(False)
        
        sendButton = StyledButton("Send", Color(255, 204, 0), Color(0, 0, 0)) 
        sendButton.setToolTipText("Send Request")
        sendButton.addActionListener(lambda event: self._sendRequest())
        requestToolbar.add(sendButton)
        
        self._requestPanel.add(requestToolbar, BorderLayout.NORTH)
        
        self._responsePanel = JPanel(BorderLayout())
        self._responsePanel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createEmptyBorder(3, 3, 3, 3),
            BorderFactory.createTitledBorder("Response")
        ))
        
        self._responseArea = JTextArea()
        self._responseArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        responseScroll = JScrollPane(self._responseArea)
        self._responsePanel.add(responseScroll, BorderLayout.CENTER)
        
        self._splitPane.setTopComponent(self._requestPanel)
        self._splitPane.setBottomComponent(self._responsePanel)
        
        self.add(self._splitPane, BorderLayout.CENTER)
        
        promptPanel = JPanel(BorderLayout())
        promptPanel.setBorder(BorderFactory.createTitledBorder("Custom Prompt (Optional)"))
        
        self._promptArea = JTextArea(3, 50) 
        self._promptArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._promptArea.setLineWrap(True)
        self._promptArea.setWrapStyleWord(True)
        self._promptArea.setText("Extract and analyze all paths, endpoints, and parameters found in this HTTP traffic.")
        promptPanel.add(JScrollPane(self._promptArea), BorderLayout.CENTER)
        
        buttonPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        
        self._analyzeButton = JButton("Analyze with AI")
        self._analyzeButton.addActionListener(lambda x: self._tabManager.analyzeWithAI(self._tabIndex))
        buttonPanel.add(self._analyzeButton)
        
        self._requestCheck = JCheckBox("Include Request", True)
        self._responseCheck = JCheckBox("Include Response", True)
        buttonPanel.add(self._requestCheck)
        buttonPanel.add(self._responseCheck)
        
        promptPanel.add(buttonPanel, BorderLayout.SOUTH)
        
        self.add(promptPanel, BorderLayout.SOUTH)
    
    def getRequestText(self):
        return self._requestArea.getText()
    
    def getResponseText(self):
        return self._responseArea.getText()
    
    def getCustomPrompt(self):
        return self._promptArea.getText()
    
    def includeRequest(self):
        return self._requestCheck.isSelected()
    
    def includeResponse(self):
        return self._responseCheck.isSelected()
    
    def setRequest(self, text):
        self._requestArea.setText(text)
    
    def setResponse(self, text):
        self._responseArea.setText(text)
        
    def _sendRequest(self):
        try:
            request_string = self._requestArea.getText()
            if not request_string:
                JOptionPane.showMessageDialog(self, "Request is empty")
                return
            
            request_bytes = self._helpers.stringToBytes(request_string)
            
            requestInfo = self._helpers.analyzeRequest(request_bytes)
            
            headers = requestInfo.getHeaders()
            if len(headers) < 1:
                JOptionPane.showMessageDialog(self, "Invalid request format")
                return
            
            host = None
            port = -1 
            useHttps = True 
            
            firstLine = headers[0].split(' ')
            if len(firstLine) >= 3:
                httpVersion = firstLine[2]
                
            for header in headers:
                if header.lower().startswith("host:"):
                    hostHeader = header[5:].strip()
                    
                    if ":" in hostHeader:
                        parts = hostHeader.split(":", 1)
                        host = parts[0]
                        try:
                            port = int(parts[1])
                            useHttps = port == 443
                        except:
                            pass
                    else:
                        host = hostHeader
                    break
            
            if not host:
                host = JOptionPane.showInputDialog(self, "Enter target host:")
                if not host:
                    return
            

            if port == -1:
                port = 443 if useHttps else 80
                
            httpService = self._helpers.buildHttpService(host, port, useHttps)
            
            self._responseArea.setText("Sending request...")
            
            thread = threading.Thread(target=self._executeRequest, args=[httpService, request_bytes])
            thread.daemon = True
            thread.start()
            
        except Exception as e:
            self._responseArea.setText("Error sending request: " + str(e))
            import traceback
            traceback.print_exc(file=sys.stdout)
    
    def _executeRequest(self, httpService, request_bytes):
        try:
            response = self._callbacks.makeHttpRequest(httpService, request_bytes)
            
            if response and response.getResponse():
                response_bytes = response.getResponse()
                response_string = self._helpers.bytesToString(response_bytes)
                self._responseArea.setText(response_string)
            else:
                self._responseArea.setText("No response received")
        except Exception as e:
            self._responseArea.setText("Error executing request: " + str(e))

class AIResultPanel(JPanel):
    def __init__(self):
        self.setLayout(BorderLayout())
        self.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        
        self._resultArea = JTextArea()
        self._resultArea.setEditable(False)
        self._resultArea.setFont(Font("Monospaced", Font.PLAIN, 14))
        
        resultScrollPane = JScrollPane(self._resultArea)
        resultScrollPane.setPreferredSize(Dimension(800, 400))
        self.add(resultScrollPane, BorderLayout.CENTER)
        
        buttonPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        
        copyButton = JButton("Copy Result")
        copyButton.addActionListener(lambda x: self._copyToClipboard())
        buttonPanel.add(copyButton)
        
        saveResultButton = JButton("Save Result")
        saveResultButton.addActionListener(lambda x: self._saveResultToFile())
        buttonPanel.add(saveResultButton)
        
        clearResultButton = JButton("Clear Result")
        clearResultButton.addActionListener(lambda x: self._resultArea.setText(""))
        buttonPanel.add(clearResultButton)
        
        self.add(buttonPanel, BorderLayout.SOUTH)
    
    def setText(self, text):
        self._resultArea.setText(text)
        self._resultArea.setCaretPosition(0)
    
    def appendText(self, text):
        current = self._resultArea.getText()
        self._resultArea.setText(current + text)
        self._resultArea.setCaretPosition(self._resultArea.getDocument().getLength())
    
    def _copyToClipboard(self):
        from java.awt.datatransfer import StringSelection
        from java.awt import Toolkit
        
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(StringSelection(self._resultArea.getText()), None)
        JOptionPane.showMessageDialog(self, "Result copied to clipboard")
    
    def _saveResultToFile(self):
        from javax.swing import JFileChooser
        from java.io import FileWriter
        
        fileChooser = JFileChooser()
        if fileChooser.showSaveDialog(self) == JFileChooser.APPROVE_OPTION:
            try:
                file = fileChooser.getSelectedFile()
                with open(file.getAbsolutePath(), 'wb') as f:
                    f.write(self._resultArea.getText().encode('utf-8', 'replace'))
                JOptionPane.showMessageDialog(self, "Result saved to " + file.getAbsolutePath())
            except Exception as e:
                JOptionPane.showMessageDialog(self, "Error saving file: " + str(e))

class TabManager:
    def __init__(self, tabbedPane, helpers, callbacks, config):
        self._tabbedPane = tabbedPane
        self._helpers = helpers
        self._callbacks = callbacks
        self._config = config
        self._tabs = [] 
        self._resultPanel = None
        self._analyzing = False
        
        default_system_prompt = (
            "You are a cybersecurity expert analyzing HTTP traffic. "
            "Focus on identifying security vulnerabilities, suspicious patterns, "
            "and potential attack vectors. Provide concise analysis with clear recommendations."
        )
        self._system_prompt = config.get("system_prompt", default_system_prompt)
    
    def setResultPanel(self, resultPanel):
        self._resultPanel = resultPanel
    
    def addTab(self, request="", response=""):
        tabId = len(self._tabs) + 1
        
        requestPanel = RequestPanel(self._helpers, self._callbacks, self, tabId - 1)
        
        if request:
            requestPanel.setRequest(request)
        if response:
            requestPanel.setResponse(response)
        
        tabTitle = "Request " + str(tabId)
        
        tabIndex = self._tabbedPane.getTabCount() - 1
        self._tabbedPane.insertTab(tabTitle, None, requestPanel, None, tabIndex)
        
        tabComponent = TabComponent(self._tabbedPane, tabIndex, tabTitle, self.closeTab)
        self._tabbedPane.setTabComponentAt(tabIndex, tabComponent)
        
        self._tabs.append(requestPanel)
        
        self._tabbedPane.setSelectedIndex(tabIndex)
        
        return tabId - 1
    
    def closeTab(self, tabIndex):
        if tabIndex < 0 or tabIndex >= len(self._tabs) or tabIndex >= self._tabbedPane.getTabCount() - 1:
            return
        
        self._tabbedPane.removeTabAt(tabIndex)
        
        self._tabs.pop(tabIndex)
        
        for i in range(tabIndex, len(self._tabs)):
            tabComponent = self._tabbedPane.getTabComponentAt(i)
            if tabComponent and isinstance(tabComponent, TabComponent):
                for component in tabComponent.getComponents():
                    if isinstance(component, JButton):
                        for listener in component.getActionListeners():
                            if isinstance(listener, CloseTabAction):
                                listener.tabIndex = i
    
    def getCurrentTabIndex(self):
        return self._tabbedPane.getSelectedIndex()
    
    def getCurrentTab(self):
        index = self.getCurrentTabIndex()
        if index >= 0 and index < len(self._tabs):
            return self._tabs[index]
        return None
    
    def analyzeWithAI(self, tabIndex):
        if self._analyzing:
            JOptionPane.showMessageDialog(None, "Analysis already in progress. Please wait.")
            return
            
        if tabIndex < 0 or tabIndex >= len(self._tabs):
            return
        
        requestPanel = self._tabs[tabIndex]
        
        if not requestPanel.getRequestText().strip() and not requestPanel.getResponseText().strip():
            JOptionPane.showMessageDialog(None, "No request or response content to analyze.")
            return
        
        self._analyzing = True
        thread = threading.Thread(target=self._analyzeWithAI, args=[requestPanel])
        thread.daemon = True
        thread.start()
    
    def _clean_ansi(self, text):
        ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]')
        return ansi_escape.sub('', text)
    
    def _analyzeWithAI(self, requestPanel):
        output_content = ""
        temp_dir = None
        
        try:
            custom_prompt = requestPanel.getCustomPrompt().strip()
            
            content = ""
            
            if requestPanel.includeRequest():
                content += "===== REQUEST =====\n"
                content += requestPanel.getRequestText() + "\n\n"
            
            if requestPanel.includeResponse():
                content += "===== RESPONSE =====\n"
                content += requestPanel.getResponseText() + "\n\n"
            
            model = self._config.get("model", "llama3")
            ollama_path = self._config.get("path", "ollama")
            
            self._resultPanel.setText("Starting Ollama analysis with model: " + str(model) + "...\n")
            
            safe_print("Analyzing with model: " + str(model))
            safe_print("Ollama path: " + ollama_path)
            safe_print("System prompt length: " + str(len(self._system_prompt)))
            safe_print("Custom prompt: " + custom_prompt)
            
            temp_dir = tempfile.mkdtemp(prefix="ollama_")
            safe_print("Created temp directory: " + temp_dir)
            
            http_file = os.path.join(temp_dir, "http_traffic.txt")
            safe_write(http_file, content)
            safe_print("Wrote HTTP traffic to: " + http_file)
            
            complete_prompt = 'Based on the following system instructions:[ %s ]  %s ' % (
                self._system_prompt,
                custom_prompt
            )
            
            output_file = os.path.join(temp_dir, "output.txt")
            
            cmd_str = ""
            if os.name == 'nt':  
                cmd_str = '%s run %s "%s" < "%s"' % (
                    ollama_path,
                    model,
                    complete_prompt.replace('"', '\\"'),
                    http_file.replace('/', '\\')
                )
                safe_print("Running Windows command: " + cmd_str)
            else:  
                cmd_str = '%s run %s "%s" < %s' % (
                    ollama_path,
                    model,
                    complete_prompt.replace('"', '\\"'),
                    http_file
                )
                safe_print("Running Unix command: " + cmd_str)
            
            self._resultPanel.setText("Running Ollama analysis...\n\nCommand: " + cmd_str)
            
            try:
                if os.name == 'nt': 
                    process = subprocess.Popen(cmd_str, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                else:  
                    process = subprocess.Popen(cmd_str, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                self._resultPanel.setText("Analysis in progress with " + model + "...\n")
                
                result = ""
                while True:
                    output_line = process.stdout.readline()
                    if not output_line and process.poll() is not None:
                        break
                        
                    if output_line:
                        line = output_line.decode('utf-8', 'replace')
                        line = self._clean_ansi(line)
                        result += line
                        self._resultPanel.setText("Analysis in progress...\n\n" + result)
                
                remaining_output, error_output = process.communicate()
                if remaining_output:
                    remaining = remaining_output.decode('utf-8', 'replace')
                    remaining = self._clean_ansi(remaining)
                    result += remaining
                
                if process.returncode != 0:
                    if error_output:
                        error = error_output.decode('utf-8', 'replace')
                        safe_print("Error output from process: " + error)
                        result += "\n\nError executing command: " + error
                
                if result.strip():
                    self._resultPanel.setText(result)
                else:
                    self._resultPanel.setText("No output received from Ollama.\n\nCommand: " + cmd_str)
                    
                    if error_output:
                        error = error_output.decode('utf-8', 'replace')
                        self._resultPanel.setText("No output received. Error: " + error)
                
            except Exception as e:
                import traceback
                error_msg = "Error running Ollama: " + str(e)
                stack_trace = traceback.format_exc()
                self._resultPanel.setText(error_msg + "\n\n" + stack_trace)
                safe_print(error_msg)
                safe_print(stack_trace)
                
        except Exception as e:
            import traceback
            error_msg = "Error during analysis: " + str(e)
            stack_trace = traceback.format_exc()
            self._resultPanel.setText(error_msg + "\n\n" + stack_trace)
            safe_print(error_msg)
            safe_print(stack_trace)
        finally:
            self._analyzing = False            
            if temp_dir:
                safe_print("Temporary files at: " + temp_dir)

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("Ollama AI Analyzer")
        
        callbacks.registerContextMenuFactory(self)
        
        self._config_file = os.path.join(os.path.expanduser("~"), ".burp_ai_analyzer.json")
        self._config = self._load_config()
        
        self._panel = JPanel(BorderLayout())
        
        topPanel = self._createSettingsPanel()
        self._panel.add(topPanel, BorderLayout.NORTH)
        
        horizontalSplitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        horizontalSplitPane.setResizeWeight(0.6) 
        
        self._tabbedPane = JTabbedPane()
        
        tabButtonPanel = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        newTabButton = JButton("+", actionPerformed=lambda event: self._tabManager.addTab())
        newTabButton.setToolTipText("Add new request tab")
        newTabButton.setMargin(Insets(2, 5, 2, 5))
        tabButtonPanel.add(newTabButton)
        self._tabbedPane.addTab("", tabButtonPanel)
        
        resultContainer = JPanel(BorderLayout())
        resultContainer.setBorder(BorderFactory.createTitledBorder("AI Analysis Results"))
        
        self._resultPanel = AIResultPanel()
        resultContainer.add(self._resultPanel, BorderLayout.CENTER)
        
        horizontalSplitPane.setLeftComponent(self._tabbedPane)
        horizontalSplitPane.setRightComponent(resultContainer)
        
        self._panel.add(horizontalSplitPane, BorderLayout.CENTER)
        
        self._tabManager = TabManager(self._tabbedPane, self._helpers, self._callbacks, self._config)
        self._tabManager.setResultPanel(self._resultPanel)
        
        self._tabManager.addTab()
        
        callbacks.addSuiteTab(self)
        
        self._lastContextMenuTime = 0
        
        safe_print("Ollama AI Analyzer extension loaded")
    
    def _createSettingsPanel(self):
        settingsPanel = JPanel(BorderLayout())
        settingsPanel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createEmptyBorder(5, 5, 5, 5),
            BorderFactory.createTitledBorder("Ollama Settings")
        ))
        
        controlsPanel = JPanel(GridLayout(1, 2, 10, 0))
        
        modelPanel = JPanel(BorderLayout())
        modelPanel.add(JLabel("Ollama Model:  "), BorderLayout.WEST)
        self._modelField = JComboBox(["llama3", "llama3:8b", "llama3:70b", "mistral", "gemma:7b", "byteLLM"])
        self._modelField.setEditable(True)
        if "model" in self._config:
            self._modelField.setSelectedItem(self._config["model"])
        modelPanel.add(self._modelField, BorderLayout.CENTER)
        controlsPanel.add(modelPanel)
        
        pathPanel = JPanel(BorderLayout())
        pathPanel.add(JLabel("Ollama Path:  "), BorderLayout.WEST)
        self._pathField = JTextField(self._config.get("path", "ollama"))
        pathPanel.add(self._pathField, BorderLayout.CENTER)
        controlsPanel.add(pathPanel)
        
        settingsPanel.add(controlsPanel, BorderLayout.CENTER)
        
        buttonPanel = JPanel(FlowLayout(FlowLayout.RIGHT))
        
        self._systemPromptButton = JButton("Configure System Prompt")
        self._systemPromptButton.addActionListener(lambda x: self._configure_system_prompt())
        buttonPanel.add(self._systemPromptButton)
        
        self._saveButton = JButton("Save Settings")
        self._saveButton.addActionListener(lambda x: self._save_config())
        buttonPanel.add(self._saveButton)
        
        testButton = JButton("Test Ollama")
        testButton.addActionListener(lambda x: self._test_ollama())
        buttonPanel.add(testButton)
        
        settingsPanel.add(buttonPanel, BorderLayout.EAST)
        
        return settingsPanel
    
    def _test_ollama(self):
        ollama_path = self._pathField.getText()
        
        try:
            self._resultPanel.setText("Testing Ollama connection...\n")
            
            if os.name == 'nt':  
                cmd = '"%s" list' % ollama_path
            else: 
                cmd = ollama_path + " list"
            
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = process.communicate()
            
            if output:
                output_str = output.decode('utf-8', 'replace')
                self._resultPanel.setText("Ollama test successful! Available models:\n\n" + output_str)
                JOptionPane.showMessageDialog(self._panel, 
                    "Ollama is working correctly.",
                    "Success", 
                    JOptionPane.INFORMATION_MESSAGE)
            else:
                error_msg = "Ollama test failed! No output received."
                if error:
                    error_str = error.decode('utf-8', 'replace')
                    error_msg += "\n\nError: " + error_str
                
                self._resultPanel.setText(error_msg)
                JOptionPane.showMessageDialog(self._panel, 
                    error_msg,
                    "Error", 
                    JOptionPane.ERROR_MESSAGE)
                
        except Exception as e:
            error_msg = "Error testing Ollama: " + str(e)
            self._resultPanel.setText(error_msg)
            JOptionPane.showMessageDialog(self._panel, 
                error_msg,
                "Error", 
                JOptionPane.ERROR_MESSAGE)
            safe_print(error_msg)
    
    def _configure_system_prompt(self):
        currentPrompt = self._config.get("system_prompt", 
            "You are a cybersecurity expert analyzing HTTP traffic. "
            "Focus on identifying security vulnerabilities, suspicious patterns, "
            "and potential attack vectors. Provide concise analysis with clear recommendations.")
        
        systemPromptArea = JTextArea(10, 60)
        systemPromptArea.setText(currentPrompt)
        systemPromptArea.setLineWrap(True)
        systemPromptArea.setWrapStyleWord(True)
        scrollPane = JScrollPane(systemPromptArea)
        
        result = JOptionPane.showConfirmDialog(
            self._panel, 
            scrollPane, 
            "Configure System Prompt", 
            JOptionPane.OK_CANCEL_OPTION,
            JOptionPane.PLAIN_MESSAGE
        )
        
        if result == JOptionPane.OK_OPTION:
            system_prompt = systemPromptArea.getText()
            self._config["system_prompt"] = system_prompt
            
            if hasattr(self, '_tabManager'):
                self._tabManager._system_prompt = system_prompt
                
            self._save_config()
            
            self._resultPanel.setText("System prompt updated to:\n\n" + system_prompt)
    
    def _load_config(self):
        try:
            if os.path.exists(self._config_file):
                with open(self._config_file, 'rb') as f:
                    return json.loads(f.read().decode('utf-8', 'replace'))
        except Exception as e:
            safe_print("Error loading config: " + str(e))
        return {}
        
    def _save_config(self):
        try:
            config = {
                "model": str(self._modelField.getSelectedItem()),
                "path": self._pathField.getText(),
                "system_prompt": self._config.get("system_prompt", 
                    "You are a cybersecurity expert analyzing HTTP traffic. "
                    "Focus on identifying security vulnerabilities, suspicious patterns, "
                    "and potential attack vectors. Provide concise analysis with clear recommendations.")
            }
            
            with open(self._config_file, 'wb') as f:
                f.write(json.dumps(config, ensure_ascii=False).encode('utf-8', 'replace'))
            
            self._config = config
            
            if hasattr(self, '_tabManager'):
                self._tabManager._config = config
                self._tabManager._system_prompt = config["system_prompt"]
            
            JOptionPane.showMessageDialog(self._panel, 
                "Settings saved successfully", 
                "Success", 
                JOptionPane.INFORMATION_MESSAGE)
                
            safe_print("Config saved with system prompt: " + config["system_prompt"])
            
        except Exception as e:
            JOptionPane.showMessageDialog(self._panel, 
                "Error saving settings: " + str(e), 
                "Error", 
                JOptionPane.ERROR_MESSAGE)
            safe_print("Error saving config: " + str(e))
    
    def getTabCaption(self):
        return "Ollama AI Analyzer"
    
    def getUiComponent(self):
        return self._panel
        
    def createMenuItems(self, contextMenuInvocation):
        menuItems = ArrayList()
        menuItem = JMenuItem("Send to Ollama AI Analyzer")
        menuItem.addActionListener(lambda x: self.handleContextMenu(contextMenuInvocation))
        menuItems.add(menuItem)
        return menuItems
    
    def handleContextMenu(self, invocation):
        current_time = int(round(time.time() * 1000))  
        if (current_time - self._lastContextMenuTime) < 500:
            safe_print("Ignoring duplicate context menu event")
            return
            
        self._lastContextMenuTime = current_time
        
        selectedMessages = invocation.getSelectedMessages()
        if not selectedMessages or len(selectedMessages) == 0:
            return
            
        message = selectedMessages[0]
        request = message.getRequest()
        response = message.getResponse()
        
        if request:
            request_str = self._helpers.bytesToString(request)
            response_str = ""
            
            if response:
                response_str = self._helpers.bytesToString(response)
                
            if request_str.strip():
                safe_print("Adding request to tab from context menu")
                
                def addTab():
                    self._tabManager.addTab(request_str, response_str)
                
                SwingUtilities.invokeLater(addTab)
