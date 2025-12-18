#Import Burp Objects
from burp import IBurpExtender, IBurpExtenderCallbacks, ITab, IBurpCollaboratorInteraction
#Import Java GUI Objects
from java.awt import Dimension, FlowLayout, Color, Toolkit, GridBagLayout, GridBagConstraints, Insets, Dimension, BorderLayout
from java.awt.datatransfer import Clipboard, StringSelection
from javax.swing import JFileChooser, SwingUtilities
from javax import swing
from thread import start_new_thread
import sys, time, threading, base64
from collections import OrderedDict 

t = "" # declare thread globally so we can stop it from any function
stopThreads = False # Thread Tracker to prevent dangling threads
exfilFormat = "base64" #Valid Formats: base64, hex
pubDom = '' # global variable to save and reuse the collaborator link
pubInstance = '' # global variable to save and reuse the collaborator link

class BurpExtender (IBurpExtender, ITab, IBurpCollaboratorInteraction, IBurpExtenderCallbacks):
    # Extension information
    accumulated_output = "" # variable to accumulate the RAW output to be saved later
    EXT_NAME = "DNS Exfilnspector"
    EXT_DESC = "Decode your exfiltrated blind remote code execution output over DNS via Burp Collaborator."
    EXT_THANKS = "Based on work by Adam Logue, Frank Scarpella, Jared McLaren, Ryan Griffin (Collabfiltrator)"
    EXT_AUTHOR = "Paul Serban"
    EXT_VERSION = "1.3"
    # Output info to the Extensions console and register Burp API functions
    def registerExtenderCallbacks(self, callbacks):
        print ("Name: \t\t"      + BurpExtender.EXT_NAME)
        print ("Description: \t" + BurpExtender.EXT_DESC)
        print ("Thanks: \t"      + BurpExtender.EXT_THANKS)
        print ("Authors: \t"      + BurpExtender.EXT_AUTHOR)
        print ("Version: \t" + BurpExtender.EXT_VERSION + "\n")
        # Required for easier debugging:
        # https://github.com/securityMB/burp-exceptions
        sys.stdout = callbacks.getStdout()
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        callbacks.setExtensionName(BurpExtender.EXT_NAME)
        self.killDanglingThreadsOnUnload = callbacks.registerExtensionStateListener(self.killDanglingThreads)

        #Create Burp Collaborator Instance
        self.burpCollab  = self._callbacks.createBurpCollaboratorClientContext()
        self.collaboratorDomain = self.burpCollab.generatePayload(True)

        #Create panels used for layout; we must stack and layer to get the desired GUI
        self.tab = swing.JPanel(BorderLayout())
        self.tabbedPane = swing.JTabbedPane()
        self.tab.add(self.tabbedPane, BorderLayout.CENTER)

        # Create the main panel with GridBagLayout
        # Main Panel for the tab
        self.dnsexfilTab = swing.JPanel(GridBagLayout())
        self.tabbedPane.addTab("DNS Exfilnspector", self.dnsexfilTab)
        gbc = GridBagConstraints()

        # ---------------------------------------------------------
        # 1. TOP SECTION (Title and Format Checkboxes)
        # ---------------------------------------------------------
        topPanel = swing.JPanel(GridBagLayout())
        tgbc = GridBagConstraints()
        
        self.titleLabel = swing.JLabel("Decode your DNS exfiltration payloads")
        self.titleLabel.setFont(self.titleLabel.getFont().deriveFont(16.0))
        tgbc.gridy = 0; tgbc.insets = Insets(5, 5, 5, 5)
        topPanel.add(self.titleLabel, tgbc)

        checkboxesPanel = swing.JPanel(FlowLayout())
        self.base64Checkbox = swing.JCheckBox("Base64", True, actionPerformed=self.toggleEncodingFormat)
        self.hexCheckbox = swing.JCheckBox("Hex", False, actionPerformed=self.toggleEncodingFormat)
        checkboxesPanel.add(self.base64Checkbox)
        checkboxesPanel.add(self.hexCheckbox)
        tgbc.gridy = 1
        topPanel.add(checkboxesPanel, tgbc)

        # Add topPanel to the main tab (Spans all 3 columns)
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 3
        gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0
        self.dnsexfilTab.add(topPanel, gbc)

        # ---------------------------------------------------------
        # 2. LEFT SIDE (Parameters)
        # ---------------------------------------------------------
        parametersPanel = swing.JPanel()
        parametersPanel.setLayout(swing.BoxLayout(parametersPanel, swing.BoxLayout.Y_AXIS))
        parametersPanel.setBorder(swing.BorderFactory.createTitledBorder("For Base64 Exfil"))
        parametersPanel.setMinimumSize(Dimension(140, 150))
        parametersPanel.setPreferredSize(Dimension(140, 180))
        
        parametersPanel.add(swing.JLabel("Replace = with:"))
        self.eqlsrepl = swing.JTextField("eqls", 7)
        parametersPanel.add(self.eqlsrepl)
        parametersPanel.add(swing.JLabel("Replace / with:"))
        self.slashrepl = swing.JTextField("slash", 7)
        parametersPanel.add(self.slashrepl)
        parametersPanel.add(swing.JLabel("Replace + with:"))
        self.plusrepl = swing.JTextField("plus", 7)
        parametersPanel.add(self.plusrepl)

        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 1
        gbc.weightx = 0.0; gbc.weighty = 1.0 # weighty 1.0 allows it to stay at top
        gbc.fill = GridBagConstraints.NONE
        gbc.anchor = GridBagConstraints.NORTHWEST
        gbc.insets = Insets(10, 10, 10, 5)
        self.dnsexfilTab.add(parametersPanel, gbc)

        # ---------------------------------------------------------
        # 3. CENTER (Middle Interaction Area - RESIZABLE)
        # ---------------------------------------------------------
        middleItems = swing.JPanel(GridBagLayout())
        mgbc = GridBagConstraints()
        mgbc.insets = Insets(2, 2, 2, 2)
        mgbc.gridx = 0; mgbc.fill = GridBagConstraints.HORIZONTAL; mgbc.weightx = 1.0

        # Collaborator Link Display
        self.burpCollaboratorDomainTxt = swing.JTextField(" ")
        self.burpCollaboratorDomainTxt.setEditable(False)
        self.burpCollaboratorDomainTxt.setBorder(swing.BorderFactory.createTitledBorder("Collaborator Link"))
        mgbc.gridy = 0
        middleItems.add(self.burpCollaboratorDomainTxt, mgbc)

        # Control Buttons (New Link, Copy, etc)
        btnPanel = swing.JPanel(FlowLayout())
        btnPanel.add(swing.JButton("Get New Link", actionPerformed=self.executePayload))
        btnPanel.add(swing.JButton("Copy To Clipboard", actionPerformed=self.copyToClipboard))
        self.contButton = swing.JButton("Continue Listening", actionPerformed=self.contCollab)
        self.contButton.setVisible(False)
        btnPanel.add(self.contButton)
        mgbc.gridy = 1
        middleItems.add(btnPanel, mgbc)

        # Progress / Stop Listener
        statusPanel = swing.JPanel(FlowLayout())
        self.progressBar = swing.JProgressBar()
        self.progressBar.setVisible(False)
        self.stopListenerButton = swing.JButton("Stop Listener", actionPerformed=self.stopListener)
        self.stopListenerButton.setVisible(False)
        statusPanel.add(self.progressBar)
        statusPanel.add(self.stopListenerButton)
        mgbc.gridy = 2
        middleItems.add(statusPanel, mgbc)

        # THE RESIZABLE OUTPUT BOX
        self.outputTxt = swing.JTextArea()
        self.outputTxt.setEditable(False)
        self.outputTxt.setLineWrap(True)
        self.outputScroll = swing.JScrollPane(self.outputTxt)
        self.outputScroll.setMinimumSize(Dimension(400, 200))
        self.outputScroll.setPreferredSize(Dimension(600, 450))

        mgbc.gridy = 3; mgbc.fill = GridBagConstraints.BOTH; mgbc.weighty = 1.0
        middleItems.add(self.outputScroll, mgbc)

        # Clear button
        self.clearBtn = swing.JButton("Clear Output", actionPerformed=self.clearOutput)
        mgbc.gridy = 4; mgbc.weighty = 0.0; mgbc.fill = GridBagConstraints.NONE
        middleItems.add(self.clearBtn, mgbc)

        # Add middleItems to the main tab (Center Column)
        gbc.gridx = 1; gbc.gridy = 1
        gbc.weightx = 1.0; gbc.weighty = 1.0
        gbc.fill = GridBagConstraints.BOTH
        gbc.insets = Insets(10, 5, 10, 5)
        self.dnsexfilTab.add(middleItems, gbc)

        # ---------------------------------------------------------
        # 4. RIGHT SIDE (Save Buttons)
        # ---------------------------------------------------------
        saveOutput = swing.JPanel()
        saveOutput.setLayout(swing.BoxLayout(saveOutput, swing.BoxLayout.Y_AXIS))
        saveOutput.setBorder(swing.BorderFactory.createTitledBorder("Export"))
        
        saveOutput.add(swing.JButton("Save Raw", actionPerformed=self.saveRawOutputButtonClicked))
        saveOutput.add(swing.Box.createRigidArea(Dimension(0, 10)))
        saveOutput.add(swing.JButton("Save Decoded", actionPerformed=self.saveDecodedOutputButtonClicked))
        
        gbc.gridx = 2; gbc.gridy = 1; gbc.gridwidth = 1
        gbc.weightx = 0.0; gbc.weighty = 1.0
        gbc.fill = GridBagConstraints.NONE
        gbc.anchor = GridBagConstraints.NORTHEAST
        gbc.insets = Insets(10, 5, 10, 10)
        self.dnsexfilTab.add(saveOutput, gbc)

        callbacks.addSuiteTab(self)
        return

    # Standard function: Set the tab name
    def getTabCaption(self):
        return BurpExtender.EXT_NAME

    # Standard function: Set the GUI component in the tab
    def getUiComponent(self):
        return self.tab

    def killDanglingThreads(self):
        global stopThreads
        global t
        stopThreads = True
        try:
            t.join() #rejoin the thread so it detects the stopThreads and exits gracefully
        except:
            pass
        stopThreads = False #Reset the threadTracker so we can run it again
        return
    
    # function to determine exfil format
    def toggleEncodingFormat(self, event):
        global exfilFormat
        if event.getSource() == self.base64Checkbox:
            if self.base64Checkbox.isSelected():
                exfilFormat = 'base64'
                self.hexCheckbox.setSelected(False)
        elif event.getSource() == self.hexCheckbox:
            if self.hexCheckbox.isSelected():
                exfilFormat = 'hex'
                self.base64Checkbox.setSelected(False)

    # function to allow locally saving the RAW output
    def saveRawOutputButtonClicked(self, event):
        file_chooser = JFileChooser()
        return_value = file_chooser.showSaveDialog(None)

        if return_value == JFileChooser.APPROVE_OPTION:
            selected_file = file_chooser.getSelectedFile()
            # Get the selected file's path and assign it to a variable for raw output
            raw_output_file_path = selected_file.getAbsolutePath().encode('utf-8').replace(b'\\\\', b'\\').decode('utf-8')

            # Save the accumulated output
            with open(raw_output_file_path, 'w') as fp:
                fp.write(self.accumulated_output)

    # function to allow locally saving the Decoded output
    def saveDecodedOutputButtonClicked(self, event):
        file_chooser = JFileChooser()
        return_value = file_chooser.showSaveDialog(None)

        if return_value == JFileChooser.APPROVE_OPTION:
            selected_file = file_chooser.getSelectedFile()
            # Get the selected file's path and assign it to a variable for decoded output
            decoded_output_file_path = selected_file.getAbsolutePath().encode('utf-8').replace(b'\\\\', b'\\').decode('utf-8')

            output_content = self.outputTxt.getText()

            # Now you can use the decoded_output_file_path variable for saving decoded output
            with open(decoded_output_file_path, 'w') as fp:
                fp.write(output_content)

    # return generated payload to payload text area
    def executePayload(self, event):
        global pubInstance
        global pubDom
        self.killDanglingThreads()
        self.collaboratorDomain = self.burpCollab.generatePayload(True) #rerun to regenerate new collab domain
        burpCollabInstance = self.burpCollab
        pubInstance = burpCollabInstance
        domain = self.collaboratorDomain # show domain in UI
        pubDom = domain
        self.burpCollaboratorDomainTxt.setText(domain)
        self.checkCollabDomainStatusWrapper(domain, burpCollabInstance )
        return
    
    # function to continue using the same Collaborator link
    def contCollab(self, event):
        global pubInstance
        global pubDom
        burpCollabInstance = pubInstance
        domain = pubDom # show domain in UI
        self.burpCollaboratorDomainTxt.setText(domain)
        self.checkCollabDomainStatusWrapper(domain, burpCollabInstance )
        return

    def stopListener(self, event):
        global stopThreads
        stopThreads = True

        # Force UI reset immediately (on the EDT)
        def reset_ui():
            self.progressBar.setIndeterminate(False)
            self.progressBar.setVisible(False)
            self.stopListenerButton.setVisible(False)
            self.contButton.setVisible(True)

        SwingUtilities.invokeLater(reset_ui)

        try:
            if t and t.isAlive():
                t.join(1)
        except:
            pass

        stopThreads = False

    def clearOutput(self, event): 
        self.outputTxt.setText("") #clear out output text because button was clicked     
        return  

    def checkCollabDomainStatusWrapper(self, domain, burpCollab):
        global stopThreads
        threadFinished = False
        global t
        t = threading.Thread(target=self.checkCollabDomainStatus, args=(domain, burpCollab)) #comma has to be here even with only 1 arg because it expects a tuple
        t.start()
        return # thread doesn't stop locking in execute button

    #copy generated payload to clipboard
    def copyToClipboard(self, event):
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        data = StringSelection(self.burpCollaboratorDomainTxt.getText())
        clipboard.setContents(data, None)
        return    

    #monitor collab domain for output response
    def checkCollabDomainStatus(self, domain, objCollab):
        complete = False
        global stopThreads
        
        answer = []
        no_data_count = 0
        receiving_data = False
        encoded_answers = [] 
        
        while (stopThreads == False):
            if stopThreads == True:
                stopThreads = False
                break
            SwingUtilities.invokeLater(lambda: self.progressBar.setVisible(True)) #show progress bar
            SwingUtilities.invokeLater(lambda: self.progressBar.setIndeterminate(True)) #make progress bar show listener is running
            SwingUtilities.invokeLater(lambda: self.stopListenerButton.setVisible(True)) # show stopListenerButton
            SwingUtilities.invokeLater(lambda: self.contButton.setVisible(False)) #hide continue button
            
            check = objCollab.fetchCollaboratorInteractionsFor(domain)
            
            # determine if data is being received on the collaborator instance
            if len(check) == 0:
                no_data_count += 1
            else:
                no_data_count = 0
                receiving_data = True
            
            # if data is not received for more than 20 interactions (20ish seconds), stop it and continue the Collaborator so that the output is printed
            if receiving_data and no_data_count >= 20:
                self.killDanglingThreads()
                self.contCollab(None)
                break
                
            # parse the DNS query to get the raw output
            for i in range(len(check)):
                raw_query = check[i].getProperty('raw_query')
                if not raw_query:
                    continue  # skip null/empty entries

                try:
                    dnsQuery = self._helpers.base64Decode(raw_query)
                except Exception as e:
                    print("Skipping invalid base64: {}".format(raw_query))
                    continue

                preambleOffset = int(dnsQuery[12])  # Offset in dns query where preamble starts
                encoded_answer = ''.join(chr(x) for x in dnsQuery[13:(13+preambleOffset)])
                encoded_answers.append(encoded_answer)

        unique_encoded_answers = list(OrderedDict.fromkeys(encoded_answers))

        # ensure no duplicate DNS lines one after the other and remove any _ and collab domain
        domain = pubDom.split('.')[0]
        prev_line = None
        
        for filtered_answer in unique_encoded_answers:
            if filtered_answer == prev_line:
                answer.append('')
            else:
                answer.append(filtered_answer.replace(domain, "").replace("_", ""))
                prev_line = filtered_answer

        SwingUtilities.invokeLater(lambda: self.progressBar.setVisible(False)) # hide progressbar
        SwingUtilities.invokeLater(lambda: self.progressBar.setIndeterminate(False)) #turn off progressbar
        SwingUtilities.invokeLater(lambda: self.stopListenerButton.setVisible(False)) # hide stopListenerButton
        SwingUtilities.invokeLater(lambda: self.contButton.setVisible(True)) # show continue button

        # pass the output to the function to decode it and put it in the output box for the user to see
        output = showOutput(answer, self.eqlsrepl.getText(), self.slashrepl.getText(), self.plusrepl.getText())
        self.accumulated_output += ''.join(answer) + '\n'
        self.outputTxt.append(output + '\n')
        self.outputTxt.setCaretPosition(self.outputTxt.getDocument().getLength()) # make sure scrollbar is pointing to bottom
        return

def decode_func(input):
    decoded_answer = base64.b64decode(input).decode()
    return decoded_answer

def showOutput(answer, eqls, slash, plus):
    if exfilFormat == 'base64':
        completedInputString = ''.join(answer)
        output = completedInputString.replace(eqls,'==').replace(plus,'+').replace(slash,'/')
        try: 
            answer = decode_func(output)
        except Exception as e:
            try:
                answer = decode_func(str(output) + '=')
            except Exception as e:
                try:
                    answer = decode_func(str(output) + '==')
                except Exception as e:
                    answer = "Couldn't decode Base64. Are you using Base64 to exfiltrate?"
        return answer
    else:
        hex_string = ''.join(answer)
        try:
            answer = hex_string.decode('hex')
        except Exception as e:
            answer = "Couldn't decode Hex. Are you using Hex to exfiltrate?"
        return answer
