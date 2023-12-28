#Import Burp Objects
from burp import IBurpExtender, IBurpExtenderCallbacks, ITab, IBurpCollaboratorInteraction
#Import Java GUI Objects
from java.awt import Dimension, FlowLayout, Color, Toolkit, GridBagLayout, GridBagConstraints, Insets, Dimension
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
    EXT_VERSION = "1.2"
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
        self.tab = swing.Box(swing.BoxLayout.Y_AXIS)
        self.tabbedPane  = swing.JTabbedPane()
        self.tab.add(self.tabbedPane)

        # Create the main panel with GridBagLayout
        mainPanel = swing.JPanel(GridBagLayout())

        # Create GridBagConstraints for the contentPanel (center)
        contentPanelConstraints = GridBagConstraints()
        contentPanelConstraints.fill = GridBagConstraints.CENTER
        contentPanelConstraints.weightx = 1.0
        contentPanelConstraints.weighty = 1.0

        # Create the contentPanel (center)
        contentPanel = swing.JPanel(GridBagLayout())

        # Create GridBagConstraints for the parametersPanel (left side)
        paramsPanelConstraints = GridBagConstraints()
        paramsPanelConstraints.fill = GridBagConstraints.CENTER
        paramsPanelConstraints.anchor = GridBagConstraints.EAST
        paramsPanelConstraints.insets = Insets(10, 10, 10, 10) 

        # Add custom params for base64 exfil to the mainPanel
        parametersPanel = swing.JPanel()
        parametersPanel.setLayout(swing.BoxLayout(parametersPanel, swing.BoxLayout.Y_AXIS))
        # Create labels and text fields
        parametersPanel.add(swing.JLabel("For Base64 Exfiltration"))
        parametersPanel.add(swing.JLabel("Replace = with:"))
        self.eqlsrepl = swing.JTextField("eqls", 5)
        parametersPanel.add(self.eqlsrepl)
        parametersPanel.add(swing.JLabel("Replace / with:"))
        self.slashrepl = swing.JTextField("slash", 5)
        parametersPanel.add(self.slashrepl)
        parametersPanel.add(swing.JLabel("Replace + with:"))
        self.plusrepl = swing.JTextField("plus", 5)
        parametersPanel.add(self.plusrepl)

        # Create GridBagConstraints for the save output (right side)
        saveOutputConstraints = GridBagConstraints()
        saveOutputConstraints.fill = GridBagConstraints.CENTER
        saveOutputConstraints.anchor = GridBagConstraints.EAST
        saveOutputConstraints.insets = Insets(10, 10, 10, 10) 

        # Add layout for save buttons to the mainPanel
        saveOutput = swing.JPanel()
        saveOutput.setLayout(swing.BoxLayout(saveOutput, swing.BoxLayout.Y_AXIS))
        # Create labels and buttons to save output
        saveAsRawButton = swing.JButton("Save Raw Output", actionPerformed=self.saveRawOutputButtonClicked)
        saveAsDecodedButton = swing.JButton("Save Decoded Output", actionPerformed=self.saveDecodedOutputButtonClicked)
        spacer = swing.JLabel(" ")
        saveOutput.add(saveAsRawButton)
        saveOutput.add(spacer)
        saveOutput.add(saveAsDecodedButton)

        # Create the contentPanel (center)
        checkboxesPanel = swing.JPanel()
        checkboxesPanel.setLayout(swing.BoxLayout(checkboxesPanel, swing.BoxLayout.X_AXIS))

        # Add checkboxes for Base64 and Hex to the mainPanel
        self.base64Checkbox = swing.JCheckBox("Base64", actionPerformed=self.toggleEncodingFormat)
        self.base64Checkbox.setSelected(True)
        self.hexCheckbox = swing.JCheckBox("Hex", actionPerformed=self.toggleEncodingFormat)
        checkboxesPanel.add(self.base64Checkbox)
        checkboxesPanel.add(self.hexCheckbox)

        # First tab
        self.dnsexfilTab = swing.Box(swing.BoxLayout.Y_AXIS)
        self.tabbedPane.addTab("DNS Exfilnspector", self.dnsexfilTab)

        middleItems = swing.JPanel()
        middleItems.setLayout(swing.BoxLayout(middleItems, swing.BoxLayout.Y_AXIS))
               
        self.cp2clip = swing.JPanel(FlowLayout()) #copy payload to clipboard frame
        self.outbox = swing.JPanel(FlowLayout()) #output box frame
        self.title = swing.JPanel(FlowLayout()) # title
        self.collname = swing.JPanel(FlowLayout()) # collaborator domainname frame
        self.hide = swing.JPanel(FlowLayout()) # hidden stop listener frame that only appears upon payload generation
        self.cont = swing.JPanel(FlowLayout()) # continue button
        self.see = swing.JPanel(FlowLayout()) # see payload
        self.clr = swing.JPanel(FlowLayout()) # clear output
        self.newlnk = swing.JPanel(FlowLayout()) # generate new link
    
        # Now add content to the first tab's GUI objects
        self.outputTxt = swing.JTextArea(20,70)
        self.outputScroll = swing.JScrollPane(self.outputTxt) # Make the output scrollable
        self.progressBar = swing.JProgressBar(5,15)
        SwingUtilities.invokeLater(lambda: self.progressBar.setVisible(False))
        #self.progressBar.setVisible(False) # Progressbar is hiding

        self.outputTxt.setEditable(False)
        self.outputTxt.setLineWrap(True)

        self.burpCollaboratorDomainTxt = swing.JTextPane() # burp collaboratorTextPane
        self.burpCollaboratorDomainTxt.setText(" ") #burp collaborator domain goes here
        self.burpCollaboratorDomainTxt.setEditable(False)
        self.burpCollaboratorDomainTxt.setBackground(None)
        self.burpCollaboratorDomainTxt.setBorder(None)

         #burp Collab Domain will go here
        self.title.add(swing.JLabel("Decode your DNS exfiltration payloads"))
        self.cp2clip.add(swing.JButton("Copy Collaborator link to Clipboard", actionPerformed=self.copyToClipboard))
        self.hide.add(self.progressBar)
        self.stopListenerButton = swing.JButton("Stop Listener", actionPerformed=self.stopListener)
        SwingUtilities.invokeLater(lambda: self.stopListenerButton.setVisible(False))
        self.hide.add(self.stopListenerButton)
        self.outbox.add(swing.JLabel(" ")) # spaces to arrange the boxes layout
        self.collname.add(self.burpCollaboratorDomainTxt) # collaborator link shown here
        self.outbox.add(self.outputScroll) #add output scroll bar to page
        self.clr.add(swing.JButton("Clear Output", actionPerformed=self.clearOutput))
        self.newlnk.add(swing.JButton("Get New Collaborator Link", actionPerformed=self.executePayload))
        self.contButton = swing.JButton("Continue Collaborator", actionPerformed=self.contCollab)
        SwingUtilities.invokeLater(lambda: self.contButton.setVisible(False))
        self.cont.add(self.contButton)

        # add the interface within the middleItems grid
        middleItems.add(self.collname)
        middleItems.add(self.newlnk)
        middleItems.add(self.cp2clip)
        middleItems.add(self.hide)
        middleItems.add(self.cont)
        middleItems.add(self.outbox)
        middleItems.add(self.see)
        middleItems.add(self.clr)

        middleItemsConstraints = GridBagConstraints()
        middleItemsConstraints.fill = GridBagConstraints.VERTICAL
        middleItemsConstraints.anchor = GridBagConstraints.NORTH
        middleItemsConstraints.insets = Insets(10, 10, 10, 10)

        # Add the checkboxesPanel to the contentPanel with specific constraints
        contentPanel.add(parametersPanel, paramsPanelConstraints)
        contentPanel.add(middleItems, middleItemsConstraints)
        contentPanel.add(saveOutput, saveOutputConstraints)
        mainPanel.add(contentPanel, contentPanelConstraints)
  
        # Add the GUI objects into the first tab
        self.dnsexfilTab.add(self.title)
        self.dnsexfilTab.add(checkboxesPanel)
        self.dnsexfilTab.add(mainPanel)

        #Register the panel in the Burp GUI
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
        self.collaboratorDomain = self.burpCollab.generatePayload(True)#rerun to regenerate new collab domain
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

    def stopListener(self, event): #killDanglingThreads, but as a buttonEvent
        self.killDanglingThreads()
        return

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
            
            # if data is not received for more than 10 interactions (10ish seconds), stop it and continue the Collaborator so that the output is printed
            if receiving_data and no_data_count >= 10:
                self.killDanglingThreads()
                self.contCollab(None)
                break
                
            encoded_answers = [] 
            # parse the DNS query to get the raw output
            for i in range(0, len(check)):
                dnsQuery = self._helpers.base64Decode(check[i].getProperty('raw_query'))
                preambleOffset = int(dnsQuery[12]) #Offset in dns query where preamble starts (0000,0001,0002,0003....)             
                encoded_answer = ''.join(chr (x) for x in dnsQuery[13:(13+preambleOffset)])
                               
                encoded_answers.append(encoded_answer)
            
            unique_encoded_answers = list(OrderedDict.fromkeys(encoded_answers))
            print(unique_encoded_answers)
            
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
