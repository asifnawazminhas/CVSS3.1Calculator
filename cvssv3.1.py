# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab
from java.awt import GridBagLayout, GridBagConstraints, Insets
from javax.swing import JPanel, JLabel, JComboBox, JButton, JTextArea, JEditorPane, JScrollPane, BorderFactory, JTabbedPane
from javax.swing.event import HyperlinkEvent
import java.awt.Desktop
from java.net import URI
from datetime import datetime

class CVSSCalculatorTab(ITab):
    def __init__(self, extender):
        self._extender = extender

        # Create a main tabbed pane
        self.tabbed_pane = JTabbedPane()

        # Add CVSS 3.1 Calculator tab
        self.create_calculator_tab()
        self.tabbed_pane.addTab("Calculator", self.calculator_panel)

        # Add About tab
        self.create_about_tab()
        self.tabbed_pane.addTab("About", self.about_panel)

    def create_calculator_tab(self):
        """Create the CVSS Calculator UI."""
        self.calculator_panel = JPanel()
        layout = GridBagLayout()
        self.calculator_panel.setLayout(layout)

        gbc = GridBagConstraints()
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.weightx = 1.0
        gbc.weighty = 0.0
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.insets = Insets(5, 5, 5, 5)

        # Define dropdowns for each CVSS 3.1 metric
        self.av = JComboBox(["Network (AV:N)", "Adjacent (AV:A)", "Local (AV:L)", "Physical (AV:P)"])
        self.ac = JComboBox(["Low (AC:L)", "High (AC:H)"])
        self.pr = JComboBox(["None (PR:N)", "Low (PR:L)", "High (PR:H)"])
        self.ui = JComboBox(["None (UI:N)", "Required (UI:R)"])
        self.s = JComboBox(["Unchanged (S:U)", "Changed (S:C)"])
        self.c = JComboBox(["None (C:N)", "Low (C:L)", "High (C:H)"])
        self.i = JComboBox(["None (I:N)", "Low (I:L)", "High (I:H)"])
        self.a = JComboBox(["None (A:N)", "Low (A:L)", "High (A:H)"])

        # Add labels and dropdowns to the panel
        self.add_component(self.calculator_panel, gbc, "Attack Vector", self.av)
        self.add_component(self.calculator_panel, gbc, "Attack Complexity", self.ac)
        self.add_component(self.calculator_panel, gbc, "Privileges Required", self.pr)
        self.add_component(self.calculator_panel, gbc, "User Interaction", self.ui)
        self.add_component(self.calculator_panel, gbc, "Scope", self.s)
        self.add_component(self.calculator_panel, gbc, "Confidentiality", self.c)
        self.add_component(self.calculator_panel, gbc, "Integrity", self.i)
        self.add_component(self.calculator_panel, gbc, "Availability", self.a)

        # Add a button to calculate the CVSS score
        self.calc_button = JButton("Calculate Score", actionPerformed=self.calculate_cvss)
        gbc.gridy += 1
        self.calculator_panel.add(self.calc_button, gbc)

        # Text area to display the results
        self.result_area = JTextArea(5, 40)
        self.result_area.setLineWrap(True)
        self.result_area.setWrapStyleWord(True)
        self.result_area.setEditable(False)
        scroll_pane_result = JScrollPane(self.result_area)
        gbc.gridy += 1
        self.calculator_panel.add(scroll_pane_result, gbc)

        # Set borders
        scroll_pane_result.setBorder(BorderFactory.createEtchedBorder())

    def create_about_tab(self):
        """Create the About tab with clickable elements."""
        self.about_panel = JPanel()
        self.about_panel.setLayout(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.insets = Insets(10, 10, 10, 10)

        # Add Project Information
        about_content = """
        <html>
        <body>
            <h3>CVSS Calculator</h3>
            <p><b>Version:</b> 1.0</p>
            <p><b>Creator:</b> Asif Nawaz Minhas</p>
            <p><b>Website:</b> <a href="https://asifnawazminhas.github.io/">asifnawazminhas.github.io</a></p>
            <p><b>LinkedIn:</b> <a href="https://www.linkedin.com/in/asifnawazminhas/">Asif Nawaz Minhas</a></p>
	    <p><b>License:</b> MIT License</p>
        </body>
        </html>
        """
        about_editor_pane = JEditorPane("text/html", about_content)
        about_editor_pane.setEditable(False)
        about_editor_pane.setOpaque(False)
        about_editor_pane.addHyperlinkListener(lambda event: self.open_link(event))
        self.about_panel.add(about_editor_pane, gbc)

        # License Information (MIT License)
        current_year = datetime.now().year
        license_text = (
            "Copyright {year} Asif Nawaz Minhas\n\n"
            "Permission is hereby granted, free of charge, to any person obtaining a copy\n"
            "of this software and associated documentation files (the \"Software\"), to deal\n"
            "in the Software without restriction, including without limitation the rights\n"
            "to use, copy, modify, merge, publish, distribute, sublicense, and/or sell\n"
            "copies of the Software, and to permit persons to whom the Software is\n"
            "furnished to do so, subject to the following conditions:\n\n"
            "The above copyright notice and this permission notice shall be included in\n"
            "all copies or substantial portions of the Software.\n\n"
            "THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n"
            "IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n"
            "FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\n"
            "AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n"
            "LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\n"
            "OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN\n"
            "THE SOFTWARE."
        ).format(year=current_year)
        gbc.gridy += 1
        license_area = JTextArea(license_text, 10, 50)
        license_area.setLineWrap(True)
        license_area.setWrapStyleWord(True)
        license_area.setEditable(False)
        license_area.setBorder(BorderFactory.createEtchedBorder())
        self.about_panel.add(JScrollPane(license_area), gbc)

    def open_link(self, event):
        """Open hyperlinks in the default web browser."""
        if event.getEventType() == HyperlinkEvent.EventType.ACTIVATED:
            if java.awt.Desktop.isDesktopSupported():
                java.awt.Desktop.getDesktop().browse(URI(event.getURL().toString()))

    def add_component(self, panel, gbc, label_text, component):
        """Helper method to add label and combo box to the panel."""
        panel.add(JLabel(label_text), gbc)
        gbc.gridy += 1
        panel.add(component, gbc)
        gbc.gridy += 1

    def getTabCaption(self):
        return "CVSS 3.1 Calculator"

    def getUiComponent(self):
        return self.tabbed_pane

    def round_up(self, input):
        """Helper method to round up the score similarly to the CVSS JS implementation."""
        int_input = round(input * 100000)
        if int_input % 10000 == 0:
            return int_input / 100000
        else:
            return (int_input // 10000 + 1) / 10

    def calculate_cvss(self, event):
        # Map the JComboBox selections to the appropriate metric keys
        metric_map = {
            'AV': {"Network (AV:N)": 'N', "Adjacent (AV:A)": 'A', "Local (AV:L)": 'L', "Physical (AV:P)": 'P'},
            'AC': {"Low (AC:L)": 'L', "High (AC:H)": 'H'},
            'PR': {"None (PR:N)": 'N', "Low (PR:L)": 'L', "High (PR:H)": 'H'},
            'UI': {"None (UI:N)": 'N', "Required (UI:R)": 'R'},
            'S': {"Unchanged (S:U)": 'U', "Changed (S:C)": 'C'},
            'C': {"None (C:N)": 'N', "Low (C:L)": 'L', "High (C:H)": 'H'},
            'I': {"None (I:N)": 'N', "Low (I:L)": 'L', "High (I:H)": 'H'},
            'A': {"None (A:N)": 'N', "Low (A:L)": 'L', "High (A:H)": 'H'}
        }

        metrics = {key: metric_map[key][getattr(self, key.lower()).getSelectedItem()] for key in metric_map}

        weights = {
            'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},
            'AC': {'H': 0.44, 'L': 0.77},
            'UI': {'N': 0.85, 'R': 0.62},
            'S': {'U': 6.42, 'C': 7.52},
            'C': {'N': 0, 'L': 0.22, 'H': 0.56},
            'I': {'N': 0, 'L': 0.22, 'H': 0.56},
            'A': {'N': 0, 'L': 0.22, 'H': 0.56}
        }

        weights['PR'] = {'N': 0.85, 'L': 0.62, 'H': 0.27} if metrics['S'] == 'U' else {'N': 0.85, 'L': 0.68, 'H': 0.5}

        exploitability_coefficient = 8.22
        scope_coefficient = 1.08
        impact_multiplier = (1 - ((1 - weights['C'][metrics['C']]) *
                                  (1 - weights['I'][metrics['I']]) *
                                  (1 - weights['A'][metrics['A']])))
        if metrics['S'] == 'U':
            impact = weights['S']['U'] * impact_multiplier
        else:
            impact = (weights['S']['C'] * (impact_multiplier - 0.029) -
                      3.25 * (impact_multiplier - 0.02) ** 15)

        exploitability = (exploitability_coefficient * weights['AV'][metrics['AV']] *
                          weights['AC'][metrics['AC']] * weights['PR'][metrics['PR']] *
                          weights['UI'][metrics['UI']])

        base_score = 0 if impact <= 0 else self.round_up(
            min((impact + exploitability) * (scope_coefficient if metrics['S'] == 'C' else 1), 10)
        )

        vector = "CVSS:3.1/" + "/".join(["{}:{}".format(key, value) for key, value in metrics.items()])

        self.result_area.setText("CVSS Vector: {}\nBase Score: {}".format(vector, base_score))


class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        callbacks.setExtensionName("CVSS 3.1 Calculator")
        callbacks.addSuiteTab(CVSSCalculatorTab(self))
