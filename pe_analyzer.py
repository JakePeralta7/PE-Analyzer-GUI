# Imports
import pefile
import PySimpleGUI as sg
import requests
import os
import random
from const import *


class PE:
    def __init__(self, path):

        # Initializing values
        self.path = path
        self.pe = pefile.PE(self.path)
        self.hashes = {}
        self.imports = {}
        self.headers = {}
        self.exports = []
        self.strings = []
        self.architecture = ""
        self.characteristics = ""
        self.sections = {"Section Name": SECTION_ATTRIBUTES}
        self.repr_hashes = ""
        self.virus_total_result = ""
        self.warnings = self.pe.get_warnings()
        self.name = os.path.basename(self.path)
        self.strings_file = f"{self.name.split('.')[0]}_strings.txt"
        self.time_stamp = f"TimeDateStamp: {self.pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split('[')[1][:-1]}"

        # Functions
        self.scan_virus_total()
        self.get_sections()
        self.get_imports_exports()
        self.get_strings()
        self.get_characteristics()
        self.get_resources()

    def check_architecture(self):

        # Check if it is a 32-bit or 64-bit binary
        if hex(self.pe.FILE_HEADER.Machine) == THIRTY_TWO_BIT:
            self.architecture = ARCH_MSG.format(32)
        else:
            self.architecture = ARCH_MSG.format(64)

    def scan_virus_total(self):
        try:
            files = {'file': (self.name, open(self.path, 'rb'))}
            scan_response = requests.post(SCAN_URL, files=files, params={'apikey': API_KEY})
            scan_result = scan_response.json()
            self.hashes = {
                SHA1: scan_result[SHA1],
                SHA256: scan_result[SHA256],
                MD5: scan_result[MD5]
            }
            report_response = requests.get(REPORT_URL, params={'apikey': API_KEY, 'resource': self.hashes[MD5]})
            report_result = report_response.json()
            self.virus_total_result = RESULT_FORMAT.format(report_result['positives'], report_result['total'])
        except requests.exceptions.ConnectionError:
            return

    def get_sections(self):
        for section in self.pe.sections:
            self.sections[section.Name.decode().rstrip('\x00')] = [
                section.get_entropy(),
                str(section.Misc_VirtualSize) + " bytes",
                hex(section.VirtualAddress),
                str(section.SizeOfRawData) + " bytes",
                hex(section.PointerToRawData),
                hex(section.Characteristics)
            ]

    def get_imports_exports(self):
        if hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                self.imports[f"{entry.dll.decode()} ({len(entry.imports)})"] = \
                    [function.name.decode() for function in entry.imports]
        if hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
            self.exports = [exp.name.decode('utf-8') for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols]
        else:
            self.exports.append("The PE doesn't export anything")

    def get_strings(self):
        command = f'strings -nobanner -n {MIN_AMOUNT_OF_CHARS} "{self.path}" > {self.strings_file}'
        os.system(command)
        with open(self.strings_file, "r") as strings_file:
            self.strings = strings_file.read().splitlines()
        os.system(f"del {self.strings_file}")

    def get_characteristics(self):
        types = []
        if self.pe.is_dll():
            types.append("dll")
        if self.pe.is_exe():
            types.append("exe")
        if self.pe.is_driver():
            types.append("driver")
        self.characteristics = f"Characteristics: {', '.join(types)}"

    def get_resources(self):
        if hasattr(self.pe, "DIRECTORY_ENTRY_RESOURCE"):
            for entry in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                directory = entry.directory
                print(directory)

    def get_headers(self):
        self.headers = {
            "DOS_HEADER": self.pe.DOS_HEADER,
            "NT_HEADERS": self.pe.NT_HEADERS,
            "FILE_HEADERS": self.pe.FILE_HEADER,
            "OPTIONAL_HEADER": self.pe.OPTIONAL_HEADER
        }

    def __str__(self):
        return self.pe.dump_info()


def write_report(pe):
    layout = [
        [sg.Text("Choose location for the report")],
        [sg.FolderBrowse(key=FOLDER_KEY), sg.Submit(), sg.Cancel()]
    ]
    window = sg.Window(TITLE, layout)
    event, values = window.Read()
    window.Close()
    if event == "Submit":
        report_path = values[FOLDER_KEY]
        report_file_name = f"{pe.name.split('.')[0]}-report.txt"
        with open(os.path.join(report_path, report_file_name), "w") as report:
            report.write(str(pe))
        sg.Popup("Report exported successfully")


def analyzer(pe_path):
    # Initializing the PE obj
    pe = PE(pe_path)

    # General Tab
    general_tab_layout = [[sg.Text(pe.virus_total_result)]]
    general_tab_layout += [[sg.Text(hash_type, size=(10, 1)), sg.Text(value)] for hash_type, value in pe.hashes.items()]
    general_tab_layout += [[sg.Text(pe.architecture)], [sg.Text(pe.time_stamp)], [sg.Text(pe.characteristics)]]

    # IOCs Tab
    if pe.warnings:
        ioc_tab_layout = [[sg.Text("Warnings")]]
        ioc_tab_layout += [[sg.Text(warning)] for warning in pe.warnings]
    else:
        ioc_tab_layout = [[sg.Text("No IOCs found")]]

    # Imports Tab
    imports_layout = []
    if pe.imports:
        current_column = []
        for dll, functions in pe.imports.items():
            current_column.append([sg.Text(dll, size=(15, 1))])
            for function in functions:
                current_column.append([sg.Text("", size=(15, 1)), sg.Text(function)])
        imports_layout.append([sg.Column(current_column, scrollable=True, vertical_scroll_only=True)])
    else:
        imports_layout.append([sg.Text("The PE doesn't imports anything")])

    # Exports Tab
    exports_layout = []
    for function in pe.exports:
        exports_layout.append([sg.Text(function)])
    exports_column = [[sg.Column(exports_layout, scrollable=True, vertical_scroll_only=True)]]

    # Section Tab
    sections_tab_layout = []
    for section, values in pe.sections.items():
        section_layout = [sg.Text(section, size=(15, 1))] + [sg.Text(value, size=(15, 1)) for value in values]
        sections_tab_layout.append(section_layout)

    # Strings Tab
    strings_tab_layout = [[sg.Text(string)] for string in pe.strings]
    strings_column = [[sg.Column(strings_tab_layout, scrollable=True, vertical_scroll_only=True)]]

    # Unites all the tabs to one layout
    tab_group_layout = [
        [sg.Tab(GENERAL_TAB, general_tab_layout)],
        [sg.Tab(IMPORTS_TAB, imports_layout)],
        [sg.Tab(EXPORTS_TAB, exports_column)],
        [sg.Tab(SECTIONS_TAB, sections_tab_layout)],
        [sg.Tab(STRINGS_TAB, strings_column)],
        [sg.Tab(IOC_TAB, ioc_tab_layout)]
    ]

    # The final layout for the window
    layout = [
        [sg.Text(f"{pe.name} ({pe.path})"), sg.Button(EXPORT_BTN)],
        [sg.TabGroup(tab_group_layout, enable_events=True)]
    ]

    # Initializing the window
    window = sg.Window(TITLE, layout, size=(900, 600))
    window.Finalize()

    # Make the window full size
    # window.Maximize()

    while True:
        event, values = window.read()
        if event in (None, 'Exit'):
            break
        elif event == EXPORT_BTN:
            write_report(pe)
    window.Close()


def main():

    # Setting the style of the app (randomly)
    sg.change_look_and_feel(random.choice(APP_STYLE))

    # The layout of the start window
    layout = [
        [sg.Text("Choose the PE you want to analyze")],
        [sg.FileBrowse(key=FILE_KEY), sg.Submit()]
    ]

    # Initializing the start window
    window = sg.Window(TITLE, layout)

    # Looping for events
    while True:
        event, values = window.Read()

        # Breaking out of the loop if chosen
        if event in (None, 'Exit'):
            break

        elif event == SUBMIT_BTN:
            try:

                # Getting the value from the FileBrowse object
                pe_path = values[FILE_KEY]

                # Checking if the PE path is valid
                if os.path.isfile(pe_path):
                    window.Close()
                    analyzer(pe_path)
                else:
                    sg.Popup(INVALID_PATH)
            except KeyError:
                sg.Popup(EMPTY_PATH)

    window.Close()


if __name__ == '__main__':
    main()
