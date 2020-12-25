# Imports
import pefile
import PySimpleGUI as sg
import requests
import os
from random import choice
from const import *


class PE:
    def __init__(self, path):
        self.path = path
        self.pe = pefile.PE(self.path)
        self.hashes = {}
        self.imports = {}
        self.headers = {}
        self.exports = []
        self.strings = []
        self.characteristics = ""
        self.sections = {"Section Name": SECTION_ATTRIBUTES}
        self.repr_hashes = ""
        self.virus_total_result = ""
        self.warnings = self.pe.get_warnings()
        self.name = os.path.basename(self.path)
        self.strings_file = f"{self.name.split('.')[0]}_strings.txt"
        try:
            self.scan_virus_total()
        except requests.exceptions.ConnectionError:
            pass

        # Check if it is a 32-bit or 64-bit binary
        if hex(self.pe.FILE_HEADER.Machine) == THIRTY_TWO_BIT:
            self.architecture = ARCH_MSG.format(32)
        else:
            self.architecture = ARCH_MSG.format(64)

        self.time_stamp = f"TimeDateStamp: {self.pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split('[')[1][:-1]}"
        self.get_sections()
        self.get_imports_exports()
        self.get_strings()
        self.get_characteristics()
        self.get_resources()

    def scan_virus_total(self):
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

    def __repr__(self):
        return f"""Name: {self.name}
"""


def write_report(pe):
    layout = [
        [sg.Text("Enter path for the report:"), sg.InputText()],
        [sg.Submit(), sg.Cancel()]
    ]
    window = sg.Window(TITLE, layout)
    event, values = window.Read()
    window.Close()
    if event == "Submit":
        report_path = values[0]
        print(report_path)


def analyzer(pe_path):

    # Initializing the PE obj
    pe = PE(pe_path)

    # General Tab
    general_tab_layout = [[sg.Text(pe.virus_total_result)]]
    general_tab_layout += [[sg.Text(hash_type, size=(10, 1)), sg.Text(value)] for hash_type, value in pe.hashes.items()]
    general_tab_layout += [[sg.Text(pe.architecture)], [sg.Text(pe.time_stamp)], [sg.Text(pe.characteristics)]]
    if pe.warnings:
        general_tab_layout += [[sg.Text("Warnings")] + [sg.Text(warning) for warning in pe.warnings]]

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

    tab_group_layout = [
        [sg.Tab("General", general_tab_layout)],
        [sg.Tab("Imports", imports_layout)],
        [sg.Tab("Exports", exports_column)],
        [sg.Tab("Sections", sections_tab_layout)],
        [sg.Tab("Strings", strings_column)]
    ]

    layout = [
        [sg.Text(f"{pe.name} ({pe.path})"), sg.Button(EXPORT_BTN)],
        [sg.TabGroup(tab_group_layout, enable_events=True)]
    ]

    window = sg.Window(TITLE, layout)
    window.Finalize()
    window.Maximize()

    while True:
        event, values = window.read()

        if event in (None, 'Exit'):
            break

        if event == EXPORT_BTN:
            write_report(pe)

    window.Close()


def main():
    sg.change_look_and_feel(choice(APP_STYLE))

    layout = [
        [sg.Text("Insert PE path:"), sg.InputText()],
        [sg.Submit(), sg.Cancel()]
    ]

    window = sg.Window(TITLE, layout)

    while True:
        event, values = window.read()

        if event in (None, 'Exit'):
            break

        if event == "Submit":
            try:
                pe_path = values[0]
                if os.path.isfile(pe_path):
                    window.close()
                    analyzer(pe_path)
                else:
                    sg.Popup("The path you entered is invalid!")
            except KeyError:
                sg.Popup("You didn't enter a path")

    window.close()


if __name__ == '__main__':
    main()
