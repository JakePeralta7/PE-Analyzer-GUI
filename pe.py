# Imports
import pefile
import requests
import os
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
