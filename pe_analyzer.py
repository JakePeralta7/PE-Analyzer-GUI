# Imports
import PySimpleGUI as sg
import os
import random
from const import *
from pe import PE


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
    window = sg.Window(TITLE, layout, size=(1000, 600))
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
