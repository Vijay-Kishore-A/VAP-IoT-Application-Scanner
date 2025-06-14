import os
import sqlite3
from datetime import datetime

import self
from kivy.modules import cursor
from openpyxl.workbook import Workbook

from arp_scanner import arp_scan, save_device_info, update_device_info
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.screenmanager import Screen
from kivy.uix.scrollview import ScrollView
from kivy.uix.textinput import TextInput
from packet_sniffer import PacketSnifferScreen


# Fetch devices (stub for integration with actual scanner)
def fetch_devices():
    print(f'fetch devices method calling')
    try:
        return arp_scan('192.168.137.1', 2, 254)  # Replace with actual parameters
    except Exception as e:
        print(f"Error fetching devices: {e}")
        return []




def edit_device_info(device, instance, show_devices_screen):
    """Create a form to edit the device name."""
    # Create the form for editing device name
    if isinstance(device, str):
        try:
            parts = device.split(" - ")
            device = {
                "Device_Name": parts[0],
                "IP": parts[1],
                "MAC_Address": parts[2],
                "MAC_Vendor": parts[3],
                "Availability": parts[4] == "Yes",
            }
        except IndexError:
            print("Error parsing device string.")
            return

    content = BoxLayout(orientation="vertical", spacing=10, padding=10)

    # Label
    content.add_widget(Label(text=f"Edit Device Name for: {device['Device_Name']}"))

    # TextInput for new device name
    new_device_name_input = TextInput(
        text=device['Device_Name'],
        size_hint_y=None,
        #height=20,
        multiline=False,
        size_hint=(0.3, 0.5),
        pos_hint={"center_x": 0.5, "center_y": 0.5}
    )
    content.add_widget(new_device_name_input)

    # Button to update device name
    update_button = Button(text="Update Device Name", size_hint_x=0.3, size_hint_y=None, height=50, pos_hint={"center_x": 0.5, "center_y": 0.5}, background_color=(0.2, 0.6, 1, 1))
    content.add_widget(update_button)

    # Close button
    close_button = Button(text="Close", size_hint_x=0.3, size_hint_y=None, height=50, pos_hint={"center_x": 0.5, "center_y": 0.5}, background_color=(0.2, 0.6, 1, 1), )
    close_button.bind(on_release=lambda x: popup.dismiss())
    content.add_widget(close_button)

    # Function to update the device name
    def update_device_name(instance):  # Accept `instance` as an argument
        new_name = new_device_name_input.text
        print(f"new_name", new_name)
        if new_name.strip():  # Avoid empty names
            device['Device_Name'] = new_name
            update_device_info(device['MAC_Address'], new_name)  # Pass the popup for proper dismissal
            print(f"Updated device name to: {new_name}")
            show_devices_screen.refresh_screen(instance)
            popup.dismiss()
        else:
            print("Device name cannot be empty.")

    update_button.bind(on_release=update_device_name)

    popup = Popup(
        title="Edit Device Info",
        content=content,
        size_hint=(0.4, 0.5)
    )
    popup.open()




def show_options(instance, show_devices_screen):
    """Show options for a selected device."""
    selected_device = instance.text

    # Parse the device info from the button text or the device data structure
    #device_info =parse_device_info(selected_device)  # This function should extract the device info

    # Pass the selected device info to the PacketSnifferScreen
    #show_devices_screen.manager.current_screen.set_device_info(device_info)

    content = BoxLayout(orientation="vertical", spacing=7, padding=10)
    content.add_widget(Label(text=f"Options for:\n{selected_device}"))

    edit_button = Button(text="Edit Device Info", size_hint_x=0.3, size_hint_y=None, height=50, pos_hint={"center_x": 0.5, "center_y": 0.5}, background_color=(0.2, 0.6, 1, 1),)
    edit_button.bind(on_release=lambda x: edit_device_info(selected_device, instance, show_devices_screen))
    content.add_widget(edit_button)

    capture_button = Button(text="Capture Packets", size_hint_x=0.3, size_hint_y=None, height=50, pos_hint={"center_x": 0.5, "center_y": 0.5}, background_color=(0.2, 0.6, 1, 1))
    capture_button.bind(
        on_release=lambda instance: (
        popup.dismiss(),
        show_devices_screen.manager.get_screen('packet_sniffer').show_packet_input(instance, selected_device.split(' - '))
        )
    )
    content.add_widget(capture_button)

    history_button = Button(text="View Capture History", size_hint_x=0.3, size_hint_y=None, height=50, pos_hint={"center_x": 0.5, "center_y": 0.5}, background_color=(0.2, 0.6, 1, 1),)
    history_button.bind(on_release=lambda x: view_all_history())
    content.add_widget(history_button)

    download_button = Button(text="Download History", size_hint_x=0.3, size_hint_y=None, height=50, pos_hint={"center_x": 0.5, "center_y": 0.5}, background_color=(0.2, 0.6, 1, 1),)
    download_button.bind(on_release=lambda x: download_history(self, instance))
    content.add_widget(download_button)

    close_button = Button(text="Close", size_hint_x=0.3, size_hint_y=None, height=50, pos_hint={"center_x": 0.5, "center_y": 0.5}, background_color=(0.2, 0.6, 1, 1),)
    close_button.bind(on_release=lambda x: popup.dismiss())
    content.add_widget(close_button)

    popup = Popup(
        title="Device Options",
        content=content,
        size_hint=(0.4, 0.5)
    )
    popup.open()

def view_all_history():
        """View capture history."""
        try:
            conn = sqlite3.connect("../db/file_storage.db")
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM Files")
            records = cursor.fetchall()
            conn.close()

            content = BoxLayout(orientation="vertical", spacing=10, padding=10)
            if not records:
                label = Label(text="No capture history found.", size_hint=(0.8, 0.1),
                              pos_hint={"center_x": 0.5, "top": 0.8})
                content.add_widget(label)
            else:
                for idx, record in enumerate(records):
                    label = Label(
                        text=f"File: {record[2]}\nMAC: {record[0]}\nTime: {record[4]}",
                        size_hint=(0.8, 0.1),
                        pos_hint={"center_x": 0.5, "top": 0.8 - (idx * 0.12)},
                    )
                    content.add_widget(label)

            popup = Popup(title="Capture History", content=content, size_hint=(0.8, 0.8))
            popup.open()
        except sqlite3.Error as e:
            print("errror")
            #self.show_popup("Error", f"Database error: {str(e)}")


def download_history(self, instance):
    db_path = "../db/file_storage.db"  # Adjust as per your database location
    output_folder = "../exported_files"  # Save in the current directory

    # Export data to Excel
    exported_file = export_history_to_excel(db_path, output_folder)
    if exported_file:
        show_popup(self, "Success: ", "History downloaded successfully!")

    else:
        show_popup("Error", "Failed to export capture history.")

def show_popup(self, title, message):
        popup_content = BoxLayout(orientation="vertical", padding=10, spacing=10)
        popup_content.add_widget(Label(text=message))
        close_button = Button(text="Close", size_hint=(1, 0.3))
        popup = Popup(title=title, content=popup_content, size_hint=(0.4, 0.5))
        close_button.bind(on_release=popup.dismiss)
        popup_content.add_widget(close_button)
        popup.open()

def export_history_to_excel(db_path, output_folder):
    """
    Export captured packet history from the database to an Excel file.
    Args:
        db_path (str): Path to the database.
        output_file (str): Path to save the Excel file.
    Returns:
        str: Path of the exported Excel file or None if an error occurred.
    """
    try:

        # Ensure the output folder exists
        os.makedirs(output_folder, exist_ok=True)

        # Generate a dynamic file name
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(output_folder, f"capture_history_{timestamp}.xlsx")

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Files")
        records = cursor.fetchall()

        # Create an Excel workbook and add data
        wb = Workbook()
        ws = wb.active
        ws.title = "Capture History"

        # Add headers
        headers = ["MAC Address", "IP Address", "Filename", "Summary", "Timestamp", "Data Rate"]
        ws.append(headers)

        # Add rows
        for record in records:
            ws.append(record)

        # Save Excel file
        wb.save(output_file)
        conn.close()
        return output_file

    except Exception as e:
        print(f"Error exporting history to Excel: {e}")
        return None



class ShowDevicesScreen(Screen):
    """Screen to display available devices."""
    def __init__(self, **kwargs):
        super(ShowDevicesScreen, self).__init__(**kwargs)
        layout = FloatLayout()

        # Title label
        self.background = Label(
            text="Available Devices",
            font_size="24sp",
            size_hint=(1, 0.1),
            pos_hint={"center_x": 0.5, "top": 1},
        )
        layout.add_widget(self.background)

        # ScrollView for the device list
        self.scroll_view = ScrollView(size_hint=(1, 0.8), pos_hint={"center_x": 0.5, "top": 0.9})
        self.device_list = BoxLayout(orientation="vertical", size_hint_y=None)
        self.device_list.bind(minimum_height=self.device_list.setter("height"))
        self.scroll_view.add_widget(self.device_list)
        layout.add_widget(self.scroll_view)

        # Back button
        back_button = Button(
            text="Back",
            font_size=24,
            size_hint=(0.1, 0.05),
            background_color=(0.2, 0.6, 1, 1),
            pos_hint={"x": 0.3, "y": 0.02},
            on_release=self.go_back
        )
        layout.add_widget(back_button)

        self.add_widget(layout)
        self.populate_devices()

        # Refresh button
        refresh_button = Button(
            text="Refresh",
            font_size=24,
            size_hint=(0.1, 0.05),
            background_color=(0.2, 0.6, 1, 1),
            pos_hint={"x": 0.6, "y": 0.02},
            on_release=self.refresh_screen  # Bind to refresh_screen method
        )
        layout.add_widget(refresh_button)




    def refresh_screen(self, instance):
        """Refresh the screen by repopulating the devices list."""
        # Clear the current device list
        self.device_list.clear_widgets()

        # Repopulate devices
        self.populate_devices()

        print("Screen refreshed!")

    def populate_devices(self):
        """Fetch and display devices."""
        devices = fetch_devices()
        print(f"devices",devices)
        if not devices:
            self.device_list.add_widget(Label(text="No devices found.", size_hint_y=None, height=50))
            return

        for device in devices:
            device_info = (
                f"{device.get('Device_Name', 'Unknown_device')} - {device['IP']} - "
                f"{device['MAC_Address']} - {device['MAC_Vendor']} - "
                f"{'Yes' if device['Availability'] else 'No'}"
            )
            device_button = Button(
                text=device_info,
                size_hint_y=None,
                height=50,
                background_color=(0.5, 0.7, 0.9, 1) if device["Availability"] else (0.9, 0.5, 0.5, 1),
            )
            device_button.bind(on_release=lambda instance: show_options(instance, self))
            self.device_list.add_widget(device_button)

    def go_back(self, instance):
        """Navigate back to the home screen."""
        self.manager.transition.direction = "right"
        self.manager.current = "home"





