from traceback import print_tb

from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
#from scapy.all import get_if_list
from kivy.uix.popup import Popup
import time
from datetime import datetime
import os
import sqlite3

from IDSApp import calculate_real_data_rate, compare_with_average_data_rate
from packet_manager import capture_packets, read_packets


class PacketSnifferScreen(Screen):
    """Screen to manage packet sniffing."""

    def __init__(self, **kwargs):
        super(PacketSnifferScreen, self).__init__(**kwargs)
        self.device_info = None  # To store selected device information (IP, MAC, etc.)
        self.packet_input = None  # Declare attribute to prevent AttributeError
        self.packet_input_label = None
        self.ip = None
        # Root layout
        self.layout = FloatLayout()



        # Title Label
        self.title_label = Label(
            text="Packet Sniffer",
            font_size="24sp",
            size_hint=(0.6, 0.1),
            pos_hint={"center_x": 0.5, "top": 0.95},
        )
        self.layout.add_widget(self.title_label)

        # Packet input label (not added initially)
        self.packet_input_label = Label(
            text="Enter the number of packets to capture:",
            size_hint=(0.6, 0.1),
            pos_hint={"center_x": 0.5, "top": 0.6},

        )
        self.layout.add_widget(self.packet_input_label)
        # Packet input field (not added initially)
        self.packet_input = TextInput(
            hint_text="Packet Count",
            size_hint=(0.4, 0.08),
            halign="center",
            pos_hint={"center_x": 0.5, "top": 0.65},

        )

        # Button to trigger showing the packet input field
        self.show_input_button = Button(
            text="Show Packet Input",
            size_hint=(0.3, 0.1),
            pos_hint={"center_x": 0.5, "top": 0.55},
        )
        self.layout.add_widget(self.packet_input)
        # Start capture button
        self.start_button = Button(
            text="Start Capture",
            background_color=(0.2, 0.6, 1, 1),
            size_hint=(0.3, 0.1),
            pos_hint={"center_x": 0.5, "top": 0.45},
        )
        self.start_button.bind(on_press=self.start_capture)
        self.layout.add_widget(self.start_button)

        # # Input for the number of entries to delete
        # self.num_entries_input = TextInput(hint_text="Enter number of entries to delete", multiline=False)
        # self.layout.add_widget(self.num_entries_input)

        # View history button
        self.delete_button = Button(
            text="Delete Entries",
            size_hint=(0.3, 0.1),
            background_color=(0.2, 0.6, 1, 1),
            pos_hint={"center_x": 0.5, "top": 0.35},
        )
        self.delete_button.bind(on_press=self.delete_oldest_entries)
        self.layout.add_widget(self.delete_button)

        # Back button
        self.back_button = Button(
            text="Back",
            size_hint=(0.3, 0.1),
            background_color=(0.2, 0.6, 1, 1),
            pos_hint={"center_x": 0.5, "top": 0.25},
        )
        self.back_button.bind(on_release=self.go_back)
        self.layout.add_widget(self.back_button)

        # Add layout to the screen
        self.add_widget(self.layout)

    def show_packet_input(self, instance, ip):
        """Dynamically show the packet input field and label."""
        #print(ip)
        self.ip = ip
        #print("Current screen:", self.manager.current)
        # Ensure we are on the correct screen (PacketSnifferScreen)
        if self.manager.current != "packet_sniffer":
            self.manager.current = "packet_sniffer"  # Switch to the PacketSnifferScreen
        #print(f'show packet input method called')
        if self.packet_input_label.parent is None:  # Add only if not already added
            #print(f'Add only if not already added-label')
            self.layout.add_widget(self.packet_input_label)
            #self.packet_input.background_color = (1, 0, 0, 1)
        if self.packet_input.parent is None:  # Add only if not already added
            #print(f'Add only if not already added - input')
            #self.packet_input.background_color = (1, 0, 0, 1)
            self.layout.add_widget(self.packet_input)


            # Disable button after it's clicked
        self.show_input_button.disabled = True
        # print(self.packet_input.pos_hint)
        # print(self.packet_input_label.pos_hint)
        #
        # print(self.layout.children)



    def start_capture(self, instance):
        """Start capturing packets."""
        ip =self.ip
        if not self.packet_input:
            self.show_popup("Error", "No packet input field found!")
            return

        packet_count = self.packet_input.text
        if not packet_count.isdigit():
            self.show_popup("Error", "Please enter a valid number of packets!")
            return

        try:
            # File output path
            time_now = str(datetime.fromtimestamp(time.time()).strftime("%Y_%m_%d_%H_%M_%S"))
            output_file = "packet-captures/" + ip[0].replace(" ","") + "-" + ip[1]+ "-" + time_now + ".pcap"
            output_dir = os.path.dirname("../" + output_file)
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            #print(get_if_list())
            # Simulate packet capture (you need to replace this with actual capture logic)
            capture_packets('Local Area Connection* 2', ip[1], int(packet_count), output_file)
            print(f"Capturing {packet_count} packets to {output_file}...")

            #summary_got = "\n".join(packet.summary() for packet in (read_packets(output_file)))
            summary_got = "RAW"
            datarate =calculate_real_data_rate("../packet-captures/" + output_file.split("/")[1], ip)
            print("datarate", datarate)

            self.save_file_in_db(output_file.split("/")[1], ip[2], summary_got, time_now, datarate, ip[1])

            compare_with_average_data_rate(datarate, ip[1])

            # Save file info in the database
            #print("output file name", "packet-captures/"+output_file.split("/")[1], output_file.split("/")[1])

            #calculate_real_data_rate("../packet-captures/"+output_file.split("/")[1], output_file.split("/")[1])

            self.show_popup("Success", f"Capture completed. File saved at {output_file}")
        except Exception as e:
            self.show_popup("Error", f"An error occurred: {str(e)}")

    def save_file_in_db(self, output_file, mac, summary, time_now, datarate, ip):
        print("saving file in db")
        """Save packet capture info in the database."""
        try:
            conn = sqlite3.connect("../db/file_storage.db")
            cursor = conn.cursor()
            cursor.execute('''CREATE TABLE IF NOT EXISTS Files
                              (mac TEXT, IP TEXT, filename TEXT PRIMARY KEY, summary TEXT, time TEXT, DATA_RATE FLOAT)''')
            cursor.execute("INSERT OR IGNORE INTO Files (mac, IP, filename, summary, time, DATA_RATE) VALUES (?, ?, ?, ?, ?, ?)",
                           (mac, ip, output_file, summary, time_now, datarate))
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            self.show_popup("Error", f"Database error: {str(e)}")

    def view_history(self, instance):
        """View capture history."""
        try:
            conn = sqlite3.connect("../db/file_storage.db")
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM Files")
            records = cursor.fetchall()
            conn.close()

            content = FloatLayout()
            if not records:
                label = Label(text="No capture history found.", size_hint=(0.8, 0.1),
                              pos_hint={"center_x": 0.5, "top": 0.8})
                content.add_widget(label)
            else:
                for idx, record in enumerate(records):
                    label = Label(
                        text=f"File: {record[1]}\nMAC: {record[0]}\nTime: {record[3]}",
                        size_hint=(0.8, 0.1),
                        pos_hint={"center_x": 0.5, "top": 0.8 - (idx * 0.12)},
                    )
                    content.add_widget(label)

            popup = Popup(title="Capture History", content=content, size_hint=(0.8, 0.8))
            popup.open()
        except sqlite3.Error as e:
            self.show_popup("Error", f"Database error: {str(e)}")

    # def delete_entries(self, instance):
    #     try:
    #         # Get the number of entries to delete from the TextInput
    #         num_entries = int(self.num_entries_input.text)
    #         if num_entries > 0:
    #             self.delete_oldest_entries(num_entries)  # Call the deletion function
    #         else:
    #             print("Please enter a valid number of entries to delete.")
    #     except ValueError:
    #         print("Invalid input. Please enter a valid integer.")

    def delete_oldest_entries(self, instance=None):
        print("deleting entries")
        try:
            # Connect to the database
            conn = sqlite3.connect("../db/file_storage.db")
            cursor = conn.cursor()

            # SQL to delete the oldest entries based on the date or timestamp (you may adjust the column name based on your schema)

            cursor.execute("""
                DELETE FROM Files
                WHERE IP IN (
                    SELECT IP FROM Files ORDER BY time ASC LIMIT ?
                );
            """, (10,))

            conn.commit()
            conn.close()
            self.show_popup("Success: ", "Successfully deleted 10 Entries from file_storage")

        except sqlite3.Error as e:
            print(f"Error deleting entries: {e}")

    def go_back(self, instance):
        """Go back to the previous screen."""
        self.manager.transition.direction = "right"
        self.manager.current = "show_devices"

    def show_popup(self, title, message):
        """Show a popup with the given title and message."""
        popup = Popup(title=title, content=Label(text=message), size_hint=(0.6, 0.4))
        popup.open()
