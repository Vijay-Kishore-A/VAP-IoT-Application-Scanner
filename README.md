# **VAP-IoT-Application-Scanner**


VAP-IoT-Application-Scanner is a smartphone or computer-based application that acts as a secure access point manager for IoT devices. When the device's hotspot is enabled, the app detects all connected IoT devices, provides device management features, enables packet capturing, and includes a lightweight Intrusion Detection System (IDS) for real-time threat monitoring.


## 📋 Device Discovery and Listing

#### Auto-detects all IoT devices connected through the hotspot.

#### Displays the following information:
  
    1)IPv4 Address/IPv6 Address.
  
    2)MAC Address.

    3)Vendor (determined via MAC address lookup).

## ✏️ Device Information Management

#### Edit and save additional metadata for each device:

    1)Custom Device Name.
    
    2)Vendor.
    
    3)Model.
    
    4)Firmware Version.

## 📦 Packet Capture

#### Capture packets for specific IoT devices:

    1)Specify the number of packets and/or capture duration.

    2)Save each device’s traffic as an individual .pcap file.

    3)Customizable file naming.

    4)Pause or terminate packet capture at any time.

## 🔥 Built-in Lightweight IDS

#### Monitor IoT device data rates using a moving average calculation.

#### Trigger alerts if a device’s data rate exceeds twice its average (threshold adjustable).

#### Upon detection:

    1)Log 5 seconds of suspicious traffic.

    2)Send alert notifications via email or phone.

    3)Maintain a 7-day data rate history for every device.

## 🗑️ Data and Record Management

#### Delete: 

    1)Specific .pcap files.

    2)Individual device records.

    3)All saved files in one click.

## ➕ Additional Enhancements

#### Modular design for future expansion:

    1) Customizable notification settings.

    2)Analytics dashboard for device behavior.

    3)Manual risk tagging for devices.

    4)Bulk export of device profiles and historical logs.

## Authors

- **Vijay Kishore Asokan**
- **Ayyappan Subramanian**
- **Preethi Srikanth**
