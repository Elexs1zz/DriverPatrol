import os
import pywinusb.hid as hid
import requests
import subprocess
import re
import time

VIRUSTOTAL_API_KEY = "api_key"

def virus_scan(file_path):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': VIRUSTOTAL_API_KEY}
    files = {'file': (os.path.basename(file_path), open(file_path, 'rb'))}

    try:
        response = requests.post(url, files=files, params=params)
        json_response = response.json()

        if 'verbose_msg' in json_response:
            print(json_response['verbose_msg'])
            if json_response['response_code'] == 1:
                return json_response['scan_id']
        else:
            print("Error scanning the file.")
    except Exception as e:
        print("VirusTotal API Error:", e)
    return None

def get_scan_report(scan_id):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': scan_id}

    try:
        response = requests.get(url, params=params)
        json_response = response.json()

        if 'verbose_msg' in json_response:
            print(json_response['verbose_msg'])
            if json_response['response_code'] == 1:
                positives = json_response['positives']
                total = json_response['total']
                if positives > 0:
                    print(f"Virus Found! ({positives}/{total} scan engines detected it)")
                else:
                    print("File is Safe.")
        else:
            print("Failed to retrieve the scan report.")
    except Exception as e:
        print("Error fetching VirusTotal report:", e)

def list_usb_devices():
    all_devices = hid.find_all_hid_devices()
    if not all_devices:
        print("No USB devices found.")
        return

    print("USB Devices on the Computer:")
    for device in all_devices:
        print(f"Vendor: {device.vendor_name}, Product: {device.product_name}, Serial: {device.serial_number}")

        device_path = device.device_path
        temp_file = f"{device_path}.temp"
        
        if copy_hid_data_to_file(device_path, temp_file):
            scan_id = virus_scan(temp_file)
            if scan_id:
                get_scan_report(scan_id)
            os.remove(temp_file)

        if detect_hid_attack(device):
            print("[ALERT] Suspicious USB HID detected! May be injecting keystrokes!")

def copy_hid_data_to_file(device_path, output_file):
    try:
        with open(device_path, 'rb') as hid_file, open(output_file, 'wb') as output:
            output.write(hid_file.read())
        return True
    except Exception as e:
        print("Error copying HID data:", e)
        return False

def list_usb_storage_devices():
    command = 'wmic diskdrive where "InterfaceType=\'USB\'" get DeviceID, Model, Size'
    
    try:
        result = subprocess.check_output(command, shell=True, text=True)
        lines = result.split('\n')
        print(lines[0])

        for line in lines[1:]:
            if line.strip():
                print(line)
                device_path = line.split()[0]

                check_usb_payloads(device_path)

    except Exception as e:
        print("Error listing USB storage devices:", e)

def check_usb_payloads(drive_path):
    autorun_path = os.path.join(drive_path, "autorun.inf")
    if os.path.exists(autorun_path):
        print("[ALERT] Autorun.inf found! Possible USB payload!")

    suspicious_extensions = ['.exe', '.bat', '.ps1', '.vbs', '.sh', '.scr']
    
    for root, dirs, files in os.walk(drive_path):
        for file in files:
            if file.lower().endswith(tuple(suspicious_extensions)):
                file_path = os.path.join(root, file)
                print(f"[WARNING] Suspicious file found: {file_path}")
                scan_id = virus_scan(file_path)
                if scan_id:
                    get_scan_report(scan_id)

    hidden_files = detect_hidden_files(drive_path)
    if hidden_files:
        print(f"[ALERT] Hidden files detected: {hidden_files}")

def detect_hid_attack(device):
    try:
        device.open()
        data = device.find_feature_reports()
        device.close()

        if data and len(data) > 5:  
            print(f"[ALERT] HID device {device.product_name} is behaving like a keyboard. Possible attack!")
            return True
    except Exception as e:
        print("Error analyzing HID device:", e)
    return False

def detect_hidden_files(drive_path):
    try:
        hidden_files = []
        command = f'attrib "{drive_path}\\*" /s /d'
        result = subprocess.check_output(command, shell=True, text=True)
        
        for line in result.split("\n"):
            if line.startswith("H") or line.startswith("SH"):  # Hidden/System file flags
                match = re.search(r"([A-Za-z]:\\.*)", line)
                if match:
                    hidden_files.append(match.group(1))

        return hidden_files
    except Exception as e:
        print("Error detecting hidden files:", e)
        return []

if __name__ == "__main__":
    print("Scanning USB Devices...")
    list_usb_devices()

    print("Scanning USB Storage Devices...")
    list_usb_storage_devices()
