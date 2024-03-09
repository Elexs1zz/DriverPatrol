import os
import pywinusb.hid as hid
import requests
import subprocess

def virus_scan(file_path):
    api_key = "api_key"

    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': api_key}
    files = {'file': (os.path.basename(file_path), open(file_path, 'rb'))}

    try:
        response = requests.post(url, files=files, params=params)
        json_response = response.json()

        if 'verbose_msg' in json_response:
            print(json_response['verbose_msg'])
            if json_response['response_code'] == 1:
                scan_id = json_response['scan_id']
                return scan_id
        else:
            print("Tarama sırasında bir hata oluştu.")
            return None
    except Exception as e:
        print("Hata:", e)
        return None


def get_scan_report(scan_id):

    api_key = "api_key"

    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': api_key, 'resource': scan_id}

    try:
        response = requests.get(url, params=params)
        json_response = response.json()

        if 'verbose_msg' in json_response:
            print(json_response['verbose_msg'])
            if json_response['response_code'] == 1:
                positives = json_response['positives']
                total = json_response['total']
                if positives > 0:
                    print(f"Virüs tespit edildi! ({positives}/{total} tarama motoru)")
                else:
                    print("Dosya güvenli.")
        else:
            print("Tarama raporu alınamadı.")
    except Exception as e:
        print("Hata:", e)


def copy_hid_data_to_file(device_path, output_file):
    try:
        with open(device_path, 'rb') as hid_file:
            with open(output_file, 'wb') as output:
                output.write(hid_file.read())
        return True
    except Exception as e:
        print("Hata:", e)
        return False


def usb_devices():
    all_devices = hid.find_all_hid_devices()

    if not all_devices:
        print("USB aygıt bulunamadı.")
        return

    print("Bilgisayardaki USB Aygıtları:")
    for device in all_devices:
        print("Üretici: %s" % device.vendor_name)
        print("Ürün: %s" % device.product_name)
        print("Serino: %s" % device.serial_number)
        print()

        device_path = device.device_path
        temp_file = f"{device_path}.temp"
        if copy_hid_data_to_file(device_path, temp_file):
            scan_id = virus_scan(temp_file)
            if scan_id:
                get_scan_report(scan_id)
            os.remove(temp_file)


def usb_storage_devices():
    command = 'wmic diskdrive where "InterfaceType=\'USB\'" get DeviceID, Model, Size'

    try:
        result = subprocess.check_output(command, shell=True, text=True)
        lines = result.split('\n')
        print(lines[0])
        for line in lines[1:]:
            if line.strip():
                print(line)
                device_path = line.split()[0]
                scan_id = virus_scan(device_path)
                if scan_id:
                    get_scan_report(scan_id)
    except Exception as e:
        print("Hata:", e)


if __name__ == "__main__":
    print("Bilgisayardaki USB Cihazları:")
    usb_devices()
    print("Bilgisayardaki USB Depolama Cihazları:")
    usb_storage_devices()


