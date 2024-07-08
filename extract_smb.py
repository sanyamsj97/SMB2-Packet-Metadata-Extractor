import sys
import json
import os
import logging
import subprocess
from scapy.all import *

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def decode_utf16le(data):
    """Decode a byte string from UTF-16-LE, or return its hex representation on failure."""
    try:
        return data.decode('utf-16-le').rstrip('\x00')  # Strip trailing null characters
    except UnicodeDecodeError:
        return data.hex()  # Return hexadecimal representation on decoding error

def extract_smb_files(pcap_file, output_dir=None):
    """Extract SMB files from a pcap file using Tshark."""
    extracted_files_names = {}
    extracted_files_sizes = {}

    # Verify the pcap file exists
    if not os.path.isfile(pcap_file):
        print(f"Error: The file '{pcap_file}' does not exist.")
        return
    
    # If no output directory is specified, create a default one in the same directory as the pcap file
    if output_dir is None:
        output_dir = os.path.join(os.path.dirname(pcap_file), 'extracted_files')
    
    # Ensure the output directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Define the Tshark command for exporting SMB objects
    tshark_command = [
        'tshark',
        '-r', pcap_file,                   # Input file
        '--export-objects', f'smb,{output_dir}'  # Export SMB objects to output directory
    ]

    # Execute the Tshark command
    try:
        subprocess.run(tshark_command, check=True)
        
        # Iterate through the files in the output directory and store their names and sizes
        for root, dirs, files in os.walk(output_dir):
            for file in files:
                file_path = os.path.join(root, file)
                file_size = os.path.getsize(file_path)
                
                # Format file name as required (replace '\' with '%5c')
                formatted_filename = file.replace('\\', '%5c')

                # Store filename and size separately in their respective dictionaries
                #extracted_files_names[formatted_filename] = formatted_filename
                #extracted_files_sizes[formatted_filename] = file_size
                extracted_files_names = formatted_filename
                extracted_files_sizes[formatted_filename] = file_size

                
                
    except subprocess.CalledProcessError as e:
        logging.error(f"Error occurred while running Tshark: {e}")

    return extracted_files_names, extracted_files_sizes

def extract_smb2_details(packet, extracted_files_names, extracted_files_sizes):
    """Extract metadata and details from an SMB2 packet."""
    smb2_header = packet[SMB2_Header]
    command = smb2_header.fields.get('Command')

    # Initialize metadata
    metadata = None  # Start with None

    try:
        if command == 0x0008 and SMB2_Read_Response in packet:  # SMB2_READ_RESPONSE
            smb2_read_resp = packet[SMB2_Read_Response]
            for filename, size in extracted_files_sizes.items():
             filesize=size
            metadata = {
                "Command": command,
                "SourceIP": packet[IP].src,
                "SourcePort": packet[TCP].sport,
                "DestIP": packet[IP].dst,
                "DestPort": packet[TCP].dport,
                "Timestamp": float(packet.time),
                "FileName": extracted_files_names,
                "FileSize": filesize
            }
            file_path = f'Output/Read_Response_{packet.time}.txt'

            with open(file_path, 'w') as file:
                file.write(f"Metadata: {json.dumps(metadata)}\n")
                for key, value in smb2_read_resp.fields.items():
                    file.write(f"Key: {key}, Value: {value}\n")

        elif command == 0x0009 and SMB2_Write_Response in packet:  # SMB2_WRITE_RESPONSE
            smb2_write_resp = packet[SMB2_Write_Response]
            for filename, size in extracted_files_sizes.items():
             filesize=size
            metadata = {
                "Command": command,
                "SourceIP": packet[IP].src,
                "SourcePort": packet[TCP].sport,
                "DestIP": packet[IP].dst,
                "DestPort": packet[TCP].dport,
                "Timestamp": float(packet.time),
                "FileName": extracted_files_names,
                "FileSize": filesize
            }
            file_path = f'Output/Write_Response_{packet.time}.txt'

            with open(file_path, 'w') as file:
                file.write(f"Metadata: {json.dumps(metadata)}\n")
                for key, value in smb2_write_resp.fields.items():
                    file.write(f"Key: {key}, Value: {value}\n")

        elif command == 0x0008 and SMB2_Read_Request in packet:  # SMB2_READ_REQUEST
            smb2_read_req = packet[SMB2_Read_Request]
            for filename, size in extracted_files_sizes.items():
             filesize=size
            
            metadata = {
                "Command": command,
                "SourceIP": packet[IP].src,
                "SourcePort": packet[TCP].sport,
                "DestIP": packet[IP].dst,
                "DestPort": packet[TCP].dport,
                "Timestamp": float(packet.time),
                "FileName": extracted_files_names,
                "FileSize": filesize
            }
            file_path = f'Output/Read_Request_{packet.time}.txt'

            with open(file_path, 'w') as file:
                file.write(f"Metadata: {json.dumps(metadata)}\n")
                for key, value in smb2_read_req.fields.items():
                    file.write(f"Key: {key}, Value: {value}\n")

        elif command == 0x0009 and SMB2_Write_Request in packet:  # SMB2_WRITE_REQUEST
            smb2_write_req = packet[SMB2_Write_Request]
            for filename, size in extracted_files_sizes.items():
             filesize=size
            metadata = {
                "Command": command,
                "SourceIP": packet[IP].src,
                "SourcePort": packet[TCP].sport,
                "DestIP": packet[IP].dst,
                "DestPort": packet[TCP].dport,
                "Timestamp": float(packet.time),
                "FileName": extracted_files_names,
                "FileSize": filesize
            }
            file_path = f'Output/Write_Request_{packet.time}.txt'

            with open(file_path, 'w') as file:
                file.write(f"Metadata: {json.dumps(metadata)}\n")
                for key, value in smb2_write_req.fields.items():
                    file.write(f"Key: {key}, Value: {value}\n")

    except Exception as e:
        logging.error(f"Error processing SMB2 packet: {e}")

    return metadata

def main(input_file):
    """Main function to process the input pcap file and extract SMB2 packet details."""
    try:
        # Initialize empty dictionaries for extracted file names and sizes
        extracted_files_names = {}
        extracted_files_sizes = {}

        # Extract SMB files from pcap
        extracted_files_names, extracted_files_sizes = extract_smb_files(input_file)

        all_metadata = []
        smb2_packet_count = 0

        # Read packets from the input pcap file
        for packet in rdpcap(input_file):
            try:
                if SMB2_Header in packet:
                    details = extract_smb2_details(packet, extracted_files_names, extracted_files_sizes)
                    if details:
                        all_metadata.append(details)
                        smb2_packet_count += 1

            except Exception as e:
                logging.error(f"Error processing packet: {e}")

        # Write all_metadata to a JSON file
        output_file = 'smb_metadata.json'
        with open(output_file, 'w') as f:
            json.dump(all_metadata, f, indent=4, default=str)

        logging.info(f"Metadata saved to {output_file}")
        logging.info(f"Total number of SMB2 packets: {smb2_packet_count}")

    except FileNotFoundError:
        logging.error(f"File '{input_file}' not found.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 your-program.py input-file")
    else:
        input_file = sys.argv[1]
        main(input_file)
