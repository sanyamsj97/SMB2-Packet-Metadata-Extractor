Here's a detailed README for your script:

---

# SMB2 Packet Metadata Extractor

This script processes a pcap file to extract and log metadata from SMB2 packets. It handles specific SMB2 commands such as CREATE_REQUEST, READ_REQUEST, READ_RESPONSE, WRITE_REQUEST, and WRITE_RESPONSE. The metadata is saved to a JSON file and individual packets' details are written to separate text files.

## Requirements

- Python 3.x
- Scapy library

## Installation

1. Ensure you have Python 3 installed.
2. Install the required library `scapy` using pip:

```bash
pip install scapy
```

## How to Run

1. Clone or download this repository to your local machine.
2. Ensure the script `smb2_packet_extractor.py` is in your working directory.
3. Prepare your pcap file that contains the SMB2 traffic you want to analyze.
4. Run the script from the command line with the pcap file as an argument:

```bash
python smb2_packet_extractor.py path/to/your/input-file.pcap
```

### Example

```bash
python smb2_packet_extractor.py sample.pcap
```

## Output

1. **smb_metadata.json**: A JSON file containing metadata of all processed SMB2 packets.
2. **Output/Read_Response_[timestamp].txt**: Text files for each READ_RESPONSE packet, containing detailed packet information.
3. **Output/Write_Response_[timestamp].txt**: Text files for each WRITE_RESPONSE packet, containing detailed packet information.
4. **Output/Read_Request_[timestamp].txt**: Text files for each READ_REQUEST packet, containing detailed packet information.
5. **Output/Write_Request_[timestamp].txt**: Text files for each WRITE_REQUEST packet, containing detailed packet information.

### Metadata Information

The metadata JSON file includes details such as:
- Command type
- Source and Destination IP addresses and ports
- Timestamp
- Filename (decoded from UTF-16-LE)
- File size (if applicable)

## Logging

The script logs various stages of its execution, including:
- The total number of SMB2 packets processed.
- Errors encountered during packet processing.

## Error Handling

The script includes error handling to manage cases such as:
- File not found errors.
- Packet processing errors.
- Unicode decoding errors.

## Functions

### `decode_utf16le(data)`

Decodes a byte string from UTF-16-LE or returns its hex representation on failure.

### `process_create_request(packet)`

Processes SMB2_CREATE_REQUEST packets and logs details without updating main metadata.

### `extract_smb2_details(packet, input_file)`

Extracts metadata and details from an SMB2 packet. It handles different SMB2 commands and writes detailed information to text files.

### `main(input_file)`

Main function to process the input pcap file and extract SMB2 packet details. It reads the pcap file, processes each packet, and saves metadata to a JSON file.

## Notes

- Ensure the `Output` directory exists in your working directory. If not, create it manually to store the individual packet details files.
- This script assumes basic familiarity with pcap files and SMB2 protocol. Make sure your pcap file includes SMB2 traffic.

---

This README provides a comprehensive guide on how to run the script, what it does, and what outputs to expect. It also includes installation instructions and error handling information for ease of use.
