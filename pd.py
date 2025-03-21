##
## Copyright (C) 2025 Benjamin Vernoux <bvernoux@hydrabus.com>
## All Rights Reserved.
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, see <http://www.gnu.org/licenses/>.
##
## hydranfc_v2_sniffer_iso14443a v0.8.3.2 21 Mar 2025 B.VERNOUX
## Compatible with sigrok PulseView v0.5(libsigrokdecode v0.6 / Python 3.4)
## Compatible with DreamSourceLab DSView v1.3.2 (libsigrokdecode4DSL 0.6.0 / Python 3.6)
##

import sigrokdecode as srd
from enum import Enum, unique

def roundto(x, k=1.0):
    return round(x / k) * k

@unique
class Ann(Enum):
    READER_BIT = 0
    READER_DATA = 1
    READER_COMMAND = 2
    TAG_BIT = 3
    TAG_DATA = 4
    TAG_ANSWER = 5
    DEBUG_MESSAGE = 6

    def __int__(self):
        return self.value

class TagType(Enum):
    UNKNOWN = 0
    MIFARE_CLASSIC_1K = 1
    MIFARE_CLASSIC_4K = 2
    MIFARE_ULTRALIGHT = 3
    NTAG = 4  # Could be more specific if needed
    OTHER = 5
    MIFARE_CLASSIC_2K = 6
    MIFARE_MINI = 7
    MIFARE_PLUS_2K = 8
    MIFARE_PLUS_4K = 9
    MIFARE_DESFIRE = 10
    INFINEON_MIFARE_CLASSIC_1K = 11
    NOKIA_MIFARE_CLASSIC_4K = 12
    GEMPLUS_MPCOS = 13
    INNOVISION_RT_JEWEL = 14
    NTAG424DNA = 15

class Decoder(srd.Decoder):
    api_version = 3
    id = 'hydranfc_v2_sniffer'
    name = 'HydraNFC V2 Sniffer'
    longname = 'HydraNFC v2 Sniffer ISO14443A/Mifare v0.8.3.2 21 Mar 2025 B.VERNOUX'
    desc = 'ISO14443A/Mifare protocol decoder for HydraNFC v2 ST25R3916 sniffer output.'
    license = 'gplv2+'
    inputs = ['logic']
    outputs = ['hydranfc_v2_sniffer']
    tags = ['RFID', 'NFC', 'ISO14443A', 'Mifare']

    channels = (
        {'id': 'cso', 'name': 'CSO', 
         'desc': 'ST25R3916 digital demodulator output'},
    )
    
    options = (
            {'id': 'nfc_type', 'desc': 'NFC Type', 'default': 'NFC-A',
             'values': ('NFC-A',)},
            {'id': 'timeout_tag_us', 'desc': 'Timeout Tag in µs', 'default': 10000},
            {'id': 'baudrate', 'desc': 'Baud rate', 'default': 106000,
             'values': (106000,)},
            {'id': 'edge', 'desc': 'Edge', 'default': 'rising',
             'values': ('rising',)},
        )
    annotations = (
        ('reader-bit', 'Reader Bit'),              # 0
        ('reader-datum', 'Reader Datum'),          # 1
        ('reader-command', 'Reader Command'),      # 2
        ('tag-bit', 'Tag Bit'),                    # 3
        ('tag-datum', 'Tag Datum'),                # 4
        ('tag-answer', 'Tag Answer'),              # 5
        ('debug-message', 'Debug Message'),        # 6
    )

    annotation_rows = (
            ('reader-bits', 'Reader Bits', (int(Ann.READER_BIT),)),                    # 0
            ('reader-data', 'Reader Data', (int(Ann.READER_DATA),)),                   # 1
            ('reader-commands', 'Reader Commands', (int(Ann.READER_COMMAND),)),        # 2
            ('tag-bits', 'Tag Bits', (int(Ann.TAG_BIT),)),                             # 3
            ('tag-data', 'Tag Data', (int(Ann.TAG_DATA),)),                            # 4
            ('tag-answers', 'Tag Answers', (int(Ann.TAG_ANSWER),)),                    # 5
            ('debug-messages', 'Debug Messages', (int(Ann.DEBUG_MESSAGE),)),           # 6
    )

    # NFC Command Name Lookup with 1- and 2-byte Commands
    NFC_COMMAND_NAMES = {
        0x26: 'REQA',
        0x52: 'WUPA',
        0x50: 'HALT',
        0x30: 'READ',
        0x39: 'READ-CNT',
        0x1B: 'PWD-AUTH',
        0x3A: 'FAST-READ',
        0x3C: 'READ-SIG',
        0x60: 'MC-AUTH-A',
        0x61: 'MC-AUTH-B',
        0xA0: 'MC-WRITE',
        0xA2: 'WRITE',
        0xE0: 'RATS',
        # 2-byte commands using tuples as keys
        (0x93, 0x20): 'ANTICOL CL1',
        (0x93, 0x70): 'SELECT CL1',
        (0x95, 0x20): 'ANTICOL CL2',
        (0x95, 0x70): 'SELECT CL2',
        (0x97, 0x20): 'ANTICOL CL3',
        (0x97, 0x70): 'SELECT CL3',
    }

    # NFC Response Name Lookup
    NFC_RESPONSE_NAMES = {
        0x26: 'ATQA',            # REQA
        0x52: 'ATQA',            # WUPA
        0x40: 'PPS',             # 
        (0x93, 0x20): 'UID CL1', # ANTICOL-CL1 UID
        (0x93, 0x70): 'SAK CL1', # SELECT command response
        (0x95, 0x20): 'UID CL2', # ANTICOL-CL2 UID
        (0x95, 0x70): 'SAK CL2', # SELECT command response (cascade level 2)
        (0x97, 0x20): 'UID CL3', # ANTICOL-3 UID
        (0x97, 0x70): 'SAK CL3', # SELECT command response (cascade level 3)
        0xE0: 'ATS',             # RATS
    }

    def __init__(self):
        self.reset()

    def reset(self):
        self.samplerate = None
        self.timeunit = 0
        self.frame_start = 0
        self.last_frame_end = 0
        self.decoder_state = 'READER'
        self.last_reader_cmd = None
        self.matched_check = False
        self.libsigrokdecode_v0_6 = False
        self.tag_crypto = False
        self.tag_type = TagType.UNKNOWN
        self.atqa = None
        self.sak_cl1 = None
        self.sak_cl2 = None
        self.sak_cl3 = None
        self.last_reader_cmd = None

    def metadata(self, key, value):
        if key == srd.SRD_CONF_SAMPLERATE:
            self.samplerate = value
            self.timeunit = int(self.samplerate / self.options['baudrate'])
            self.timeout_tag_us = self.options['timeout_tag_us']

    def start(self):
        self.out_ann = self.register(srd.OUTPUT_ANN)

    def check_matched(self, channel=0):
        if self.matched_check == False:
            self.matched_check = True
            if type(self.matched) == tuple:
                self.libsigrokdecode_v0_6 = True
            else:
                self.libsigrokdecode_v0_6 = False
        
        if self.libsigrokdecode_v0_6:
            return self.matched[channel]
        else:
            return (self.matched & (1 << channel)) != 0

    def iso14443a_crc(self, data):
        wCrc = 0x6363
        for bt in data:
            bt = bt ^ (wCrc & 0xFF)
            bt = bt ^ ((bt << 4) & 0xFF)
            wCrc = (wCrc >> 8) ^ (bt << 8) ^ (bt << 3) ^ (bt >> 4)
        return wCrc & 0xFFFF

    def validate_bcc(self, uid_bytes):
        bcc = 0
        for byte in uid_bytes:
            bcc ^= byte
        return bcc

    def decode_reader_bits(self):
        timeunit = self.samplerate / self.options['baudrate']
        edgetype = self.options['edge'][0]
        
        self.wait({0: edgetype})
        prevedge = self.samplenum
        
        self.put(int(prevedge), int(prevedge + timeunit), 
                self.out_ann, [int(Ann.READER_BIT), ['SOF']])
        
        expectedstart = self.samplenum + timeunit
        self.frame_start = expectedstart
        prevbit = 0
        bits = []

        while True:
            self.wait([{0: edgetype}, {'skip': int(3 * timeunit)}])
            sampledelta = (self.samplenum - prevedge)
            prevedge = self.samplenum
            timedelta = roundto(sampledelta / timeunit, 0.5)

            if prevbit == 0:
                if timedelta == 1.0:
                    bits.append(0)
                    self.put(int(expectedstart), int(expectedstart + timeunit),
                            self.out_ann, [int(Ann.READER_BIT), ['0']])
                    prevbit = 0
                    expectedstart = self.samplenum + timeunit
                elif timedelta == 1.5:
                    bits.append(1)
                    self.put(int(expectedstart), int(expectedstart + timeunit),
                            self.out_ann, [int(Ann.READER_BIT), ['1']])
                    prevbit = 1
                    expectedstart = self.samplenum + timeunit*0.5
                elif timedelta >= 1.6:
                    self.last_frame_end = int(self.samplenum - 2*timeunit)
                    self.put(int(self.samplenum - 2*timeunit), int(self.samplenum),
                            self.out_ann, [int(Ann.READER_BIT), ['EOF']])
                    return bits
                else:
                    return None
            else:
                if timedelta <= 0.5:
                    return None
                if timedelta == 1.0:
                    bits.append(1)
                    self.put(int(expectedstart), int(expectedstart + timeunit),
                            self.out_ann, [int(Ann.READER_BIT), ['1']])
                    prevbit = 1
                    expectedstart = self.samplenum + timeunit*0.5
                elif timedelta == 1.5:
                    bits.extend([0, 0])
                    self.put(int(expectedstart), int(expectedstart + timeunit),
                            self.out_ann, [int(Ann.READER_BIT), ['0']])
                    self.put(int(expectedstart + timeunit), int(expectedstart + 2*timeunit),
                            self.out_ann, [int(Ann.READER_BIT), ['0']])
                    prevbit = 0
                    expectedstart = self.samplenum + timeunit
                elif timedelta == 2.0:
                    bits.extend([0, 1])
                    self.put(int(expectedstart), int(expectedstart + timeunit),
                            self.out_ann, [int(Ann.READER_BIT), ['0']])
                    self.put(int(expectedstart + timeunit), int(expectedstart + 2*timeunit),
                            self.out_ann, [int(Ann.READER_BIT), ['1']])
                    prevbit = 1
                    expectedstart = self.samplenum + timeunit*0.5
                else:
                    bits.append(0)
                    self.put(int(expectedstart), int(expectedstart + timeunit),
                            self.out_ann, [int(Ann.READER_BIT), ['0']])
                    self.last_frame_end = int(expectedstart + timeunit)
                    self.put(int(self.samplenum - 2*timeunit), int(self.samplenum),
                            self.out_ann, [int(Ann.READER_BIT), ['EOF']])
                    return bits

    def lookup_nfc_command(self, data_bytes):
        if not data_bytes:
            return "NO DATA"

        if(self.tag_crypto == False):
            if len(data_bytes) >= 2:
                cmd_name = self.NFC_COMMAND_NAMES.get((data_bytes[0], data_bytes[1]))
                if cmd_name:
                    return cmd_name

            cmd_name = self.NFC_COMMAND_NAMES.get(data_bytes[0])
            if cmd_name:
                return cmd_name
        else:
            return "Encrypted: "

        return "UNKNOWN CMD: "

    def decode_command(self, bits):
        if not bits or len(bits) < 8:
            return

        data_bytes = []
        i = 0
        while i < len(bits):
            if len(bits) - i < 8: break
            byte_bits = bits[i:i + 8]
            if i + 8 < len(bits):
                parity_bit = bits[i + 8]
            byte = sum(b << j for j, b in enumerate(byte_bits))
            data_bytes.append(byte)
            i += 9

        if not data_bytes:
            return

        status = ""
        display_bytes = data_bytes.copy()
        raw_hex = ' '.join('{:02X}'.format(byte) for byte in data_bytes)

        if self.tag_crypto:
            num_bytes = len(data_bytes)
            if num_bytes == 1 and data_bytes[0] in (0x26, 0x52): # REQA(0x26), WUPA(0x52) encrypted data are stopped
                self.tag_crypto = False
                self.last_reader_cmd = data_bytes

        if not self.tag_crypto and len(data_bytes) >= 3:
            if data_bytes[0] in [0x93, 0x95, 0x97] and data_bytes[1] == 0x70:  # SELECT CLx
                cmd_bytes = data_bytes[0:2]
                uid_bytes = data_bytes[2:-3]
                bcc = data_bytes[-3]
                
                # BCC check on UID only
                calculated_bcc = self.validate_bcc(uid_bytes)
                bcc_ok = calculated_bcc == bcc
                
                # CRC check includes command + UID + BCC
                msg_data = data_bytes[:-2]
                received_crc = (data_bytes[-1] << 8) | data_bytes[-2]
                calculated_crc = self.iso14443a_crc(msg_data)
                crc_ok = calculated_crc == received_crc
                
                display_bytes = cmd_bytes + uid_bytes
                
                if bcc_ok and crc_ok:
                    status = " (BCC&CRC OK)"
                elif not bcc_ok and not crc_ok:
                    status = " (BCC&CRC ERR)"
                elif not bcc_ok:
                    status = " (BCC ERR)"
                else:
                    status = " (CRC ERR)"
            else:  # Other commands including RATS
                msg_data = data_bytes[:-2]
                received_crc = (data_bytes[-1] << 8) | data_bytes[-2]
                calculated_crc = self.iso14443a_crc(msg_data)
                status = " (CRC OK)" if calculated_crc == received_crc else " (CRC ERR)"
                display_bytes = msg_data

        self.put(int(self.frame_start), int(self.last_frame_end),
                 self.out_ann, [int(Ann.READER_DATA), ['{}'.format(raw_hex)]])

        hex_data = ' '.join('{:02X}'.format(byte) for byte in display_bytes)
        cmd_name = self.lookup_nfc_command(display_bytes)

        if(cmd_name != "UNKNOWN CMD: "):
            self.put(int(self.frame_start), int(self.last_frame_end), 
                    self.out_ann, [int(Ann.READER_COMMAND), ['{} ({}){}'.format(cmd_name, hex_data, status)]])
        else:
            self.put(int(self.frame_start), int(self.last_frame_end), 
                    self.out_ann, [int(Ann.READER_COMMAND), ['{} {}{}'.format(cmd_name, hex_data, status)]])

        if(self.tag_crypto == False):
            self.last_reader_cmd = data_bytes
            if(data_bytes[0] == 0x60 or data_bytes[0] == 0x61): # MC-AUTH-A / MC-AUTH-B
                if (self.tag_type == TagType.MIFARE_CLASSIC_1K or self.tag_type == TagType.MIFARE_CLASSIC_4K or 
                   self.tag_type == TagType.MIFARE_CLASSIC_2K or self.tag_type == TagType.MIFARE_MINI or 
                   self.tag_type == TagType.MIFARE_PLUS_2K or self.tag_type == TagType.MIFARE_PLUS_4K or 
                   self.tag_type == TagType.MIFARE_DESFIRE or self.tag_type == TagType.INFINEON_MIFARE_CLASSIC_1K or 
                   self.tag_type == TagType.NOKIA_MIFARE_CLASSIC_4K):
                    self.tag_crypto = True
                    self.put(int(self.frame_start), int(self.last_frame_end), self.out_ann, [int(Ann.DEBUG_MESSAGE), ['tag_crypto set to: {}'.format(self.tag_crypto)]])
                else:
                    self.tag_crypto = False
                    self.put(int(self.frame_start), int(self.last_frame_end), self.out_ann, [int(Ann.DEBUG_MESSAGE), ['tag_crypto set to: {}'.format(self.tag_crypto)]])
        else:
            self.last_reader_cmd = None

    def conv_nb_sample_to_us(self, nb_sample):
        return (nb_sample * (1 / self.samplerate) * 1000000)

    def conv_us_to_nb_sample(self, time_us):
        return (self.samplerate * time_us / 1000000)

    def detect_nfc_card_type(self, atqa, sak_cl1, sak_cl2, sak_cl3):
        """
        Detects the NFC card type based on ATQA and SAK values using Cascade Level information.

        Based on:
        - MIFARE Type Identification Procedure AN10833 (especially Table 5 and Table 6)
          https://www.nxp.com/docs/en/application-note/AN10833.pdf
        - http://nfc-tools.org/index.php/ISO14443A
        - https://www.nxp.com/docs/en/application-note/AN10834.pdf

        Args:
            atqa (list or tuple): ATQA bytes (e.g., [0x04, 0x00]).
            sak_cl1 (int or None): SAK byte from Cascade Level 1 (if applicable).
            sak_cl2 (int or None): SAK byte from Cascade Level 2 (if applicable).
            sak_cl3 (int or None): SAK byte from Cascade Level 3 (if applicable).

        Returns:
            TagType: An enum representing the detected tag type.
        """

        if atqa is None:
            return TagType.UNKNOWN

        atqa_val = (atqa[1] << 8) | atqa[0] if len(atqa) == 2 else 0
        # Use SAK from different cascade levels for better identification if available
        if sak_cl3 is not None:
            sak_val = sak_cl3
        elif sak_cl2 is not None:
            sak_val = sak_cl2
        elif sak_cl1 is not None:
            sak_val = sak_cl1
        else:
            sak_val = 0

        if sak_val == 0x00:
            if atqa_val == 0x0044:
                return TagType.MIFARE_ULTRALIGHT  # Could also be NTAG
            else:
                return TagType.UNKNOWN

        elif sak_val == 0x08:
            if atqa_val == 0x0004 or atqa_val == 0x0044:
                return TagType.MIFARE_CLASSIC_1K
            else:
                return TagType.MIFARE_CLASSIC_1K

        elif sak_val == 0x09:
            if atqa_val == 0x0004:
                return TagType.MIFARE_MINI
            else:
                return TagType.OTHER

        elif sak_val == 0x18:
            if atqa_val == 0x0002:
                return TagType.MIFARE_CLASSIC_4K
            elif atqa_val == 0x0042:
                return TagType.MIFARE_PLUS_4K
            else:
                return TagType.MIFARE_CLASSIC_4K

        elif sak_val == 0x88:
            return TagType.INFINEON_MIFARE_CLASSIC_1K
        
        elif sak_val == 0x20:
            if atqa_val == 0x0344:
                return TagType.NTAG424DNA
            else:
                return TagType.OTHER
            
        elif sak_val == 0x24 or sak_val == 0x28:
            if atqa_val == 0x0344:
                return TagType.MIFARE_DESFIRE
            else:
                return TagType.OTHER

        elif sak_val == 0x38:
            return TagType.NOKIA_MIFARE_CLASSIC_4K

        elif sak_val == 0x98:
            if atqa_val == 0x0002:
                return TagType.GEMPLUS_MPCOS
            else:
                return TagType.OTHER

        else:
            if atqa_val == 0x0c00:
                return TagType.INNOVISION_RT_JEWEL
            else:
                return TagType.OTHER

    def identify_tag_type(self, response_name, bytes_data):
        """
        Identifies the tag type, with a focus on Mifare Classic, called within annotate_tag_response.
        """
        # Check if bytes_data is valid before processing
        if bytes_data is None or len(bytes_data) == 0:
            self.put(int(self.frame_start), int(self.last_frame_end), self.out_ann, [int(Ann.DEBUG_MESSAGE), ['Empty or missing bytes_data for {}'.format(response_name)]])
            return

        if response_name.startswith("ATQA") and len(bytes_data) >= 2:
            self.atqa = bytes_data[:2]
        if response_name.startswith("SAK"):
            if self.atqa is not None:
                # Capture SAK from different cascade levels
                if self.last_reader_cmd and len(self.last_reader_cmd) > 0:
                    cmd_byte = self.last_reader_cmd[0]
                    if cmd_byte == 0x93:
                        self.sak_cl1 = bytes_data[0] if len(bytes_data) > 0 else None
                    elif cmd_byte == 0x95:
                        self.sak_cl2 = bytes_data[0] if len(bytes_data) > 0 else None
                    elif cmd_byte == 0x97:
                        self.sak_cl3 = bytes_data[0] if len(bytes_data) > 0 else None
                    
                    # Only attempt to detect tag type if we have valid SAK data
                    if (self.sak_cl1 is not None or self.sak_cl2 is not None or self.sak_cl3 is not None):
                        self.tag_type = self.detect_nfc_card_type(self.atqa, self.sak_cl1, self.sak_cl2, self.sak_cl3)
                        self.put(int(self.frame_start), int(self.last_frame_end), self.out_ann, [int(Ann.DEBUG_MESSAGE), ['{}'.format(self.tag_type)]])
                    else:
                        self.put(int(self.frame_start), int(self.last_frame_end), self.out_ann, [int(Ann.DEBUG_MESSAGE), ['SAK data is empty, cannot determine tag type']])
                else:
                    self.put(int(self.frame_start), int(self.last_frame_end), self.out_ann, [int(Ann.DEBUG_MESSAGE), ['Invalid or missing last_reader_cmd']])
            else:
                self.put(int(self.frame_start), int(self.last_frame_end), self.out_ann, [int(Ann.DEBUG_MESSAGE), ['ATQA is None, cannot determine tag type']])

    def analyze_tag_response(self, bytes_data):
        return ' '.join('{:02X}'.format(b) for b in bytes_data)

    def annotate_tag_response(self, data_start, bit_start, hex_data):
        if not self.last_reader_cmd:
            response_name = "Data"
        else:
            cmd_key = self.last_reader_cmd[0]
            # Check if any tuple keys in NFC_RESPONSE_NAMES start with this command
            if any(isinstance(k, tuple) and k[0] == cmd_key for k in self.NFC_RESPONSE_NAMES) and len(self.last_reader_cmd) >= 2:
                cmd_key = (self.last_reader_cmd[0], self.last_reader_cmd[1])
            response_name = self.NFC_RESPONSE_NAMES.get(cmd_key, "Data")

        bytes_data = [int(x, 16) for x in hex_data.split()]
        
        self.identify_tag_type(response_name, bytes_data)
        
        status = ""
        if not self.tag_crypto:
            if len(bytes_data) >= 3:
                if response_name in ["UID CL1", "UID CL2", "UID CL3"]:
                    uid_bytes = bytes_data[:-1]  # All bytes except BCC
                    received_bcc = bytes_data[-1]
                    calculated_bcc = self.validate_bcc(uid_bytes)
                    status = " (BCC OK)" if calculated_bcc == received_bcc else " (BCC ERR)"
                    display_data = ' '.join('{:02X}'.format(b) for b in uid_bytes)
                else:
                    msg_data = bytes_data[:-2]
                    received_crc = (bytes_data[-1] << 8) | bytes_data[-2]
                    calculated_crc = self.iso14443a_crc(msg_data)
                    status = " (CRC OK)" if calculated_crc == received_crc else " (CRC ERR)"
                    display_data = ' '.join('{:02X}'.format(b) for b in bytes_data[:-2])
            else:
                display_data = hex_data
        else:
            # Tag is likely using cryptography
            response_name = "Encrypted"  # Change response name to "Encrypted"
            display_data = hex_data

        if response_name.startswith("ATQA"):
            display_data = " ".join(display_data.split()[::-1])

        self.put(int(data_start), int(bit_start), 
                self.out_ann, [int(Ann.TAG_ANSWER), ['{}: {}{}'.format(response_name, display_data, status)]])

    def wait_tag_sof(self):
        start_sample = self.samplenum
        timeout_nb_us = self.timeout_tag_us
        timeout_samples = int(self.conv_us_to_nb_sample(timeout_nb_us))
        timeout_nb_us_calc = self.conv_nb_sample_to_us(timeout_samples)

        nfc_baudrate = self.options['baudrate'] # Expected to be 1060000 (106KHz)
        subcarrier_frequency = nfc_baudrate * 8 # Manchester subcarrier = 8*nfc_baudrate (848KHz expected)
        subcarrier_frequency_adjust = (subcarrier_frequency * 6) / 100 # Adjust for higher frequency +6%
        subcarrier_period = round(self.samplerate / (subcarrier_frequency + subcarrier_frequency_adjust)) # Adjust for higher frequency
        actual_frequency = self.samplerate / subcarrier_period

        skip_wait = subcarrier_period * 2

        wait_nb_sample = int(self.conv_us_to_nb_sample(0.5))
        while (self.samplenum - start_sample) <= timeout_samples:
            try:
                start = self.samplenum
                self.wait([{0: 'e'}, {'skip': int((timeout_samples) - (subcarrier_period * 2 + wait_nb_sample))}])
                potential_sof = self.samplenum - (subcarrier_period / 2)
                edge_count = 1
                
                for _ in range(7): # There is only 7 edge at TAG SOF 
                    self.wait([{0: 'e'}, {'skip': int(subcarrier_period * 2)}])
                    if self.check_matched(0):
                        edge_count += 1

                if edge_count >= 6:
                    # Wait a full bit "16 * subcarrier_period" - time already spent
                    wait_time_nb_samples = ((16 * subcarrier_period) / 2) - (self.samplenum - potential_sof)

                    self.wait([{'skip': int(wait_time_nb_samples)}])

                    self.put(int(potential_sof), self.samplenum, 
                            self.out_ann, [int(Ann.TAG_BIT), ['SOF']])
                    return True

            except StopIteration:
                break

        self.put(int(start_sample), int(self.samplenum),
                self.out_ann, [int(Ann.TAG_BIT), ['Timeout waiting for TAG SOF ({}µs)'.format(timeout_nb_us)]])
        return False

    def decode_tag_bits(self):
        data_start = self.samplenum
        bits = []
        nfc_baudrate = self.options['baudrate'] # Expected to be 1060000 (106KHz)
        subcarrier_frequency = nfc_baudrate * 8 # Manchester subcarrier = 8*nfc_baudrate (848KHz expected)
        subcarrier_frequency_adjust = (subcarrier_frequency * 6) / 100 # Adjust for higher frequency +6%
        subcarrier_period = round(self.samplerate / (subcarrier_frequency + subcarrier_frequency_adjust)) # Adjust for higher frequency
        bit_period = subcarrier_period * 8
        half_period = bit_period // 2
        edge_window = subcarrier_period // 4
        decode_bit_error = False

        def count_edges_in_window(start_time, duration):
            """Count edges in a specified time window"""
            edges = 0
            end_time = start_time + duration
            first_edge_time = None
            last_edge_time = None
            pattern_timeout = int(duration * 0.5)
            
            while True:
                try:
                    before = self.samplenum
                    self.wait([{0: 'e'}, {'skip': edge_window}])
                    
                    if self.check_matched(0):
                        edges += 1
                        
                        if first_edge_time is None:
                            first_edge_time = self.samplenum
                        last_edge_time = self.samplenum
                        
                        if edges == 8:
                            break
                        
                        # Keep searching if we're finding edges
                        continue
                    
                    # For zero windows, stop at normal duration
                    if first_edge_time is None:
                        if self.samplenum >= end_time:
                            break
                    # For edge patterns, allow timeout from last edge
                    elif self.samplenum >= last_edge_time + pattern_timeout:
                        break
                        
                except StopIteration:
                    break
            
            return edges

        bit_count = 0
        while True:
            try:
                bit_start = self.samplenum
                # Count edges in first and second half
                before = self.samplenum
                first_edges = count_edges_in_window(before, half_period)
                after = self.samplenum

                before = self.samplenum
                second_edges = count_edges_in_window(before, half_period)
                after = self.samplenum

                bit_end = self.samplenum
                # Check for EOF
                if first_edges <= 1 and second_edges <= 1:
                    if bits:
                        self.put(int(bit_start), int(bit_end),
                                self.out_ann, [int(Ann.TAG_BIT), ['EOF']])
                    break
                # Check invalid case
                if first_edges >= 7 and second_edges >= 7:
                    if bits:
                        decode_bit_error = True
                        self.put(int(bit_start), int(bit_end),
                                self.out_ann, [int(Ann.TAG_BIT), ['ERR']])
                    break
                # Decode bit value
                bit = 1 if first_edges > second_edges else 0
                bits.append(bit)

                self.put(int(bit_start), int(bit_end), self.out_ann, [int(Ann.TAG_BIT), ['{}'.format(bit)]])

                bit_count += 1

            except StopIteration:
                break

        self.frame_start = data_start
        self.last_frame_end = bit_start
        # Process decoded bits into bytes
        if bits:
            data_bytes = []
            for i in range(0, len(bits), 9):
                byte_bits = bits[i:i+8]
                if len(byte_bits) >= 4:
                    byte = sum(b << i for i, b in enumerate(byte_bits))
                    data_bytes.insert(0, byte)

            if len(data_bytes) > 1:
                data_bytes.reverse()

            if decode_bit_error == False:
                hex_data = self.analyze_tag_response(data_bytes)
                self.put(int(data_start), int(bit_start),
                        self.out_ann, [int(Ann.TAG_DATA), [hex_data]])
            else:
                hex_data = self.analyze_tag_response(data_bytes)
                self.put(int(data_start), int(bit_start),
                        self.out_ann, [int(Ann.TAG_DATA), [hex_data+ " ERROR TO DECODE BIT"]])

            self.annotate_tag_response(data_start, bit_start, hex_data)

        return bits

    def decode(self):
        if not self.samplerate:
            raise Exception("Samplerate required")

        while True:
            bits = self.decode_reader_bits()
            if bits:
                self.decode_command(bits)
                if self.wait_tag_sof():
                    self.decode_tag_bits()