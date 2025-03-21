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

'''
HydraNFC v2 ISO14443A/Mifare Sniffer protocol decoder.
This protocol decoder handles ISO14443A/Mifare communications captured by 
HydraNFC v2's ST25R3916 analog frontend and digital demodulator.

Features:
- Decodes ISO14443A commands & responses (REQA, ATQA, SELECT, RATS...)
- Supports all UID sizes (4, 7, 10 bytes)
- Validates ISO14443A CRC16 for commands and responses
- Validates BCC for UID and SELECT commands
- Detects encrypted Mifare Classic communication (disables CRC validation)
- Processes synchronous demodulator output (CSO)
- Operates at ISO14443A 106 kbps baudrate
- Detect Tag Type Mifare Classic 1K/4K/UltraLight ...

Data Display:
- Reader Data: Shows all raw bytes including BCC/CRC
- Reader Command: Shows command bytes without BCC/CRC and validation status
- Tag Data: Shows all raw bytes including BCC/CRC
- Tag Answer: Shows response bytes without BCC/CRC and validation status

Validation Status:
- CRC OK/ERR: For commands and responses with CRC16
- BCC OK/ERR: For UID responses
- BCC&CRC OK/ERR: For SELECT commands (both checks)
'''

from .pd import Decoder
