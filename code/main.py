# Michael "Mickey" Kerr - 2023 UNR

# This script will take all information from a BLE pcapng file, parse it, and 
# put it into a table file organized by MACID and time 
# Information should include the following:
#   Data
#   MACID
#   RSSI


#import files
from pcapng import FileScanner
from pcapng.blocks import EnhancedPacket
from binascii import hexlify
import os
import csv

#block class for storing data
class blockEntry:
    def __init__(self, rssi, aMacID, sMacID, bleType, data):
        self.rssi = rssi
        self.aMacID = aMacID
        self.sMacID = sMacID
        self.bleType = bleType
        self.data = data


#chunkify script to seperate
def chunkify(lst, n):
    n = max(1, n)
    return (lst[i: i + n] for i in range(0, len(lst), n))


def main():
    # List files in packet-captures

    packetCapNum = 0

    packetCapPath = "..//packet-captures"
    dirList = os.listdir(packetCapPath)

    for entry in dirList:
        displayLine = str(packetCapNum) + "\t-\t" + entry
        print(displayLine)
        packetCapNum = packetCapNum + 1


    #Take input
    print("Enter packet capture number: ")
    packetCapToProcessNum = input()
    packetCapToProcessNum = int(packetCapToProcessNum)

    if(packetCapToProcessNum < 0 or packetCapToProcessNum > packetCapNum):
        print("INVALID NUMBER, please run the script again")
        exit

    packetCapToProcess = dirList[packetCapToProcessNum]



    # Open input for processing and store in var
    scannerOutRaw = []

    with open('..//packet-captures//' + packetCapToProcess, 'rb') as fp:
        scanner = FileScanner(fp)
    
        for block in scanner:
            if isinstance(block, EnhancedPacket):
                scannerOutRaw.append(block.packet_data)
    
                
    #get all blocks
    allBlocks = []

    for entry in scannerOutRaw:


        #1st part nRF Scanner info
        # Board 
        # Header (get header length from second byte)
        # Payload Length (from 3rd byte)
        traversal = 0

        rssi = -abs(int(entry[10]))
        advertisingMacID = str()
        scanningMacID = str()
        data = str()
        bleType = str()
        # print('-' + str(rssi))

        #need logic to determine scan req
        result = entry[21] & 15 # some binary & 00001111 = only the last 4 to find info

        #print(str(result) + "\t" + "{:08b}".format(int(result)))
        # if byte 21 ends with "0011", then is scan request
        if(result == 3):

            scanningID = hexlify(bytearray(entry[22:28]))
            scanningID = scanningID.decode()           

            scanningMacID =  ":".join(list(chunkify(advertisingID,2)))

            advertisingID = hexlify(bytearray(entry[28:34]))
            advertisingID = advertisingID.decode()           

            advertisingMacID = ":".join(list(chunkify(advertisingID,2))) #seperate string for readability

            bleType = 'SCAN_REQ'

            #print('SCAN_REQ')

        # if byte 21 ends with "0000", then is ADV_IND
        elif(result == 0):

            advertisingID = hexlify(bytearray(entry[22:28]))
            advertisingID = advertisingID.decode()           

            
            advertisingMacID = ":".join(list(chunkify(advertisingID,2))) #seperate string for readability
            bleType = 'ADV_IND'
            
            data = hexlify(bytearray(entry[28:-3])) # we ignore the CRC
            data = data.decode() # unnecessary to add colons to data, would be transmitted as a byte string

            #print(macID)
            #print(data)

        # if byte 21 wnds with "0010", then is ADV_NONCONN_IND
        elif(result == 2):
            advertisingID = hexlify(bytearray(entry[22:28]))
            advertisingID = advertisingID.decode()           


            advertisingMacID = ":".join(list(chunkify(advertisingID,2))) #seperate string for readability
            bleType = 'ADV_NONCONN_IND'

            data = hexlify(bytearray(entry[28:-3])) # we ignore the CRC
            data = data.decode() # unnecessary to add colons to data, would be transmitted as a byte string
            
            #print(data)

        elif(result == 4):
            advertisingID = hexlify(bytearray(entry[22:28]))
            advertisingID = advertisingID.decode()           


            advertisingMacID = ":".join(list(chunkify(advertisingID,2))) #seperate string for readability
            bleType = 'SCAN_RSP'

            data = hexlify(bytearray(entry[28:-3])) # we ignore the CRC
            data = data.decode() # unnecessary to add colons to data, would be transmitted as a byte string
            
            #print(data)

        else:
            print(result)
            print('NOT RECOGNIZED')


        allBlocks.append(blockEntry(rssi, advertisingMacID, scanningMacID, bleType, data))

    print(allBlocks[78].rssi)

    filteredBlocks = []

    #filter blocks based on rssi
    for block in allBlocks:
        if block.rssi >= -50:
            filteredBlocks.append(block)
    
    #test code
    for block in filteredBlocks:
        lineToPrint = str(block.rssi) + "\t" + block.aMacID + '\t' + block.sMacID + "\t" + block.bleType + '\t' + block.data
        print(lineToPrint)
    
    # Process raw byte strings from var -> log file

    print("Thank you! Please input name of export file.")
    export_file = input('>')

    with open('..//export_CSVs//' + export_file + '.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Advertising MAC ID', 'Scanning MAC ID', 'PDU Type', 'RSSI', 'PAYLOAD DATA'])
        for block in filteredBlocks:
            writer.writerow([block.aMacID, block.sMacID, block.bleType, block.rssi, block.data])






if __name__ == "__main__":
    main()
# TODO: Good code
