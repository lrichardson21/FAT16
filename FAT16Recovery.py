#FAT16Recovery.py
#Alex Richardson
#Last Edited: October 12th
#This python program extracts contiguous and non-contiguous files from a FAT16 file system missing BPB
#The program takes a path to a disk image, 'path', and yeilds recovered files.

import math
import struct
import os

#BIOS paramter block
BPB_BytsPerSec = 512
BPB_SecPerClus = 4
BPB_RsvdSecCnt = 1
BPB_NumFATs = 2
BPB_RootEntCnt = 512
BPB_TotSec16 = 0
BPB_FATSz16 = 115
BPB_SecPerTrk = 32
BPB_NumHeads = 16
BPB_HiddSec = 1
BPB_TotSec32 = 117250
RootDirSectors = 33
FirstDataSector = 64
FirstDataSectorOffset = 135168
DataSec = 116986
CountofClusters = 29246

#calculate bytes in FAT
bytesInFAT = BPB_FATSz16 * BPB_BytsPerSec

#Function to read FAT into program as an ARRAY
def readFAT(path):
    #initialize array to fold FAT
    FAT = []
    with open(path, 'rb') as file:
        #FAT is at begining of file
        fat_offset = 0
        #2 bytes per entry
        entrysize = 2
        file.seek(fat_offset)
        #Iterate over the bytes in the FAT, by 2, since each entry is 2 bytes
        for i in range (0, bytesInFAT, entrysize):
            entry = file.read(entrysize)
            if not entry:
                break
            #This gives entry in DECIMAL
            newentry = int.from_bytes(entry, byteorder='little')
            #add the new entry to the array
            FAT.append(newentry)
    return FAT

#PATH to exam.image on this mac
path = '/Users/laurenrichardson/Desktop/Digital Forensics/MIDTERM/exam.image'
#Call function to parse FAT into the array FATentries
FATentries = readFAT(path)

#TEST 
#print(FATentries)
#print(FATentries[15])
#Make sure print(len(FATentries)) == 29440
print(len(FATentries))

#Identify beginnig and ending entries of contigious chains
#Initialize arrays to hold values
chainBegining = []
chainEnd = []
chainMiddle = []
def chain(FAT):
    #iterate through each FAT entry
    for i in range (1,len(FAT)-1):
        if ((FAT[i] != i+1) and (FAT[i+1] != FAT[i]+1)): #END of Chain
            chainEnd.append(i)
        if ((FAT[i-1] != i) and (FAT[i] == i+1)): #BEGINING of Chain
            chainBegining.append(i)
        elif FAT[i] == i+1 and FAT[i-1]==i: #MIDDLE of Chain
            chainMiddle.append(FAT[i])
#Call the function to populate the arrays    
chain(FATentries)
#TEST
#print(chainBegining)
#print(chainEnd)

#Store file start locations in the FAT in an array
fileStartLocationsFAT = []
for begining in chainBegining:
    fileStart = True
    for ending in chainEnd:
        #if ending is BAD(0xFFF7), RESERVED()xFFF6)(0xFFF8-0xFFFE), or EOF(0xFFFF) just skip over it
        #if FATentries[ending] == 65527 or FATentries[ending] == 65526 or FATentries[ending] == 65535:
        if ending >= 65526:
            break    
        elif FATentries[ending] == begining:
            fileStart = False
            break
    if fileStart == True:
        fileStartLocationsFAT.append(begining)

#Store file start locations in the FILE in an array
fileStartLocations = [0] *21
i = 0
for entry in fileStartLocationsFAT: #iterate through start locations in the FAT
    if i == 21:
        break
    else:
        clusterNum = fileStartLocationsFAT[i] -2 #Cluster Number = Starting FAT Entry - 2
        fileStartLocations[i] = clusterNum * BPB_BytsPerSec * BPB_SecPerClus + FirstDataSectorOffset - 1024 #adjust offset for missing data
        i = i+1
#TEST
#print(fileStartLocationsFAT)
#print(fileStartLocations)

#Loop through FAT
# #while FAT[i] != FFFF
def extract_file(start_cluster, output_path):
    with open(output_path, 'wb') as filestream:
        current_cluster = start_cluster
        while current_cluster < 0xFFF8: #write cluster data to filestream
            with open(path, 'rb') as file:
                cluster_offset = (current_cluster - 2) * 2048 + FirstDataSectorOffset - 1024 #adjust offset for missing data
                file.seek(cluster_offset)
                cluster_data = file.read(2048)
                filestream.write(cluster_data)
            current_cluster = FATentries[current_cluster] #update FAT location

#Using the extract_file() function:
#I used the values in the array 'fileStartLocations' and a hex editor to manually determine the file extensions.
#For example, the file at the 2nd entry in fileStartLocationsFAT (location 23976960 in file)
#was MV4 -  so I called the function extract_file with these parameters:
#extract_file(fileStartLocationsFAT[2], 'recovered.mp4')
#The file at location 41882624 in the file was JFIF, thus:
#extract_file(fileStartLocationsFAT[4], 'recovered.jpg')
#I reapeated this process for each value in the 'fileStartLocations' array, and called the function with the corresponding index in fileStartLocationsFAT.

#End of program
