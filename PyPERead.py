import sys

import getopt
import pefile
import pydasm

print  sys.argv
filename = sys.argv[1]
#pe = pefile.PE("E:\\4.DevelopmentAndTesting\\Resources\\VirusSample\\EXE\\VirusSignList_Free_0129885bfd264dfb103eb75584405541.exe")
#pe = pefile.PE("E:\\4.DevelopmentAndTesting\\Resources\\Quarantine Malwares\\New.exe")
#pe = pefile.PE("E:\\4.DevelopmentAndTesting\\Resources\\Quarantine Malwares\\1. RMI Calculator .exe")
pe = pefile.PE(filename)
print "Section Alignment:",hex(pe.OPTIONAL_HEADER.SectionAlignment)
print "Imagebase:",hex( pe.OPTIONAL_HEADER.ImageBase)

def ShowImportedFunction(pe):
  print "************************************************"
  print "Imported Functions"
  for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print entry.dll
    for imp in entry.imports:
      print '\t', hex(imp.address),imp.name#hex(imp.address), imp.name

def ScanFunc(IntAddress):
  print "************************************************"
  print "Trying To scan "+str(hex(IntAddress))
  ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
  ep_ava = ep+pe.OPTIONAL_HEADER.ImageBase
  offset = IntAddress-pe.OPTIONAL_HEADER.ImageBase
  #print hex(IntAddress)+">"+hex(ep+pe.OPTIONAL_HEADER.ImageBase)
  data = pe.get_memory_mapped_image()[ep:ep+pe.OPTIONAL_HEADER.SizeOfCode]
  while offset < len(data):
    i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
    
    if i!= None:
      #print hex(pe.OPTIONAL_HEADER.ImageBase+offset)," ", i.ptr.mnemonic
      if i.ptr.mnemonic=="ret": 
        #print str(hex(ep_ava+offset))+ " I am Return Statement from"+str(hex(IntAddress))
        break
      elif i.ptr.mnemonic=="retn":
         #print str(hex(ep_ava+offset))+ " I am Return Statement from"+str(hex(IntAddress))
         break
      elif i.ptr.mnemonic=="call":
         HexString = pydasm.get_operand_string(i,0,pydasm.FORMAT_INTEL, ep_ava+offset)
         if len(HexString)==10 and HexString[1]!="e" :
           HexStr = HexString.lstrip("[")
           HexStrAdd = HexStr.rstrip("]")
           intAdd=int(HexStrAdd,16)
           for entry in pe.DIRECTORY_ENTRY_IMPORT:
              for imp in entry.imports:
                 if imp.address==intAdd:
                   print "From Function:",str(hex(IntAddress)),"at",hex(intAdd), i.ptr.mnemonic +" "+ entry.dll+"."+imp.name+","+str(imp.hint)
         else:
                   #print str(hex(ep_ava+offset))+" "+i.ptr.mnemonic+" "+ HexString
                    if(HexString[0]!="e" and HexString[1]!="e"):
                     # print str(hex(ep_ava+offset))
                      ScanFunc(int(HexString,16))
      offset += i.length
                    #print str(hex(ep_ava+offset))+" "+ i.ptr.mnemonic 
    offset+=1


def ScanMainTillRet():
  #Entry point for Optional Header
  ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint

  #Viratual Address of Imagebase
  ep_ava = ep+pe.OPTIONAL_HEADER.ImageBase
  data = pe.get_memory_mapped_image()[ep:ep+ pe.OPTIONAL_HEADER.SizeOfCode]
  offset = 0

  #Scan the code of main function till length of Code section 
  while offset < len(data):
    i = pydasm.get_instruction(data[offset:], pydasm.MODE_32)
    if i!= None:
      #print str(hex(ep_ava+offset)),i.ptr.mnemonic
      if i.ptr.mnemonic =="ret":
         #print "I am Returning From Main :)"
         return
      if i.ptr.mnemonic=="call": 
         HexString = pydasm.get_operand_string(i,0,pydasm.FORMAT_INTEL, ep_ava+offset)
         #print HexString
         if len(HexString)==10 and HexString[1]!="e":
           HexStr = HexString.lstrip("[")
           HexStrAdd = HexStr.rstrip("]")
           intAdd=int(HexStrAdd,16)
           for entry in pe.DIRECTORY_ENTRY_IMPORT:
              for imp in entry.imports:
                 if imp.address==intAdd:
                    #Print the detailed information for the API function found   
                    print str(hex(ep_ava+offset))+" "+i.ptr.mnemonic +" "+ entry.dll+"."+imp.name+","+str(imp.hint)
         else:
           if(HexString[0]!="e" and HexString[1]!="e"):
            #print str(hex(ep_ava+offset))
            #print i.ptr.mnemonic+" "+ HexString
            ScanFunc(int(HexString,16))
      offset += i.length

ShowImportedFunction(pe)
ScanMainTillRet()
#ScanFunc(4201776)
#ScanFunc(4198400)
#ScanFunc(4205604)
