# A simple script to help visually navigate installed 
# nmap NSE scripts to determine their usage in a GUI.
# Fixed for Kali Linux 2.0 - grid / pack issues 
# - Hacker Fantastic
from Tkinter import *
import tkMessageBox
import os

root = Tk()
text = Text(root)

def onselect(event):
        w = event.widget
        index = int(w.curselection()[0])
        value = w.get(index)
        nsescript = open("/usr/share/nmap/scripts/"+value)
	parseme = False
	description = ""
	for line in nsescript.readlines():
		if parseme == True:
			if "]]" in line:
				parseme = False
			description = description + line.replace("]]","")
		if "description = [[" in line:
			string = line.rsplit("description = [[")
			clean = "%s" % str(string[-1:])
			description = "" + clean.replace("['\\n']","");
			parseme = True
	text.delete('0.0',END)
	text.insert(END,description)
	nsescript.close()

if __name__ == "__main__":
	root.title("NSE script discoverer!")
	w = 800
	h = 360 
	ws = root.winfo_screenwidth() 
	hs = root.winfo_screenheight() 
	x = (ws/2) - (w/2)
	y = (hs/2) - (h/2)
	root.geometry('%dx%d+%d+%d' % (w, h, x, y))
	scrollbar = Scrollbar(root)
	scrollbar.pack(side=LEFT, fill=Y)
	files = os.listdir("/usr/share/nmap/scripts")
	files.sort() 
	listbox = Listbox(root, yscrollcommand=scrollbar.set)
	for row in xrange(0,len(files)):
		if ".nse" in files[row]:
			listbox.insert(END, files[row])
	listbox.pack(side=LEFT,fill=BOTH,expand=1)
	listbox.bind('<<ListboxSelect>>', onselect)
	text.pack()
	root.mainloop()

