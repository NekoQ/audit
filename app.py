import glob
import json
import subprocess
import tarfile
from tkinter import *
from tkinter import filedialog as fd
from tkinter import ttk
from tkinter.font import Font
import requests
import audit
import re
global previous

main = Tk()
myFont = Font(family="Consolas", size=10)
s = ttk.Style()
s.configure('TFrame', background='#000000')
main.title("Security Benchmarking Tool")
main.geometry("1550x700")
frame = ttk.Frame(main, width=1550, height=700,
                  style='TFrame', padding=(4, 4, 450, 450))
frame.grid(column=0, row=0)
previous = []
index = 0
arr = []
matching = []

SystemDict = {}
querry = StringVar()
vars = StringVar()
tofile = []
structure = []

success = []
success1 = []
fail = []
unknown = []

toChange = []
vars1 = StringVar()
vars2 = StringVar()
arr1 = []
arr2 = []
arr2copy = []

failedselected = []


def check():
    global success1
    global success
    global fail
    success.clear()
    success1.clear()
    fail.clear()
    arr1.clear()
    arr2.clear()
    for struct in structure:
        if 'reg_key' in struct and 'reg_item' in struct and 'value_data' in struct:
            make_query(struct)

    for i in range(len(success1)):
        item1 = success1[i]
        arr1.append(' PASSED POLICY Description' + item1[0]['description'])

    for i in range(len(fail)):
        item2 = fail[i]
        arr2.append(' FAILED POLICY Description' + item2[0]['description'])
        global arr2copy
        arr2copy = arr2

    procent = int((len(success1)/(len(success1)+len(fail)))*100)
    print(procent)
    arr1.append('The system is securised :' + str(procent) + ' % ')
    arr2.append('The system is securised :' + str(procent) + ' % ')
    vars1.set(arr1)
    vars2.set(arr2)

    frame2 = Frame(main, bd=10, bg='#140000', highlightthickness=10)
    frame2.config(highlightbackground="Red")
    frame2.place(relx=0.5, rely=0.1, width=800,
                 relwidth=0.4, relheight=0.8, anchor='n')
    listbox_succes = Listbox(frame2, bg="#6aa84f", font=myFont, fg="black", listvariable=vars1,
                             selectmode=MULTIPLE, width=50, height=27, highlightthickness=3)
    listbox_succes.place(relx=0.07, rely=0.03, relwidth=0.4, relheight=0.9)
    listbox_succes.config(highlightbackground="green")
    listbox_fail = Listbox(frame2, bg="#e06666", font=myFont, fg="black", listvariable=vars2,
                           selectmode=MULTIPLE, width=50, height=27, highlightthickness=3)
    listbox_fail.bind("<<ListboxSelect>>", on_select_failed)
    listbox_fail.place(relx=0.5, rely=0.03, relwidth=0.4, relheight=0.9)
    listbox_fail.config(highlightbackground="red")

    def exit():

        frame2.destroy()

    exit_btn = Button(frame2, text='Back', command=exit, bg="#D60020", fg="white", font=myFont, padx='10px',
                      pady='3px')
    exit_btn.place(relx=0.93, rely=0.92)

    def changeFailures():
        global arr2copy
        global arr2
        backup()
        for i in range(len(failedselected)):
            print(i)
            struct = failedselected[i][0]
            query = 'reg add "' + struct['reg_key'] + '" /v ' + struct['reg_item'] + ' /d "' + struct[
                'value_data'] + '" /f'
            print(query)
            out = subprocess.Popen(query,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT)
            output = out.communicate()[0].decode('ascii', 'ignore')
            str = ''
            for char in output:
                if char.isprintable() and char != '\n' and char != '\r':
                    str += char
            output = str
            print(output)
            vars2.set(arr2)
            arr2copy = arr2

    def restore():
        f = open('backup.txt')
        fail = json.loads(f.read())
        print(fail)
        f.close()

        for i in range(len(fail)):
            struct = fail[i][0]
            query = 'reg add ' + struct['reg_key'] + ' /v ' + \
                struct['reg_item'] + ' /d ' + fail[i][1] + ' /f'
            print('Query:', query)
            out = subprocess.Popen(query,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT)
            output = out.communicate()[0].decode('ascii', 'ignore')
            str = ''
            for char in output:
                if char.isprintable() and char != '\n' and char != '\r':
                    str += char
            output = str
            print(output)

    def backup():
        f = open('backup.txt', 'w')
        backupString = json.dumps(fail)
        f.write(backupString)
        f.close()
    changeBtn = Button(frame2, text='Change', command=changeFailures, bg="#300000", fg="white", font=myFont, padx='10px',
                       pady='3px')
    changeBtn.place(relx=0.30, rely=0.95)

    backupBtn = Button(frame2, text='Restore', command=restore, bg="#300000", fg="white", font=myFont,
                       padx='10px',
                       pady='3px')
    backupBtn.place(relx=0.70, rely=0.95)


def on_select_failed(evt):
    w = evt.widget
    actual = w.curselection()

    global failedselected
    global arr2
    failedselected = []
    for i in actual:
        failedselected.append(fail[i])
    localarr2 = []
    for i in actual:
        localarr2.append(arr2copy[i])
    arr2 = localarr2
    arr2 = [x for x in arr2copy if x not in arr2]
    print(failedselected)


###

def entersearch(evt):
    search()


def search():
    global structure
    q = querry.get()
    arr = [struct['description']
           for struct in structure if q.lower() in struct['description'].lower()]
    global matching
    matching = [struct for struct in structure if q in struct['description']]
    vars.set(arr)


def on_select_configuration(evt):
    global previous
    global index
    w = evt.widget
    actual = w.curselection()

    difference = [item for item in actual if item not in previous]
    if len(difference) > 0:
        index = [item for item in actual if item not in previous][0]
    previous = w.curselection()

    text.delete(1.0, END)
    str = '\n'
    for key in matching[index]:
        str += key + ':' + matching[index][key] + '\n'
    text.insert(END, str)


def download_url(url, save_path, chunk_size=1024):
    r = requests.get(url, stream=True)
    with open(save_path, 'wb') as fd:
        for chunk in r.iter_content(chunk_size=chunk_size):
            fd.write(chunk)


def extract_download():
    url = "https://www.tenable.com/downloads/api/v1/public/pages/download-all-compliance-audit-files/downloads/7472/download?i_agree_to_tenable_license_agreement=true"
    path = "audits.tar.gz"
    download_url(url, path)
    tf = tarfile.open("audits.tar.gz")
    tf.extractall()
    print(glob.glob("portal_audits/*"))


def import_audit():
    global arr
    file_name = fd.askopenfilename(initialdir="../portal_audits")
    if file_name:
        arr = []
    global structure
    structure = audit.main(file_name)
    for element in structure:
        for key in element:
            str = ''
            for char in element[key]:
                if char != '"' and char != "'":
                    str += char
            isspacefirst = True
            str2 = ''
            for char in str:
                if char == ' ' and isspacefirst:
                    continue
                else:
                    str2 += char
                    isspacefirst = False
            element[key] = str2

    global matching
    matching = structure
    if len(structure) == 0:
        f = open(file_name, 'r')
        structure = json.loads(f.read())
        f.close()
    for struct in structure:
        if 'description' in struct:
            arr.append(struct['description'])
        else:
            arr.append('Error in selecting')
    vars.set(arr)

# highlighting the specifications of each audit file


lstbox = Listbox(frame, bg="#000000", font=myFont, fg="white", listvariable=vars, selectmode=MULTIPLE, width=85,
                 height=25, highlightthickness=3)
lstbox.config(highlightbackground="white")
lstbox.grid(row=0, column=0, columnspan=3, padx=130, pady=70)
lstbox.bind('<<ListboxSelect>>', on_select_configuration)


def save_config():
    file_name = fd.asksaveasfilename(filetypes=(("Audit FILES", ".audit"),
                                                ("All files", ".")))
    file_name += '.audit'
    file = open(file_name, 'w')
    selection = lstbox.curselection()
    for i in selection:
        tofile.append(matching[i])
    json.dump(tofile, file)
    file.close()


def select_all():
    lstbox.select_set(0, END)
    for struct in structure:
        lstbox.insert(END, struct)


def deselect_all():
    for struct in structure:
        lstbox.selection_clear(0, END)


##

text = Text(frame, bg="#000000", fg="white", font=myFont,
            width=55, height=27, highlightthickness=3)
text.config(highlightbackground="white")
text.grid(row=0, column=3, columnspan=3, padx=40)
saveButton = Button(frame, bg="#D60020", fg="white", font=myFont, text="Save", width=15, height=1,
                    command=save_config).place(relx=0.01, rely=0.45)
import_button = Button(frame, bg="#D60020", fg="white", font=myFont, text="Import", width=15, height=1,
                       command=import_audit).place(relx=0.01, rely=0.40)
downloadButton = Button(frame, bg="#D60020", fg="white", font=myFont, text="Download audits", width=15, height=1,
                        command=extract_download).place(relx=0.01, rely=0.35)
selectAllButton = Button(frame, bg="#D60020", fg="white", font=myFont, text="Select All", width=15, height=1,
                         command=select_all).place(relx=0.01, rely=0.55)
deselectAllButton = Button(frame, bg="#D60020", fg="white", font=myFont, text="Deselect All", width=15, height=1,
                           command=deselect_all).place(relx=0.01, rely=0.60)
global e
e = Entry(frame, bg="#f5f5f5", font=myFont, width=30,
          textvariable=querry).place(relx=0.29, rely=0.05)
search_button = Button(frame, bg="#D60020", fg="white", font=myFont, text="Search", width=7, height=1,
                       command=search).place(relx=0.48, rely=0.05)
check_button = Button(frame, bg="#D60020", fg="white", font=myFont, text="Check", width=7, height=1,
                      command=check).place(relx=0.54, rely=0.05)

main.bind('<Return>', entersearch)
main.mainloop()
