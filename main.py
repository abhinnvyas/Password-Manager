import sqlite3
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox as msg
from tkinter import font
import hashlib
import re
from tkinter import Image
from PIL import ImageTk, Image
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


class PasswordManager:
    def __init__(self):
        self.DATABASE = "backend/db.sqlite3"
        self.USERNAME = ""
        self.PASSWORD = ""
        self.QUERY = ""
        self.PUBLIC = None
        self.PRIVATE = None

        self.conn = sqlite3.connect(self.DATABASE)
        self.cursor = self.conn.cursor()

        self.root = tk.Tk()
        self.root.title("Password Manager")
        self.root.resizable(False, False)
        self.root.configure(bg="white")
        self.root.geometry("300x350+500+200")

    def hashGenerator(self, password):
        """Generated MD5 Hashes"""
        hashedPassword = hashlib.md5(password.encode()).hexdigest()

        return hashedPassword

    def validatePassword(self, passwd):
        reg = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{6,20}$"
        pat = re.compile(reg)
        mat = re.search(pat, passwd)

        return True if mat else False

    def encryptPassword(self, message):
        """Encrypt the Saved Passwords"""
        return self.PUBLIC.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def decryptPassword(self, message):
        """Encrypt the Saved Passwords"""
        return self.PRIVATE.decrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def loginFrame(self):

        def login():
            self.USERNAME = usrname.get()
            self.PASSWORD = self.hashGenerator(password.get())

            self.QUERY = f"SELECT * FROM Users WHERE username='{self.USERNAME.strip()}' and password='{self.PASSWORD}'"
            self.cursor.execute(self.QUERY)
            result = self.cursor.fetchall()

            if len(result) == 1:
                # self.root.geometry("500x350+500+200")
                self.PUBLIC = serialization.load_pem_public_key(
                    result[0][2].encode(),
                    backend=default_backend()
                )
                self.PRIVATE = serialization.load_pem_private_key(
                    result[0][3].encode(),
                    password=None,
                    backend=default_backend()
                )
                self.FunctionFrame()

            else:
                msg.showerror("Login Status",
                              "Login Failed!\nIncorrect Username or Password.")
                usrname.set("")
                password.set("")
                frame1.tkraise()

        self.root.geometry("300x350+500+200")

        # Creating a Base Frame
        emptyFrame = tk.Frame(self.root, bg="white")
        emptyFrame.place(x=0, y=0, width=300, height=350)
        emptyFrame.tkraise()

        # LOGIN FRAME
        frame1 = tk.Frame(emptyFrame, bg="white")
        frame1.place(x=45, y=95, width=200, height=100)
        frame1.tkraise()

        # Heading
        heading = tk.Label(emptyFrame, text="Login",
                           bg="white", font=("Times New Roman", 14))
        heading.pack(fill=tk.X, pady=60)
        f = font.Font(heading, heading.cget("font"))
        f.configure(underline=True)
        heading.configure(font=f)

        # username entry
        tk.Label(frame1, text="Username ", bg="white").grid(row=0, column=0)
        usrname = tk.StringVar()
        usrname.set("")
        usrnm_entry = tk.Entry(frame1, textvariable=usrname)
        usrnm_entry.grid(row=0, column=1)
        usrnm_entry.focus()

        # password entry
        tk.Label(frame1, text="Password ", bg="white").grid(row=1, column=0)
        password = tk.StringVar()
        password.set("")
        passw_entry = tk.Entry(frame1, textvariable=password, show="*")
        passw_entry.grid(row=1, column=1)

        login_button = tk.Button(
            frame1, text="Login", command=login, bg='blue', fg="white", relief=tk.FLAT)
        login_button.place(relx=0.5, rely=0.6, anchor=tk.CENTER, width=200)

        login_button.bind("<Return>", lambda event: login())

        signupSwitch = tk.Button(self.root, text="Create an Account",
                                 bg="white", fg="blue", relief=tk.FLAT, command=self.SignUpFrame)
        signupSwitch.place(relx=0.6, rely=0.51,
                           anchor=tk.CENTER, width=200, height=17)

        signupSwitch.bind("<Return>", lambda event: self.SignUpFrame())

    def SignUpFrame(self):

        def signup():
            user = usrname.get()
            passw1 = password.get()
            passw2 = rePassword.get()

            if user and passw1 and passw2:
                if passw1 == passw2:
                    if self.validatePassword(passw1):
                        self.USERNAME = user.strip()
                        self.PASSWORD = self.hashGenerator(passw1)
                        self.PRIVATE = rsa.generate_private_key(
                            public_exponent=65537,
                            key_size=2048,
                            backend=default_backend()
                        )
                        self.PUBLIC = self.PRIVATE.public_key()

                        private_key_pem = self.PRIVATE.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.NoEncryption()
                        )

                        public_key_pem = self.PUBLIC.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )

                        try:
                            self.cursor.execute('''
                                    INSERT INTO Users VALUES (?,?, ?, ?)
                            ''', (self.USERNAME, self.PASSWORD, public_key_pem.decode(), private_key_pem.decode()))
                            self.conn.commit()
                        except Exception as e:
                            msg.showerror(
                                "Error", f"{self.USERNAME} already Exists")
                            msg.showerror(
                                "Error", e)
                            usrname.set("")
                            password.set("")
                            rePassword.set("")
                            self.USERNAME = ""
                            self.PASSWORD = ""
                            self.PUBLIC = None
                            self.PRIVATE = None
                        else:
                            msg.showinfo(
                                "Success", "Account Created Successfully")
                            self.FunctionFrame()
                    else:
                        msg.showwarning("Invalid Password", "Password must Contain \n1. at least one number.\n\
2. at least one uppercase and one lowercase character.\n\
3. Should have at least one special symbol.\n\
4. Should be between 6 to 20 characters long.")
                        usrname.set("")
                        password.set("")
                        rePassword.set("")
                else:
                    msg.showwarning("Warning", "Passwords Doesnt Match")
                    usrname.set("")
                    password.set("")
                    rePassword.set("")
            else:
                msg.showwarning("Warning", "Fill all the Fields.")
                usrname.set("")
                password.set("")
                rePassword.set("")

        self.root.geometry("300x350+500+200")

        # Creating a Base Frame
        emptyFrame = tk.Frame(self.root, bg="white")
        emptyFrame.place(x=0, y=0, width=300, height=350)
        emptyFrame.tkraise()

        # Heading
        heading = tk.Label(emptyFrame, text="Register",
                           bg="white", font=("Times New Roman", 14))
        heading.pack(fill=tk.X, pady=60)
        f = font.Font(heading, heading.cget("font"))
        f.configure(underline=True)
        heading.configure(font=f)

        # Creating a SignUp Frame
        signupFrame = tk.Frame(self.root, bg="white")
        signupFrame.place(x=45, y=95, width=200, height=100)
        signupFrame.tkraise()

        # username entry
        tk.Label(signupFrame, text="Username ",
                 bg="white").grid(row=0, column=0)
        usrname = tk.StringVar()
        usrname.set("")
        usrnm_entry = tk.Entry(signupFrame, textvariable=usrname)
        usrnm_entry.grid(row=0, column=1)
        usrnm_entry.focus()

        # password entry
        tk.Label(signupFrame, text="Password ",
                 bg="white").grid(row=1, column=0)
        password = tk.StringVar()
        password.set("")
        passw_entry = tk.Entry(signupFrame, textvariable=password, show="*")
        passw_entry.grid(row=1, column=1)

        # repassword entry
        tk.Label(signupFrame, text="Confirm Password ",
                 bg="white").grid(row=2, column=0)
        rePassword = tk.StringVar()
        password.set("")
        re_passw_entry = tk.Entry(
            signupFrame, textvariable=rePassword, show="*")
        re_passw_entry.grid(row=2, column=1)

        signup_button = tk.Button(signupFrame, text="Create Account",
                                  command=signup, bg='blue', fg="white", relief=tk.FLAT)
        signup_button.place(relx=0.5, rely=0.8, anchor=tk.CENTER, width=200)

        signup_button.bind("<Return>", lambda event: signup())

        signupSwitch = tk.Button(self.root, text="Login", bg="white",
                                 fg="blue", relief=tk.FLAT, command=self.loginFrame)
        signupSwitch.place(relx=0.7, rely=0.56, anchor=tk.CENTER, height=15)

        signupSwitch.bind("<Return>", lambda event: self.loginFrame())

    def FunctionFrame(self):

        def functions():

            def addElement():
                if platform.get() != "" and usr.get() != "" and passw.get() != "":

                    try:
                        self.cursor.execute('''
                                    INSERT INTO ProfilesManaged VALUES (?,?, ?, ?)
                            ''', (str(usr.get()).strip(), self.encryptPassword(str(passw.get()).strip()).hex(), str(str(platform.get()).lower()).strip(), self.USERNAME))

                        self.cursor.execute(self.QUERY)
                        self.conn.commit()
                    except Exception as e:
                        msg.showerror("Error in addelement: ", e)
                        usr.set("")
                        passw.set("")
                        platform.set("")
                    else:
                        msg.showinfo("Success", "Item added successfullly!")
                        listbox.delete(0, tk.END)
                        updateListBox()

                        usr.set("")
                        passw.set("")
                        platform.set("")
                        platform_entry.focus()
                else:
                    msg.showwarning("ERROR", "Fill all the fields")
                    platform_entry.focus()

            def deleteSelected():
                try:
                    selection = listbox.curselection()[0]
                except IndexError:
                    msg.showerror("Error", "Select a Item First.")
                else:
                    if selection != 0:
                        value = listbox.get(selection).split("|")

                        user = str(value[0][1:]).strip()
                        passw = str(value[1]).strip()
                        platfrm = str(value[2]).strip()

                        try:
                            self.QUERY = f"DELETE FROM ProfilesManaged WHERE usernm='{user}' and passw='{self.encryptPassword(passw).hex()}' and platform='{platfrm}' and username='{self.USERNAME}'"
                            self.cursor.execute(self.QUERY)
                            self.conn.commit()
                        except Exception as e:
                            msg.showerror("Error", e)
                        else:
                            msg.showinfo(
                                "Info", "Element Deleted Successfully.")
                            listbox.delete(selection)
                    else:
                        msg.showwarning(
                            "Warning", "Can't Delete this Element.")

            def logout():

                ask = msg.askyesnocancel("Logout", "Do you want to Logout?")
                if ask:
                    self.root.geometry("300x350+500+200")
                    self.USERNAME = ""
                    self.PASSWORD = ""
                    self.PRIVATE = None
                    self.PUBLIC = None

                    self.loginFrame()
                else:
                    self.FunctionFrame()

            def Exit():
                ask = msg.askyesnocancel("Exit", "Do you want to Exit?")
                if ask:
                    self.USERNAME = ""
                    self.PASSWORD = ""
                    self.PRIVATE = None
                    self.PUBLIC = None
                    self.root.destroy()
                    self.cursor.close()
                    self.conn.close()
                else:
                    self.FunctionFrame()

            def deleteAccount():
                ask = msg.askyesnocancel(
                    "Delete", "Do you want to Delete this Account?")
                if ask:
                    try:
                        self.QUERY = f"DELETE FROM Users WHERE username='{self.USERNAME}'"
                        self.cursor.execute(self.QUERY)
                        self.conn.commit()
                    except Exception as e:
                        msg.showerror("Error", e)
                        self.conn.rollback()
                    else:
                        msg.showinfo(
                            "Success", "Account Deleted SuccessFully.")
                        self.SignUpFrame()
                else:
                    self.FunctionFrame()

            def updateListBox():
                self.QUERY = f"select usernm, passw, platform from ProfilesManaged where username='{self.USERNAME}' ORDER BY platform"
                self.cursor.execute(self.QUERY)
                result = [
                    u"⚫"+f"{i[0]} | {self.decryptPassword(bytes.fromhex(i[1])).decode()} | {i[2]}" for i in self.cursor.fetchall()]
                listbox.insert(tk.END, "USERNAME | PASSWORD | PLATFORM")
                for element in result:
                    listbox.insert(tk.END, element)

            # Creating a new Frame
            functions_frame = tk.Frame(frame2, bg="white")
            functions_frame.pack(fill=tk.BOTH, ipady=3)

            tk.Label(functions_frame, text="Add New", font=("times new roman", 12),
                     bg="black", fg="white", width=24).grid(padx=2, pady=7, row=0, columnspan=2)

            # Code for the "Add an Entry" Section
            platform = tk.StringVar()
            usr = tk.StringVar()
            passw = tk.StringVar()

            tk.Label(functions_frame, text="Platform",
                     bg="white").grid(row=1, column=0)
            platform_entry = tk.Entry(
                functions_frame, textvariable=platform, relief=tk.SUNKEN)
            platform_entry.grid(row=1, column=1)
            platform_entry.focus()

            tk.Label(functions_frame, text="Username",
                     bg="white").grid(row=2, column=0)
            tk.Entry(functions_frame, textvariable=usr,
                     relief=tk.SUNKEN).grid(row=2, column=1)

            tk.Label(functions_frame, text="Password",
                     bg="white").grid(row=3, column=0)
            tk.Entry(functions_frame, textvariable=passw,
                     relief=tk.SUNKEN).grid(row=3, column=1)

            add = tk.Button(functions_frame, text="Add", bg="Black",
                            fg="white", command=addElement, width=30)
            add.grid(pady=1, row=4, columnspan=2)

            add.bind("<Return>", lambda event: addElement())

            # Code for Deleting the Current Entry
            del_selected = tk.Button(functions_frame, bg="white", fg="red",
                                     text="Delete Selected", width=30, command=deleteSelected, relief=tk.RIDGE)
            del_selected.grid(padx=15, row=0, column=2, columnspan=2)

            del_selected.bind("<Return>", lambda event: deleteSelected())

            # Code for Log Out
            logout = tk.Button(functions_frame, text="Logout", bg="white",
                               fg="red", width=30, bd=2, relief=tk.RIDGE, command=logout)
            logout.grid(row=1, column=2, columnspan=2)

            logout.bind("<Return>", lambda event: logout())

            # Code for the Exit
            exitButton = tk.Button(functions_frame, text="Quit", bg="white",
                                   fg="red", width=30, bd=2, relief=tk.RIDGE, command=Exit)
            exitButton.grid(row=2, column=2, columnspan=2, pady=3)

            exitButton.bind("<Return>", lambda event: Exit())

            deleteAccButton = tk.Button(functions_frame, text="Delete Account", bg="white",
                                        fg="red", width=30, bd=2, relief=tk.RIDGE, command=deleteAccount)
            deleteAccButton.grid(row=3, column=2, columnspan=2, pady=3)

            deleteAccButton.bind("<Return>", lambda event: deleteAccount())

        # Resizing the Frame
        self.root.geometry("500x362+500+200")

        # Creating the Frame
        frame2 = tk.Frame(self.root, bg="white")
        frame2.place(x=0, y=0, width=500, height=362)
        frame2.tkraise()

        # Creating the Listbox and Scrollbar
        lis_box_frame = tk.Frame(frame2, bg="white")
        lis_box_frame.pack()

        scrollBar = tk.Scrollbar(lis_box_frame, orient=tk.VERTICAL)
        listbox = tk.Listbox(lis_box_frame, selectmode=tk.BROWSE, width=300, relief=tk.RIDGE, font=(
            "times new roman", 12), bg="white", yscrollcommand=scrollBar.set)
        scrollBar.config(command=listbox.yview)
        scrollBar.pack(side=tk.RIGHT, fill=tk.Y)
        listbox.pack(fill=tk.BOTH, expand=1)

        # Adding Entries from the Database
        self.QUERY = f"select usernm, passw, platform from ProfilesManaged where username='{self.USERNAME}' ORDER BY platform"
        self.cursor.execute(self.QUERY)
        result = [
            u"⚫"+f"{i[0]} | {i[1]} | {i[2]}" for i in self.cursor.fetchall()]
        listbox.insert(tk.END, "USERNAME | PASSWORD | PLATFORM")
        for element in result:
            listbox.insert(tk.END, element)

        functions()

    def main(self):
        # Enabling the foreign key support
        self.QUERY = "PRAGMA foreign_keys = ON"
        self.cursor.execute(self.QUERY)
        self.conn.commit()

        # Setting the icon of the file
        image = ImageTk.PhotoImage(Image.open('./logo.ico'))
        self.root.iconphoto(False, image)

        self.loginFrame()

        self.root.mainloop()


if __name__ == "__main__":
    PasswordManager().main()
