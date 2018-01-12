# Written by Scott Moore (NetWitness/RSA) in Aug 2012 against NextGen v10.6
# using Python 3.5
#
# The purpose of this program is to demonstrate how to interact with NextGen
# using the RESTful API.  I hereby release this code into the public domain so
# you may do whatever you want with it.  However, if you make useful changes
# to it, you would generate good karma by posting it back to the NetWitness
# community.  :)
#
# BTW, this is my first python program and I taught myself as I went along,
# so apologies in advance for what is probably poor python style.
# One thing I could never figure out is how to get the error text returned
# by NextGen when a 4xx HTTP error code is received.  The URLError exception
# doesn't seem to contain the actual payload response (see the submit func).
# If anyone solves that, please post the solution on the NetWitness community
# site.  https://community.emc.com/go/netwitness
#
# Thanks and I hope you find this useful.

from tkinter import *
from tkinter import ttk
from tkinter import filedialog
import urllib, urllib.request, urllib.parse, sys
import json
import re
import ssl

response_data = bytearray()

class StringParams:
    """A class that parses a string into NextGen parameters.
    Example:
    id1=1 id2=10000 query="select * where service=80"
    
    This class will generate a dict with 3 keys from the string above:
    {'query': 'select * where service=80', 'id2': '10000', 'id1': '1'}
    """
    params = {}  # dictionary from the result of calling parse

    def parse(self, str):
        self.params    = {}
        backslash      = False
        quotes         = False
        checkQuote     = True
        skipWhitespace = True
        hexChar        = False
        p              = 0
        hexValue       = ""
        param          = ["", ""]
        
        for c in range(len(str)):
            ch = str[c]
            
            if checkQuote:
                if ch == '"' and not backslash:
                    quotes         = True
                    checkQuote     = False
                    skipWhitespace = False
                    continue
            
            if skipWhitespace:
                if ch == ' ' or ch == '\t' or ch == '\n' or ch == '\r':
                    continue
                skipWhitespace = False
                checkQuote     = False
            
            if ch == '"' and quotes and not backslash:
                quotes     = False
                checkQuote = True
            elif (ch == ' ' or ch == '\t' or ch == '\n' or ch == '\r') and not backslash and not quotes:
                # store active parameters
                if len(param[0]) > 0:
                    self.params[param[0]] = param[1]
                
                # reset state
                p = 0
                param = ["", ""]
                checkQuote     = True
                skipWhitespace = True
            elif ch == "=" and backslash == False and quotes == False and p == 0:
                p = 1  # go to value parameter
                checkQuote = True
                skipWhitespace = False
            elif ch == '\\' and backslash == False:
                backslash = True
            elif backslash:
                if hexChar:
                    hexValue = hexValue + ch
                    if len(hexValue) > 1:
                        # time to decoder
                        hexChar = False
                        backslash = False
                        value = int(hexValue, 16)
                        param[p] = param[p] + chr(value)
                        hexValue = ""
                elif ch == 'n':
                    param[p] = param[p] + '\n'
                    backslash = False
                elif ch == 't':
                    param[p] = param[p] + '\t'
                    backslash = False
                elif ch == 'r':
                    param[p] = param[p] + '\r'
                    backslash = False
                elif ch == '0':
                    param[p] = param[p] + '\0'
                    backslash = False
                elif ch == 'x':
                    hexChar = True
                    hexValue = ""
                else:
                    param[p] = param[p] + ch
                    backslash = False
            else:
                param[p] = param[p] + ch
                backslash = False
        
        # store active parameters
        if len(param[0]) > 0:
            self.params[param[0]] = param[1]

        
class BusyManager:
    """This class provides a way to display a busy cursor on all widgets below a Tk root window"""

    def __init__(self, widget):
        self.toplevel = widget.winfo_toplevel()
        self.widgets = {}

    def busy(self, widget=None):
        # attach busy cursor to toplevel, plus all windows
        # that define their own cursor.
        if widget is None:
            w = self.toplevel # myself
        else:
            w = widget

        if str(w) not in self.widgets:
            try:
                # attach cursor to this widget
                cursor = w.cget("cursor")
                if cursor != "watch":
                    self.widgets[str(w)] = (w, cursor)
                    w['cursor'] = "watch"
            except TclError:
                pass

        for w in w.children.values():
            self.busy(w)

    def notbusy(self):
        # restore cursors
        for w, cursor in self.widgets.values():
            try:
                w['cursor'] = cursor
            except TclError:
                pass
        self.widgets = {}


def getSupportedMessages(*args):
    """This function takes the current value of pathname and asks the service for all messages on that node.
    It then parses the json response to get the list of those messages and fill the message combobox"""
    try:
        global message_combo
        # request help on the current node (in the pathname text entry)
        res = submit(url.get(), pathname.get(), "help", "op=messages force-content-type=application/json", username.get(), password.get())
        # convert json response to a string
        s = res.decode("utf-8")
        # load json string into json decoder for later parsing, d is a dict of the json
        d = json.loads(s)

        # make sure our dict has a params parameter
        if 'params' in d:
            l = []
            # create a list of supported messages
            for msg in d['params']:
                l.append(msg)
            # take the list and set the combobox dropdown with all the supported messages
            message_combo['values'] = l
            message_combo.set(l[0])
    except:
        print("getSupportedMessages error: ", sys.exc_info()[0])


def getMessageHelp(*args):
    """This function takes the current value of pathname and message and displays help for it on the screen."""
    try:
        # request help on the current node (in the pathname text entry)
        s = "m=" + message.get() + " force-content-type=text/plain"
        res = submit(url.get(), pathname.get(), "help", s, username.get(), password.get())
    except:
        print("Unexpected error: ", sys.exc_info()[0])
    

def getMessageManPage(*args):
    """This function takes the current value of pathname and message and displays help for it on the screen."""
    try:
        # request help on the current node (in the pathname text entry)
        s = "m=" + message.get() + " force-content-type=text/plain op=manual"
        res = submit(url.get(), pathname.get(), "help", s, username.get(), password.get())
    except:
        print("Unexpected error: ", sys.exc_info()[0])
    

def submit(url, pathname, message, parameters, username, password, headers=None, bin_data=None):
    """Submits a RESTful request to a NextGen service and returns the response"""
    try:
        global request_text
        global response_text
        global root
        global busy
		
        # maximum amount of text that will be displayed in the request/response text boxes
        max_length = 64 * 1024 * 1024
        
        # don't verify any SSL certificates, not really a good idea, but this is just for testing purposes
        ssl._create_default_https_context = ssl._create_unverified_context
        
        busy.busy()

        sp = StringParams()
        sp.parse(parameters)

        urlParamChar = "?"

        urlPath = url
        urlPath = urlPath + pathname
        if len(message) > 0:
            urlPath = urlPath + urlParamChar + "msg="
            urlPath = urlPath + message
            urlParamChar = "&"

        request_text.delete("1.0", "end")
        response_text.delete("1.0", "end")
        
        auth_handler = urllib.request.HTTPBasicAuthHandler()
        auth_handler.add_password(realm="NetWitness", uri=urlPath, user=username, passwd=password)
        opener = urllib.request.build_opener(auth_handler)
        urllib.request.install_opener(opener)
        
        data = urllib.parse.urlencode(sp.params)
        
        if bin_data != None:
            req = urllib.request.Request(urlPath + urlParamChar + data, bin_data)
        elif post.get() == "POST":
            data = data.encode("utf-8")
            req = urllib.request.Request(urlPath, data)
        else:
            req = urllib.request.Request(urlPath + urlParamChar + data)
        
        request_text.insert("end", req.full_url)
        request_text.insert("end", "\n")
		
        if headers != None:
            for name, value in headers.items():
                req.add_header(name, value)
        
        for name, value in req.header_items():
            request_text.insert("end", name + ": " + value)
            request_text.insert("end", "\n")
        
        if req.data != None:
            request_text.insert("end", "\n")
            request_text.insert("end", req.data[0:max_length])

        response = urllib.request.urlopen(req)
        res_data = response.read()
        
        # Uncomment the lines below if you want to see the HTTP headers returned
        #for i in response.info():
        #    response_text.insert("end", i + ": " + response.info()[i])
        #    response_text.insert("end", "\n")
        #response_text.insert("end", "\n")
        
        res_string = str()
        try:
            # try to convert to utf-8, if it fails, then assume it's binary
            # and strip out non-ascii characters
            res_string = res_data[0:max_length].decode("utf-8")
        except:
            # strip out all non-ascii control chars, use a mutable bytearray
            # first, then convert to string at end.
            ascii_ba = bytearray()
            for c in res_data:
                if (c > 31 and c < 127) or c == 13 or c == 10 or c == 9:
                    ascii_ba.append(c)
                # prevent excessively large responses in our text widget
                if len(ascii_ba) > max_length:
                    break
            res_string = ascii_ba.decode("ascii")
        
        response_text.insert("end", res_string)

        busy.notbusy()

        global response_data
        response_data = res_data

        # return original bytearray response
        return res_data
    except urllib.request.URLError as e:
        #global response_text
        if hasattr(e, 'reason'):
            response_text.insert("end", e.reason)
            print(e.reason)
        elif hasattr(e, 'code'):
            response_text.insert("end", "HTTP Error " + e.code)
            print(e.code)
    finally:
        busy.notbusy()


def submitForm(*args):
    headers = {}
    headers['Accept'] = accept.get()
    return submit(url.get(), pathname.get(), message.get(), parameters.get(),\
    username.get(), password.get(), headers)

def submitFile(*args):
    """This method shows a file dialog and submits the chosen file to NextGen.
    This is primarily used to import a pcap to decoder (/decoder/import) or upload
    parsers or feeds (/decoder/parsers/upload")."""
    
    filepath = filedialog.askopenfilename()

    if len(filepath) == 0:
        return

    # open and read contents of file - no checking is performed for large files
    # beware - could get out of memory errors!
    with open(filepath, 'rb') as f:
        bin_data = f.read()
    
    headers = {}
    headers['Accept'] = accept.get()
    headers['Content-Type'] = 'application/octet-stream'
    headers['X-pcap'] = filepath  # used to identify the filename for /decoder/import
    return submit(url.get(), pathname.get(), message.get(), parameters.get(),\
    username.get(), password.get(), headers, bin_data)

def savePayload(*args):
    """Saves the returned REST response to a file."""
    filepath = filedialog.asksaveasfilename()
    if len(filepath) == 0:
        return
    
    with open(filepath, 'wb') as f:
        f.write(response_data)


root = Tk()
root.title("NextGen REST Client Test App v1.1")

# BusyManager is purely for displaying a watch cursor when the python script is busy
# waiting for a response from NextGen
busy = BusyManager(root)

mainframe = ttk.Frame(root, padding="3 3 12 12", width="1000", height="700")
mainframe.grid(column=0, row=0, sticky=(N, W, E, S))
mainframe.columnconfigure(2, weight=1)
mainframe.rowconfigure(30, weight=1)

# URL row
ttk.Label(mainframe, text="NextGen URL").grid(column=1, row=1, sticky=E)

url = StringVar()
url_entry = ttk.Entry(mainframe, width=30, textvariable=url)
url_entry.grid(column=2, row=1, sticky=(W, E), columnspan=1)
url_entry.insert(0, "http://localhost:50105")

# Username row
ttk.Label(mainframe, text="Username").grid(column=3, row=1, sticky=E)

username = StringVar()
username_entry = ttk.Entry(mainframe, width=20, textvariable=username)
username_entry.grid(column=4, row=1, sticky=(W), columnspan=1)
username_entry.insert(0, "admin")

# Password row
ttk.Label(mainframe, text="Password").grid(column=5, row=1, sticky=E)

password = StringVar()
password_entry = ttk.Entry(mainframe, width=20, textvariable=password, show="*")
password_entry.grid(column=6, row=1, sticky=(W, E), columnspan=1)
password_entry.insert(0, "netwitness")

# pathname row
ttk.Label(mainframe, text="Pathname").grid(column=1, row=3, sticky=E)

pathname = StringVar()
pathname_combo = ttk.Combobox(mainframe, width=20, textvariable=pathname)
pathname_combo.grid(column=2, row=3, sticky=(W, E), columnspan=1)
pathname_combo['values'] = ('/sdk', '/database', '/decoder', '/concentrator', '/broker', '/index',\
    '/decoder/parsers', '/decoder/import', '/decoder/parsers/upload', '/sdk/content', '/sdk/packets',\
    '/logs', '/sys', '/users','/appliance', '/appliance/upgrade')
pathname_combo.set('/sdk')

get_messages_button = ttk.Button(mainframe, text="Get Messages", command=getSupportedMessages)
get_messages_button.grid(column=3, row=3, sticky=W)

# message row
ttk.Label(mainframe, text="Message").grid(column=5, row=3, sticky=E)

message = StringVar()
message_combo = ttk.Combobox(mainframe, width=20, textvariable=message)
message_combo.grid(column=6, row=3, sticky=(W, E), columnspan=1)

get_message_help_button = ttk.Button(mainframe, text="Help", command=getMessageHelp)
get_message_help_button.grid(column=7, row=3, sticky=W)

get_message_manual_button = ttk.Button(mainframe, text="Manual", command=getMessageManPage)
get_message_manual_button.grid(column=8, row=3, sticky=W)

# parameters row
ttk.Label(mainframe, text="Parameters").grid(column=1, row=6, sticky=E)

parameters = StringVar()
parameters_entry = ttk.Entry(mainframe, width=20, textvariable=parameters)
parameters_entry.grid(column=2, row=6, sticky=(W, E), columnspan=3)

post = StringVar()
post_check = ttk.Checkbutton(mainframe, text='POST', variable=post, onvalue='POST', offvalue='GET')
post_check.grid(column=7, row=6, sticky=(W))

# accept
ttk.Label(mainframe, text="Accept").grid(column=5, row=6, sticky=E)

accept = StringVar()
accept_combo = ttk.Combobox(mainframe, width=20, textvariable=accept)
accept_combo.grid(column=6, row=6, sticky=(W, E), columnspan=1)
accept_combo['values'] = ('application/json', 'text/html', 'text/plain', 'text/xml',\
'application/octet-stream')
accept_combo.set('text/plain')

# submit button
submit_button = ttk.Button(mainframe, text="Submit", command=submitForm)
submit_button.grid(column=2, row=7, sticky=W)

# submit button
submit_file_button = ttk.Button(mainframe, text="Submit File", command=submitFile)
submit_file_button.grid(column=3, row=7, sticky=W)

# submit button
save_payload_button = ttk.Button(mainframe, text="Save Payload", command=savePayload)
save_payload_button.grid(column=6, row=7, sticky=W)

# request text
req_sep = ttk.Separator(mainframe, orient=HORIZONTAL)
req_sep.grid(column=1, row=19, columnspan=9, sticky=(W,E))

ttk.Label(mainframe, text="Request").grid(column=1, row=20, sticky=E)

for child in mainframe.winfo_children(): child.grid_configure(padx=3, pady=3)

# Stick the request text in it's own frame in order to get the scrollbars to
# align nicely
req_frame = ttk.Frame(mainframe, padding="3 3 3 3")
req_frame.grid(column=2, row=20, sticky=(N, W, E, S), columnspan=8)
req_frame.columnconfigure(0, weight=1)
req_frame.rowconfigure(0, weight=1)

request_text = Text(req_frame, wrap="none", height=10)
request_text.grid(column=0, row=0, sticky=(N, E, W))

request_scrollbarV = ttk.Scrollbar(req_frame, orient=VERTICAL, command=request_text.yview)
request_scrollbarV.grid(column=1, row=0, sticky=(N,S))
request_text['yscrollcommand'] = request_scrollbarV.set

request_scrollbarH = ttk.Scrollbar(req_frame, orient=HORIZONTAL, command=request_text.xview)
request_scrollbarH.grid(column=0, row=1, sticky=(E,W))
request_text['xscrollcommand'] = request_scrollbarH.set

# response text
ttk.Label(mainframe, text="Response").grid(column=1, row=30, sticky=E)

for child in mainframe.winfo_children(): child.grid_configure(padx=3, pady=3)

# Stick the response text in it's own frame in order to get the scrollbars to align
# nicely and also to make the text box expand nicely when the user resizes the window
res_frame = ttk.Frame(mainframe, padding="3 3 3 3")
res_frame.grid(column=2, row=30, sticky=(N, W, E, S), columnspan=8)
res_frame.columnconfigure(0, weight=1)
res_frame.rowconfigure(0, weight=1)

# Now place the response text and scrollbars in res_frame, then configure it to
# grow and shrink appropriately as the user resizes the window
response_text = Text(res_frame, wrap="none", height=20)
response_text.grid(column=0, row=0, sticky=(N, E, W, S))

response_scrollbarV = ttk.Scrollbar(res_frame, orient=VERTICAL, command=response_text.yview)
response_scrollbarV.grid(column=1, row=0, sticky=(N,S))
response_text['yscrollcommand'] = response_scrollbarV.set

response_scrollbarH = ttk.Scrollbar(res_frame, orient=HORIZONTAL, command=response_text.xview)
response_scrollbarH.grid(column=0, row=1, sticky=(E,W))
response_text['xscrollcommand'] = response_scrollbarH.set

root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)
mainframe.rowconfigure(30, weight=1)

welcome = """\
Welcome to the NextGen RESTful Test App!

To connect to NextGen, please edit the URL to point to the NextGen service
to communicate with.  Default REST ports are: Decoder - 50104,
LogDecoder - 50102, Concentrator - 50105, Broker - 50103.
Modify the username and password and press Get Messages to verify
everything works.  If it works, the Message Combobox will fill with all
supported messages for the pathname.

The parameters text field is used to add any additional parameters to the
command that will be submitted.  The format of the parameters should be in
the native NextGen format, not URL encoded.  The native format is like this:

param1=value1 param2="value 2 with embedded quote \\" and spaces"

Basically, name=value but quote the value if it has spaces.  You can also
escape any characters with a backslash \ or even use \\xHH and provide a
two digit hex number.  \\n, \\r, \\t and \\0 are also supported.  Once the
command is submitted, it will automatically URL encode the parameters, which
will be shown in the request text box.

If you are new to NextGen, let's start with a little background.  Originally,
(prior to v9.5), the only way to communicate with NextGen was using our
native protocol and we provided a C SDK to do exactly that.  We broke our
functionality into a series of nodes in a tree, something like a virtual
file system.  Each node in the system supports a fixed set of messages.
For instance, the /users node has an "addOrMod" message, which let's you
add or modify an existing user account.  Each folder node supports a
"ls" message, which returns a list of immediate child nodes.  Every node
also supports a "help" message, which can be used to discover what messages
the node supports.  This is the command sent by the Get Messages and
Get Message Help buttons.

Starting with v9.5, a RESTful HTTP layer was added to NextGen, running
on that service's default port + 100.  The RESTful layer converts HTTP
commands into the native message system, the message is sent to the
proper node, the message reply is received and converted back to proper
HTTP and returned to the client.  For the most part, this system works
flawlessly and the RESTful service has been a big hit.  Fundamentally,
HTTP is a request/response protocol and our native messaging can be and
usually is that simple.  One message request and one message response.
But...not all commands are that simple and here's where things get a
little more complicated.

On a decoder, the /decoder node supports a message called "import".
This message provides the capability to import packets directly from
a client, which usually comes from reading a pcap file.  NwConsole
provides a command called "import" which natively does exactly that.
However, the "import" message expects the client will break the pcap
into a series of chunks and send the packets to be imported over
a series of hundreds or thousands of messages.  This way we can support
arbitrarily large file transfers without memory constraints.  Well,
because "import" isn't a simple request/response model, it does not
naturally fit the RESTful model without some additional logic on the
NextGen REST service.

The normal HTTP way to transfer large files is to use chunked encoding.
However, on the NextGen side, additional logic must be added to convert
the chunked HTTP payload into native NextGen messages.  The code that does
this is located at the URL "/decoder/import".  You can POST a pcap to a
decoder at that URL and it will convert it to a series of native messages
automatically and perform the import just as naturally as NwConsole's native
import command.  Bottom line: you cannot import over HTTP using
/decoder?msg=import, which is used by the native protocol.  Instead, you
must use /decoder/import for HTTP POSTs of pcap or log files.  

One way to discover these additional URLs is to watch the logs
as the NextGen service initializes the RESTful interface.  However, I'm
going to list them here and provide a brief description of what they
do.

/decoder/import - POST a pcap or log file for importing to a decoder

/decoder/parers/upload - POST a feed or parser for a decoder

/decoder/agg - Aggregation service which will feed sessions/meta and/or logs
to a listening HTTP service.  All data is sent using google protobufs.

/sdk/content - File extraction service that returns files sent over well known
protocols like HTTP, SMTP, FTP, SMB, etc.  Heavily used by Spectrum.

/sdk/packets - Returns pcap or log files based on session IDs or a time range.

/appliance/upgrade - POST RPM or NPF files for upgrading NextGen to new versions.


The Submit button should be used for most commands.  The Submit File button
will display a file dialog so you can select a file to POST to the current
URL.  Use this command for the following pathnames: /decoder/import,
/decoder/parsers/upload or /appliance/upgrade.  The Save Payload button can
be used to write the full HTTP response to a file.  For instance, use this
button to write a pcap file after sending a command to /sdk/packets.

For additional help or updates to this python script, please check
the NetWitness Community at https://community.rsa.com/message/893120
"""

response_text.insert("end", welcome)

url_entry.focus()
# any press of the enter key on the form will auto-submit to the NextGen service
root.bind('<Return>', submitForm)

root.mainloop()
