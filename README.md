# ng-rest-client

To connect to NextGen, please edit the URL to point to the NextGen service to communicate with.  Default REST ports are: 
* Decoder 50104,
* LogDecoder 50102
* Concentrator 50105
* Broker 50103
* Archiver 50108

Modify the username and password and press Get Messages to verify everything works.  If it works, the Message Combobox will fill with all supported messages for the pathname.

The parameters text field is used to add any additional parameters to the command that will be submitted.  The format of the parameters should be in the native NextGen format, not URL encoded.  The native format is like this:

    param1=value1 param2="value 2 with embedded quote \\" and spaces"

Basically, name=value but quote the value if it has spaces.  You can also escape any characters with a backslash \ or even use \\xHH and provide a two digit hex number.  \\n, \\r, \\t and \\0 are also supported.  Once the command is submitted, it will automatically URL encode the parameters, which will be shown in the request text box.

If you are new to NextGen, let's start with a little background.  Originally, (prior to v9.5), the only way to communicate with NextGen was using our native protocol and we provided a C SDK to do exactly that.  We broke our functionality into a series of nodes in a tree, something like a virtual file system.  Each node in the system supports a fixed set of messages.  For instance, the /users node has an "addOrMod" message, which let's you add or modify an existing user account.  Each folder node supports a "ls" message, which returns a list of immediate child nodes.  Every node also supports a "help" message, which can be used to discover what messages the node supports.  This is the command sent by the Get Messages and Get Message Help buttons.

Starting with v9.5, a RESTful HTTP layer was added to NextGen, running on that service's default port + 100.  The RESTful layer converts HTTP commands into the native message system, the message is sent to the proper node, the message reply is received and converted back to proper HTTP and returned to the client.  For the most part, this system works flawlessly and the RESTful service has been a big hit.  Fundamentally, HTTP is a request/response protocol and our native messaging can be and usually is that simple.  One message request and one message response.  But...not all commands are that simple and here's where things get a little more complicated.

On a decoder, the /decoder node supports a message called "import".  This message provides the capability to import packets directly from a client, which usually comes from reading a pcap file.  NwConsole provides a command called "import" which natively does exactly that. However, the "import" message expects the client will break the pcap into a series of chunks and send the packets to be imported over
a series of hundreds or thousands of messages.  This way we can support arbitrarily large file transfers without memory constraints.  Well,
because "import" isn't a simple request/response model, it does not naturally fit the RESTful model without some additional logic on the
NextGen REST service.

The normal HTTP way to transfer large files is to use chunked encoding.  However, on the NextGen side, additional logic must be added to convert the chunked HTTP payload into native NextGen messages.  The code that does this is located at the URL "/decoder/import".  You can POST a pcap to a decoder at that URL and it will convert it to a series of native messages automatically and perform the import just as naturally as NwConsole's native import command.  Bottom line: you cannot import over HTTP using /decoder?msg=import, which is used by the native protocol.  Instead, you must use /decoder/import for HTTP POSTs of pcap or log files.  

One way to discover these additional URLs is to watch the logs as the NextGen service initializes the RESTful interface.  However, I'm
going to list them here and provide a brief description of what they do.

* /decoder/import - POST a pcap or log file for importing to a decoder
* /decoder/parers/upload - POST a feed or parser for a decoder
* /decoder/agg - Aggregation service which will feed sessions/meta and/or logs to a listening HTTP service.  All data is sent using google protobufs.
* /sdk/content - File extraction service that returns files sent over well known protocols like HTTP, SMTP, FTP, SMB, etc.  Heavily used by Spectrum.
* /sdk/packets - Returns pcap or log files based on session IDs or a time range.
* /appliance/upgrade - POST RPM or NPF files for upgrading NextGen to new versions.

The Submit button should be used for most commands.  The Submit File button will display a file dialog so you can select a file to POST to the current URL.  Use this command for the following pathnames: /decoder/import, /decoder/parsers/upload or /appliance/upgrade.  The Save Payload button can be used to write the full HTTP response to a file.  For instance, use this button to write a pcap file after sending a command to /sdk/packets.

For additional help, please check the NetWitness Community at https://community.rsa.com/message/893120
