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
  
# Day 1: LESSON 1-3 - Pen Testing | Exploitation Research | Recon & Scanning

# Pen Testing
  ## Phase 1: Mission
        -Scope of Mission
        -Determine valid targets (networks/machines)
        -Define RoE
  ## Phase 2: Recon
        -Public info gathering
        -DO NOT TOUCH THE TARGET
  ## Phase 3: Footprinting
        -Scan network/targets
  ## Phase 4: Exploitation/Initial Access
        -Gain it
  ## Phase 5: Post-exploitation
      -Persistence
      -Escalate priveleges
      -Obfuscate
      -Cover tracks
      -Exfiltrate target data
  ## Phase 6: Document/Report Mission

  

  # Network Recon & Scanning
  ## Create Control Socket
  ssh -MS /tmp/jump student@10.50.15.96
   ### -M puts SSH into Master mode & multiplexing
   ### -S creates socket in specified directory
   ### Authenticate to jumpbox

  ## Ping Sweep 
  for i in {x..y}; do (ping -c 1 x.x.x.$i | grep "bytes from" &); done


  ## Set up Dyanmic port forward
  ssh -S /tmp/jump jump -O forward -D 9050

  ## Scan targets found 
  proxychains nmap <ip>

  ## Banner Grab open ports, Verify port services
  proxychains nc <ip> <port>
  !Press enter key just in case to get more info

  ## Set up local port forward to open port
  ssh -S /tmp/jump jump -O forward -L 1111:<tgt_ip>:<tgt_port> -L 1112:<tgt_ip>:<tgt_port>

  ## Use Firefox
  127.0.0.1:<localportforward>

#################################################################################################### 

  ## Create New Master Socket To New IP
  ssh -MS /tmp/t1 username@127.0.0.1 -p 1112
  
  
    
    
 
