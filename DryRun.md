# Dry Run Details
  ## Stack Number 14
  ## USER: VERA-016-M
  ## PASS: plxcy00G2RdT
  ## 1st Target: 10.50.14.238
  _____________________________________________________________
# Start
  ## Target 1: 10.50.14.238
  ## Ports: 22, 53, 80
  ## HTTP-ENUM scan:
        -/login.php
        -/login.html
        -/img/
        -/scripts/
  ## Actions
    1.Went To firefox: 10.50.14.238/login.html
    2.Trying SQL UN, PW injection: tom' OR 1='1 = SUCCESSFUL
    3. Was Given Command Injection Page. Trying ssh keygen exploit: SUCCESSFUL 
    4. SSH CONNECTION TO PublicFacingWebsite: Established
    5. Enumeration:
        - pwd: /var/www
        - whoami: www-data
        - ifconfig: 10.10.28.40
        - CCHaplann@UNiversalExports.com \ PublicAffairs@TargetCorp.com
        -Suite 112, 1607 Range Rd, Tampa, FL 33601
        -SQL Server
     6. Ping sweep scan: 10.10.28.1, 10.10.28.17, [---10.10.28.20---] 
     7. Set up dynamic tunnel on ssh to .238

  ## Target 1 - OTHER INTERFACE 
  ## Ports: 22, 80
  ## HTTP-ENUM Scan
    -/login.php
    -/login.html
    -/img/
    -/scripts/
    -/server-status
  ## Actions
    8. Set up local forwarder to 10.10.28.20 port 80 RHP: 1112
    9. Query 127.0.0.1:1112/*, Different webpage at first glance
    10. Notes: 
        - Universal Exports 
        - Letter from CEO
        - Link to HOME
        - Link to Job Openings ( Potential Attack Vector )
        - Link to Contact
        - Link to Employee Sign in ( Attack Vector )
        - Donovian Logo in the background
      11. In employee sign in, using SQL un pw injection : SUCCESSFUL 
      12. Was Given Command Injection Page. Trying ssh keygen exploit: SUCCESSFUL
      13. REALIZED I WAS STILL ENUMERATING THE GODDAMN PUBLIC FACING WEBSITE
      14. Went back to: cat /etc/hosts - found BestWebApp has ip 192.168.28.175

   ## Target 2: 192.168.28.175
     -Used SQL schema injections GET request method to enumerate
     -Got UNS & PWS
         a. Aaron : appleBottomJ3an$
         b. user2 : TurkeyDay24
         c. user3 : Bob4THEpin3apples
         d. Lee_Roth : Lroth
         e. Lroth : anotherpassword4THEages
        
        
     

