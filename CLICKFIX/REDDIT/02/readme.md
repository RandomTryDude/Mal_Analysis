Source Thread: 
https://www.reddit.com/r/cybersecurity_help/comments/1r4ae25/what_does_this_clickfixlumma_infostealer_ps/ 


--------------------------
Initial Discovery : 

- The main ps1 command will download & execute instruction from a storage.googleapis.com/release-v5-dl/fin2.txt & run it with IEX 
- The downloaded file will set $errorActionPreference to SilentlyContinue and hide the next code line into big text blob that will throw an error 
Clear the junk and you basically get a base64 string that's first reverse , decoded from base64 & reverse again 
This one will download 'OpenVPN-2.6.17-I001-amd64.msi' from the same storage.googleapis.com as before
and execute it. 
(on the S3 bucket there's a few different payloads ) 
