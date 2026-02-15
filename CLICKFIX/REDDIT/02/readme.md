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
The storage in question has been reported , i took some time to dump it if you wanna parse it it will be inside S3_Content.zip per usual password is infected






checkbinary.exe (A golang file) 

Appear to check for valid license key (possible MAAS ?) 



So From the golang analysis : 



<img width="576" height="92" alt="image" src="https://github.com/user-attachments/assets/02d2cca6-bcb1-46a1-9068-857a66b51c28" />

We can expect some remote KEY checking if we dive a bit into this function : 

<img width="438" height="270" alt="image" src="https://github.com/user-attachments/assets/4a5ac6a6-fd45-4d86-b171-95ac346b8cad" />


we got a post request on a remote worker  that is decoded a bit earlier in the decrypt() function 
<img width="364" height="65" alt="image" src="https://github.com/user-attachments/assets/d3ce6363-021a-4bf7-ac56-37bd93bb1194" />



We can now confirm there's a remote checking server in place : 

<img width="855" height="176" alt="image" src="https://github.com/user-attachments/assets/f06c0610-6379-4729-8c9d-407517b9b81d" />

So we are in fact working on a malware that's proposed as a service . 


for our purpose we are gonna bypass the key verification 
 <img width="627" height="126" alt="image" src="https://github.com/user-attachments/assets/660f8716-30ea-426b-9326-ce00fa1410da" />
 this check basically compare the len of RSI (remote_check) to 4 
If not equal , we go contact our remote website to check for the license 
or check if the string in rsi is 'none'
<img width="462" height="76" alt="image" src="https://github.com/user-attachments/assets/ba76e765-2510-49bc-9a62-8d54d1fa5019" />
if it is : 
<img width="580" height="116" alt="image" src="https://github.com/user-attachments/assets/af7d2866-066a-46cc-855d-b2b7bbffd5c8" />

we get to skip the key Otherwise the program exit itself.






