SourceThread: https://www.reddit.com/r/antivirus/comments/1r9kk7l/beta_game_malware_yaremos/ 

AttackMode : Hacked Discord 
`Hey Mate i'm developing a game can you try it %link%`

-> Download the .zip 
-> Zip contain .msi 
-> Game install itself 
-> If you run the game -> execute %install_location%/scripts/crypted.js 
                       -> execute %install_location%/scripts/discord-injection-obf.js 

      

discord-injection-obf.js :

Main point : extract a secondary payload from itself using AES 
payload stored as such [payload,enc,iv,masterkey] 

<img width="1215" height="72" alt="image" src="https://github.com/user-attachments/assets/33104948-3e68-4c32-bd75-acef5de7172e" />

Later decrypted using : 

<img width="1608" height="160" alt="image" src="https://github.com/user-attachments/assets/007b9356-10c0-4016-99dd-2d4516596ea1" />


we'll swap to the newfound part which is the culprit for the discord part : 

<img width="1459" height="512" alt="image" src="https://github.com/user-attachments/assets/237d4cb2-f964-42dc-92ce-4be8e44a8782" />

Which give us our first link 

In term of capabilities we get : 
account fetching (Username, avatar , Userbadges , PhoneNumber , billing info , IP , email , account MFA (enabled?) & password 

<img width="1772" height="612" alt="image" src="https://github.com/user-attachments/assets/1acccf58-1492-4353-acaf-b1beb2cd8dce" />

Password Changer : 


 <img width="1652" height="463" alt="image" src="https://github.com/user-attachments/assets/6f4cad3b-39cd-4290-a413-a30fc290a0cb" />

And send/recieve the .zip of whatever was stolen using crypted.js 


Then finally export itself as core.asar : 

 <img width="1820" height="134" alt="image" src="https://github.com/user-attachments/assets/ef1809f8-3653-4895-b097-f8dbb3972081" />

that's our first persistance mechanism : 
you'll find it under %LocalAppData%/Discord/app-<some version>/modules/discord_desktop_core-<number>/discord_desktop_core/ 

explanation on (https://gist.github.com/vanyle/edbdd0c28a0150af3b905b99a4c48f00) 
it let you mod your discord client. 


Now we get on the 'gatherring' intel part 

Crypted.js 


Same model as before , the main payload is encrypted 

<img width="1362" height="102" alt="image" src="https://github.com/user-attachments/assets/447b5fbf-6f80-4e6b-bf79-f3ee00833914" />



Quick decrypt :
and we get this cutie : 

https://www.virustotal.com/gui/file/169a23484fb0f903cc8374ec797d72078caabab252b46476579ebdb62b847144 


<img width="1836" height="454" alt="image" src="https://github.com/user-attachments/assets/3223b719-c852-4688-b2b8-6f56aad4be3d" />


there we get all the necessary element to upload any file it may find on the target system 

Target : 

<img width="1256" height="591" alt="image" src="https://github.com/user-attachments/assets/6c861253-e87b-4900-a1cc-457cad3c967f" /> 

anything that may contain some intels  

List : Chrome.exe  , msedge.exe , brave.exe , firefox.exe , opera.exe , operaGX , vivaldi , Yandex  , Roblox (username , ip , payement data and so on) 

Bypass / commands ran : 

reg add HKCU\\software\\Classes\ms-settings\\shell\open\command /ve /t REG_SZ /d fodhelper.exe /f 
reg add HKCU\\software\\Classes\ms-settings\\shell\open\command /v DelegateExecute /t REG_SZ /d "" /f 


Ability to upload files to gofile :

 <img width="1825" height="271" alt="image" src="https://github.com/user-attachments/assets/c4a9c014-a67d-40d2-bc83-c67353adc398" />

 Discord Token Finder 

 <img width="865" height="139" alt="image" src="https://github.com/user-attachments/assets/5f7479f9-f266-4be5-b9fc-7bf0ae97cc14" />


 then dump any of the browssers founds DB / tokens :
 
 <img width="1820" height="481" alt="image" src="https://github.com/user-attachments/assets/b371c3fc-b6cc-4d8d-aba5-b8d981daa124" />

 and taskill it once done 
 as well as 

  <img width="1376" height="242" alt="image" src="https://github.com/user-attachments/assets/b37bd7db-3452-4bb2-8ea8-16795321b842" />

<img width="1741" height="310" alt="image" src="https://github.com/user-attachments/assets/f0c9214e-405e-4f48-88a8-fa6cb84bf109" />



  any Credit cards saved. (dont save your credit card it's 12 numbers comeon) 


first exttraction path :  

<img width="1329" height="145" alt="image" src="https://github.com/user-attachments/assets/94dd938e-fdbe-437c-9a7f-b8811e3f7231" />

as a .zip 

Cleanup of Browsers harvesting : 

<img width="1630" height="352" alt="image" src="https://github.com/user-attachments/assets/903bdc3c-64fe-4a37-926a-b474ffd29a4d" />



LIke the rest Yandex also get harvested & killed :
<img width="1813" height="340" alt="image" src="https://github.com/user-attachments/assets/ff4f716c-1236-4b94-aeda-ba576315f270" />



IOCS :

Extracted file 
https://www.virustotal.com/gui/file/c325db8133c1939971a4369d8f1ded74bde8f5488240da5f838ac24d98c37bbf/
https://www.virustotal.com/gui/file/da3f67f4f79f40d93a18d69993e3041246b48d5545657b4278f88341baa832ad/
crypted.js  md5: e7daaca7357fff36c7da68e6801a4dfd
discord-injection-obf.js  md5: 1739b4cb315e2e09862c86f508895325 

Joined link : 
`https://network-sync-protocol[.]net/`

https://www.virustotal.com/gui/url/4611bae71a26c48eba5af9f8ae7ca93151aba86123e6013717b4abfb89c094c0/community

`https://datanetworksync[.]onrender[.]com`
https://www.virustotal.com/gui/url/fea3f44d88eb3c9bebff1b74bb00afeeeac3c5c62d8ff01d2af9276530ac64ac 

