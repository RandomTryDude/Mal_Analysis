https://www.virustotal.com/gui/file/f8fef470326c2834b213fe47a5024edbb101dc966395622a6617f686d330fb52/detection 


Campaign ID: F867700a
Campaign Name: Digler
Program Version : 1.0.2 

This new format now take argument when ran 
-> Microsoft_Installer_Agent_V3_RunFromArgs 

As of 16/02/2026 it is detected by only one AV

<img width="1304" height="361" alt="image" src="https://github.com/user-attachments/assets/4853b7fd-50d7-4410-b4a1-e314573eb1a0" />





Starting with Digler v1.0.2 new domains for the workers  :
<img width="1119" height="239" alt="image" src="https://github.com/user-attachments/assets/1fc66c33-2178-45fb-b31c-22a863bf2c06" />


from a random name to trusted instances 

<img width="962" height="101" alt="image" src="https://github.com/user-attachments/assets/f5bb5879-b20d-4725-ae28-f00288ed2a1c" />

wonder if their instance is secured ... BUT not now.



the result of the offline Key Verification ( based on the md5 of the date) 
 
 <img width="713" height="239" alt="image" src="https://github.com/user-attachments/assets/4cda4c6a-f54f-4635-b1bd-0f5657b06c63" />


 By selected the mov eax,1 , the program will believe we do infact have a valid key , the verification is better than for v1.0.1 but can still be easy to bypass 


  
  
<img width="646" height="163" alt="image" src="https://github.com/user-attachments/assets/3296284b-1c6a-495d-b30e-ae08d4d1efbc" />

based on the parameters the program was launched with (none , all , windows_service) different persistances mechanism will be put in place the cute IOC !! 


