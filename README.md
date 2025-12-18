# DNS-Exfilnspector
Automagically decode DNS Exfiltration queries to convert Blind RCE into proper RCE via Burp Collaborator

#### Requirements:
[Burp Suite Professional Edition](https://portswigger.net/burp/documentation/desktop/getting-started/download-and-install)  
[Jython 2.7.3](https://www.jython.org/download.html)

#### How to install:  
[Manual install in Burp Suite](https://github.com/LazyTitan33/DNS-Exfilnspector/wiki/Installation-in-BurpSuite-Pro)  
[Download from Bapp Store](https://portswigger.net/bappstore/0e9c1b7acd25422ab1fd1df5d1f09bbd)

#### Reason this exists:
I was on an engagement where I couldn't send large payloads but I could upload a file and run it with some arguments but again, I was very restricted on length. I found a DNS exfiltrator tool, but I had to constantly change the Collaborator link or I had to manually copy and paste the DNS responses and decode them. I tried using the [Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator) plugin but again, I encountered the same issues and it wasn't universally applicable enough for my needs. So I made my own universal DNS decoder.

#### Usage:
By default, the decoding is done from Hex. For Base64 you have options on the left side of the output box, from where you can choose the words that you are using to replace the Base64 special characters in your DNS exfiltration. By default, as it was tested with [Ivan Šincek](https://github.com/ivan-sincek/) [DNS Exfiltration tool](https://github.com/ivan-sincek/dns-exfiltrator), it will use _eqls_, _slash_ and _plus_.

<img width="1356" height="602" alt="image" src="https://github.com/user-attachments/assets/cf1200c1-d5f3-40ed-9914-1ac8e9313407" />

For testing with HEX DNS Exfiltration I have developed this [tool](https://github.com/LazyTitan33/dns-exfiltrator-hex):

At the click of a button, you can generate a Burp Collaborator link:  
<p align="center"><img width="745" height="264" alt="image" src="https://github.com/user-attachments/assets/e57324ba-8b5f-437e-aaf7-0121cc2f2734" /></p>

You also have a button to copy that link to your clipboard. After sending the payload to the Collaborator, the listener stops when it no longer detects interactions with the Collaborator and decodes the output and displays it automatically. Then the listener starts back up. This allows you to reuse the same Burp Collaborator link as many times as you want:

<img width="1349" height="606" alt="image" src="https://github.com/user-attachments/assets/6f9dda7a-15c7-4e87-9064-72d40e51d2d4" />

You can switch back and forth between Base64, Base32 and Hex while using the same Burp Collaborator link and it even supports receiving and decoding multiple lines. If like me, you forget to switch between encodings, it fails the decoding and reminds you to check.  
<img width="1355" height="612" alt="image" src="https://github.com/user-attachments/assets/cca16fdd-6e87-431e-b2ee-b461b2e8d62f" />

I checked the box for base32 and reissued the command to exfiltrate and we get the output properly and automatically decoded. I've used my own DNS exfiltration [tool](link) via Base32:  
<img width="1355" height="612" alt="image" src="https://github.com/user-attachments/assets/810ae701-8ae8-4bf7-8652-77c0be7166cf" />

If, at the end, you want to save the Raw or Decoded output, you have buttons on the right side to do so.  
<p align="center"><img width="173" height="125" alt="image" src="https://github.com/user-attachments/assets/b5ea964a-ded8-470c-87b6-432b5321657b" /></p>

Clicking on the button opens a window for you to choose where to save the output, in what file and after you open said file, you'll see each RAW output on a new line, in the order they were received.  
![image](https://i.imgur.com/OwbyDn7.png)

In the same fashion, you can save your Decoded output at the end of your session to store it locally:  
<p align="center"><img width="841" height="843" alt="image" src="https://github.com/user-attachments/assets/d8daa195-fce3-41a2-bc88-415dce21933c" /></p>

Clicking on the Stop Listener button stops the Burp Collaborator from listening, but if you want to continue and use the same link, you can click on **Continue Listening** or if you wish to generate a new link, you can click on **Get New Link**:  

The **Clear Output** button is self explanatory helping you to clear the output box:  
<img width="1081" height="479" alt="image" src="https://github.com/user-attachments/assets/a97420d6-af91-41a6-b7b4-6a2344b513f4" />



### Special Thanks for inspiration to the creators of [Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
