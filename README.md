# DNS-Exfilnspector
Automagically decode DNS Exfiltration queries to convert Blind RCE into proper RCE via Burp Collaborator

#### Requirements:
[Burp Suite Professional Edition](https://portswigger.net/burp/documentation/desktop/getting-started/download-and-install)  
[Jython 2.7.3](https://www.jython.org/download.html)

#### How to install:  
[Install in Burp Suite](https://github.com/0xC01DF00D/Collabfiltrator/wiki/Installation-in-Burp-Suite-Professional)

#### Reason this exists:
I was on an engagement where I couldn't send large payloads but I could upload a file and run it with some arguments but again, I was very restricted on length. I found a DNS exfiltrator tool, but I had to constantly change the Collaborator link or I had to manually copy and paste the DNS responses and decode them. I tried using the [Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator) plugin but again, I encountered the same issues and it wasn't universally applicable enough for my needs. So I made my own universal DNS decoder.

#### Usage:
By default, the decoding is done from Base64. On the left side of the output box, you can choose the words that you are using to replace the Base64 special characters in your DNS exfiltration. By default, as it was tested with [Ivan Šincek](https://github.com/ivan-sincek/) [DNS Exfiltration tool](https://github.com/ivan-sincek/dns-exfiltrator), it will use _eqls_, _slash_ and _plus_.
![image](https://i.imgur.com/BdKoGwt.png)

You can also check the box at the top if you are doing DNS Exfiltration via HEX encoding. For testing with HEX DNS Exfiltration I have developed this [tool](https://github.com/LazyTitan33/DNS-Exfilnspector):

At the click of a button, you can generate a Burp Collaborator link:  
![image](https://i.imgur.com/Ssbm6GV.png)

You also have a button to copy that link to your clipboard. After sending the payload to the Collaborator, the listener stops when it no longer detects interactions with the Collaborator and decodes the output and displays it automatically. Then the listener starts back up. This allows you to reuse the same Burp Collaborator link as many times as you want:

![image](https://i.imgur.com/XeQHCLz.png)

You can switch back and forth between Base64 and Hex while using the same Burp Collaborator link and it even supports receiving and decoding multiple lines. If like me, you forget to switch between encodings, it fails the decoding and reminds you to check.  
![image](https://i.imgur.com/MdXKfYL.png)

I checked the box for base64 and reissued the command to exfiltrate and we get the output properly and automatically decoded:  
![image](https://i.imgur.com/DudmLPF.png)

If, at the end, you want to save the Raw or Decoded output, you have buttons on the right side to do so.  
![image](https://i.imgur.com/QADJeTa.png)

Clicking on the button opens a window for you to choose where to save the output, in what file and after you open said file, you'll see each RAW output on a new line, in the order they were received.  
![image](https://i.imgur.com/OwbyDn7.png)

In the same fashion, you can save your Decoded output at the end of your session to store it locally:  
![image](https://i.imgur.com/wRlFZiC.png)

Clicking on the Stop Listener button stops the Burp Collaborator from listening, but if you want to continue and use the same link, you can click on **Continue Collaborator** or if you wish to generate a new link, you can click on **Get New Collaborator Link**:  
![image](https://i.imgur.com/n3paVer.png)

The **Clear Output** button is self explanatory helping you to clear the output box:  
![image](https://i.imgur.com/UvvSShP.png)

### Special Thanks for inspiration to the creators of [Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
