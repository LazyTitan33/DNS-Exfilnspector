# DNS-Exfilnspector
Decode DNS Exfiltration queries automatically to convert Blind RCE into proper RCE via Burp Collaborator

#### Requirements:
[Burp Suite Professional Edition](https://portswigger.net/burp/documentation/desktop/getting-started/download-and-install)  
[Jython 2.7.3](https://www.jython.org/download.html)

#### How to install:  
[Install in Burp Suite](https://github.com/0xC01DF00D/Collabfiltrator/wiki/Installation-in-Burp-Suite-Professional)

#### Usage:
By default, the decoding is done from Base64. On the left side of the output box, you can choose the words that you are using to replace the Base64 special characters in your DNS exfiltration. By default, as it was tested with [Ivan Šincek](https://github.com/ivan-sincek/) [DNS Exfiltration tool](https://github.com/ivan-sincek/dns-exfiltrator), it will use _EQLS_, _slash_ and _plus_.
![image](https://github.com/LazyTitan33/DNS-Exfilnspector/assets/80063008/930b42c5-022a-4ba6-9fca-587215ed6aac)

You can also check the box at the top if you are doing DNS Exfiltration via HEX encoding. For testing with HEX DNS Exfiltration I have developed this [tool](https://github.com/LazyTitan33/DNS-Exfilnspector):

At the click of a button, you can generate a Burp Collaborator link:  
![image](https://github.com/LazyTitan33/DNS-Exfilnspector/assets/80063008/69055b12-ff7c-40f0-8a18-deba5bf691d6)

You also have a button to copy that link to your clipboard. 
