# sslkill

SSL Kill is a forced man-in-the-middle transparent proxy that modifies HTTP requests and responses in order to avoid SSL and HSTS, to achieve that, it use a two-way ARP spoofing plus a forced DNS resolver that redirects all name server queries to the attacker IP Address. This tool is for information security researchers and should not be used for criminal acts


SSL Kill v1.0<br/>


![alt text] (banner.png)


## Installation
```
   $sudo apt-get install build-essential python-dev libnetfilter-queue-dev
   $git clone https://github.com/m4n3dw0lf/sslkill
   $cd sslkill
   $sudo pip install -r requirements.txt
   $sudo chmod +x sslkill
   $sudo ./sslkill -h
```

## Basics
```
usage: 
 Network interface:     -i <INTERFACE> or --interface <INTERFACE> 
 Target IP Address:     -t <TARGET> or --target <TARGET> 
 Gateway IP Address:	-g <GATEWAY> or --gateway <GATEWAY>
 Debugg mode:	        -d Turn debugger ON, default = OFF

examples:
  $sudo ./sslkill.py -i wlan0 -t 10.0.0.3 -g 10.0.0.1

```
