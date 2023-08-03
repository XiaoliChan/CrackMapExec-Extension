# CrackMapExec-Extension
CrackMapExec extension module/protocol support

## Table of content

* [Overview](#overview)
* [Usage](#Usage)
* [Todo](#todo)
* [References](#References)

### Overview

- ### cme-xfreerdp
  Original from: [RDPassSpray.py](https://github.com/xFreed0m/RDPassSpray/blob/master/RDPassSpray.py)  
  ![image](https://user-images.githubusercontent.com/30458572/175292568-0d8472eb-7b61-4213-bd00-549f198f4676.png)

- ### cme-rdp(Experimentally)  
  Picked function from impacket rdp_check.py(bad coding currently).  
  ![image](https://user-images.githubusercontent.com/30458572/172290058-4723e9bb-da60-4470-90a8-0e3fa15db5cf.png)

- ### cme-wmi(Experimentally)  
  Forked from [Orange-Cyberdefense upstream](https://github.com/Orange-Cyberdefense/cme-wmi) , use impacket DCOM function instead of RPCRequester.  
  For more details: [XiaoliChan's Forked](https://github.com/XiaoliChan/CrackMapExec-WMI)  
  ![image](https://user-images.githubusercontent.com/30458572/172290474-1021ab72-fbaa-43c2-801a-ba5f8e609b1c.png)

### Usage (development version)

- xfreerdp binary: [link](https://github.com/FreeRDP/FreeRDP/wiki/PreBuilds)
- wfreerdp binary: [link](https://ci.freerdp.com/job/freerdp-nightly-windows/arch=win64,label=vs2013/)

- Sys env: ubuntu 22.04 / kali
```
git clone https://github.com/mpgn/CrackMapExec.git
cd CrackMapExec
git clone https://github.com/XiaoliChan/CrackMapExec-Extension.git
cp -r CrackMapExec-Extension/cme-wmi/* cme/protocols/
cp -r CrackMapExec-Extension/cme-xfreerdp/* cme/protocols/
python3 -m pip install pipx
pipx install .
```
