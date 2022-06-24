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

- Sys env: ubuntu 22.04
```
git clone https://github.com/byt3bl33d3r/CrackMapExec.git
cd CrackMapExec
echo "cchardet" >> requirements.txt
change 'impacket==0.9.24' to 'impacket' (latest version)
python3 -m venv cme-env
source cme-env/bin/activate
pip3 install -r requirements.txt
cp cme/crackmapexec.py .
python3 crackmapexec.py (make sure it can execute)

git clone https://github.com/XiaoliChan/CrackMapExec-Extension.git
cp -r CrackMapExec-Extension/cme-rdp/* cme/protocols/

or

cp -r CrackMapExec-Extension/cme-xfreerdp/* cme/protocols/
```
