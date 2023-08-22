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

- ### cme-wmi
  Merged in official branch now. :)

- ### cme-zerologon-autopwn
  CME 192.168.1.1 -u '' -p '' -M zerologon -o mode=pwn

### Usage (development version)

- xfreerdp binary: [link](https://github.com/FreeRDP/FreeRDP/wiki/PreBuilds)
- wfreerdp binary: [link](https://ci.freerdp.com/job/freerdp-nightly-windows/arch=win64,label=vs2013/)

- Sys env: ubuntu 22.04 / kali
```
git clone https://github.com/mpgn/CrackMapExec.git
cd CrackMapExec
git clone https://github.com/XiaoliChan/CrackMapExec-Extension.git
cp -r CrackMapExec-Extension/cme-xfreerdp/* cme/protocols/
python3 -m pip install pipx
pipx install .
```
