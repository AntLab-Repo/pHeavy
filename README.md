# pHeavy: Predicting Heavy Flows in the Programmable Data Plane

## Overview
pHeavy is a machine learning based scheme for predicting heavy flows directly on the programmable data plane. This repository contains the source code for our paper published on TNSM:  

* Xiaoquan Zhang, Lin Cui, Fung Po Tso and Weijia Jia, "pHeavy: Predicting Heavy Flows in the Programmable Data Plane", _IEEE Transactions on Network and Service Management_, 18(4), pp.4353-4364. 

## About the code

### BMv2

To be added soon...

### Tofino ASIC

The core is written by P4<sub>16</sub> running in programmable switches (i.e., Tofino AISC).

The Tofino-version code implements the prediction of TCP traffic via optional features (e.g., TCP flgas, packet length and port) and memory management via registers.

## Citations

If you find this code useful in your research, please cite the following papers:

* Xiaoquan Zhang, Lin Cui, Fung Po Tso and Weijia Jia, "pHeavy: Predicting Heavy Flows in the Programmable Data Plane", _IEEE Transactions on Network and Service Management_, 18(4), pp.4353-4364. 
```bibtex
@article{zhang2021pheavy,
  title={pHeavy: Predicting Heavy Flows in the Programmable Data Plane},
  author={Zhang, Xiaoquan and Cui, Lin and Tso, Fung Po and Jia, Weijia},
  journal={IEEE Transactions on Network and Service Management},
  volume={18},
  number={4},
  pages={4353--4364},
  year={2021},
  publisher={IEEE}
}
```

* Xiaoquan Zhang, Lin Cui, Kaimin Wei, Fung Po Tso, Yangyang Ji, and Weijia Jia, "A survey on stateful data plane in software defined networks", _Computer Networks_, 184, p.107597.
```bibtex
@article{zhang2021survey,
  title={A survey on stateful data plane in software defined networks},
  author={Zhang, Xiaoquan and Cui, Lin and Wei, Kaimin and Tso, Fung Po and Ji, Yangyang and Jia, Weijia},
  journal={Computer Networks},
  volume={184},
  pages={107597},
  year={2021},
  publisher={Elsevier}
}
```
