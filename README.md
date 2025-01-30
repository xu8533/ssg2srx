# ssg2srx

A perl program that converts juniper screenOS(ssg) configuration to junOS(srx) configuration

usage:
perl ssg2srx.pl [-c \<your ssg config file\>] [-d \<compare.xlsx\>] [-s \<service-map.xlsx\>] [\<your ssg config file\>]

source和destination nat中source/destination-address-name地址需在global中定义

- [x] 按每组8个，分解nat条目中的source和destination，application
- [x] 解析nat条目中的源和目的地址
- [x] 解析nat条目中的address-set
- [ ] VIP(virtual ip)条目解析
