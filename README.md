# ssg2srx

A perl program that converts juniper screenOS(ssg) configuration to junOS(srx) configuration

usage:
perl ssg2srx.pl [-c \<your ssg config file\>] [-d \<compare.xlsx\>] [-s \<service-map.xlsx\>] [\<your ssg config file\>]

source和destination nat中source/destination-address-name地址需在global中定义

- [ ] 解析nat条目中的源和目的地址
