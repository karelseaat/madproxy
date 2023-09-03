import psutil

addrs = psutil.net_if_addrs()
print(addrs.keys())

for inter in addrs.items():
    print(inter[1][0][1], inter[0])
