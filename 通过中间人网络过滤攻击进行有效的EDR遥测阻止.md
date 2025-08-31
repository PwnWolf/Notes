`https://tierzerosecurity.co.nz/2024/07/23/edr-telemetry-blocker.html`
# 前置知识
ARP欺骗
中间人（PitM）攻击
全双工、半双工
# 介绍
通过执行中间人（PitM）工具和筛选遥测数据包来阻止EDR遥测数据达到其云服务器，从而有效地向SOC团队隐藏报警。这可以通过对目标主机进行ARP欺骗并配置iptables来实现。我们可以在TLS客户端Hello数据包中使用服务器名称指示（SNI）来识别遥阻止的特定IP地址，而不是阻止各种IP子网，虽然未发送的警报会缓存在主机上，但是会在重新启动时清除它们。
ARP欺骗通常用于PitM攻击，通过明文协议窃取凭据，在这里我们会解释如何通过ARP欺骗的中间人攻击来阻止其远程API的EDR遥测流量，使得警报静音。这种方法相对于主机上的网络过滤攻击（如操纵防火墙规则或windows过滤平台（WFP））的优势在于他不需要管理权限或访问受害主机，但是确实需要攻击者控制的计算机与受害主机位于同一网络上
![[arp_spoofing.png]]
当受害主机需要连接到外网时，需要通过网关进行路由，主机将尝试通过发送ARP请求广播包来找到网关的MAC地址，然后攻击者机器不断发送ARP回复，声称网关的MAC为自己的MAC地址，此操作会使得受害主机相信攻击者机器就是网关机并更新自己的ARP缓存表。注意这里并不是全双工设置，这意味着只有受害者主机上的ARP表会被毒害，而不是网关的ARP表，这样会使得攻击更难以被检测，只有来自受害者的主机出站流量会被影响。
# 如何利用ARP欺骗进行PitM攻击
## 环境
攻击者：ubuntu24.0.4
受害者：安装Defender for endponit的windows 11
```
# 安装arpspoof
apt install dsniff
# 启用IP转发
sysctl -w net.ipv4.ip_forward=1
# 运行arpspoof
arpspoof -i <interface> -t <target ip> <gateway ip>
# 通过浏览受害者主机上的网站并使用tcpdump观察攻击者机器上的出站流量来确定
tcpdump -i <interface> host <victim ip>
```
# 阻止EDR遥测
在中间人攻击期间，可以通过在Forward表中配置来使用iptables丢弃流量，该表控制通过主机路由的数据包，我们可以根据目标IP地址或子网编写DROP规则，但是这里遇到了一个重大的挑战
在受害者主机上进行EDR遥测过滤的文章中强调了覆盖IP地址的难度，并指出某些EDR产品与数百甚至数千个联系服务器通信，因此很难保持隐蔽的同时覆盖所有联系服务器，为解决这个问题，他们的解决方案包括硬编码进程名称并阻止这些进程生成的任何出站流量，遗憾的是，这种技术无法应用与PitM场景，因为攻击者的机器不知道是那个进程生成的流量。
# TLS握手
大多数EDR供应商都是用TLS加密通过端口443与其远程API进程通信，虽然TLS已在保护通信安全，但是初始密钥交换流量的某些部分是可读的，例如：作为初始握手过程的一部分客户端消息包含可读信息，如服务器名称指示器（SNI）
因此我们可以通过使用iptables拦截客户端数据包来实现阻止TLS密钥交换完成
```
iptables -A FORWARD -p tcp --dport 433 0m string "xxx.com" --algo bm DROP
```
但是在实现过程中，这种方法看似已经生效了，但是随着时间的推移一些数据包被遗漏，导致EDR控制台接收遥测数据并发出警报，这可能是由于解析方式和高流量造成的。与基于IP地址或端口丢弃数据包相比，iptables进行字符串匹配的效率低。
因此我们选择使用python scapy编写自己的poc工具
`https://github.com/TierZeroSecurity/edr_blocker`
功能：
- EDR遥测阻断技术
	python scapy库支持解析TLS握手（包括SNI），即使Scapy运行在用户模式而非内核模式，其性能也优于iptables字符串匹配，该库无法丢弃数据包，因此我们的思路是解析客户端数据包中的SNI，并根据字典进行检查，如果找到匹配项，iptables会更新为更高效的规则，如根据目标iP地址丢弃数据
- 内置ARP欺骗
	scapy能够自定义数据包，包括ARP应答，因此我们可以在同一代码中嵌入ARP欺骗功能，该工具获取目标主机IP地址和网关地址IP，并向目标发送伪造的ARP应答，以冒充网关并执行PitM攻击。当该工具终止时，他会向目标发送正确的ARP应答，以回复被污染的ARP表
- 确保攻击者机器启用了数据包转发，如：检测是否执行sysctl -n net.ipv4.ip_forward
- 监控模式： 当SNI包含被阻止的条目时，他不会创建iptables规则
- 详细模式： 输出客户端数据包中所有服务器名称
- 输入文件： 需要包含一个需要拦截的服务器名称的文件路径，以便于TLS握手的SNI服务器名称进行匹配
# 阻止Microsoft Defender for Endpoint 遥测
Microsoft Defender for Endpoint 或windows在与远程API通信时会定期启动TLS握手，其阻止服务器名称如下:
```
events.data.microsoft.com
wd.microsoft.com
wdcpalt.microsoft.com
wdcp.microsoft.com
blob.core.windows.net
winatp-gw-cus
automatedirstrprdcus
endpoint.security.microsoft.com
smartscreen.microsoft.com
```
阻止这些TLS不会影响其他Microsoft服务，如teams、outlook、O365，但是在使用该工具前需要再本地进行测试，云服务器无法访问时发生的任何事件或警报都将缓存在本地，但是重新启动时会被清楚，从而导致可见性丧失
# 实现代码

