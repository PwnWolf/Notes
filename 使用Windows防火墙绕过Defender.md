```
https://www.freebuf.com/articles/system/261770.html
```
需要解决，在恢复防火墙规则后事件和警报会显示在Defender安全中心中（重启应该能够解决）
# 介绍
通过分析流量规则确定向Defender安全中心发送请求的进程，通过添加windows防火墙规则（管理员权限），来阻止这些进程向443端口发送请求以达到绕过Defender的目的
# 分析
技术是否有效需要进行测试，使用该技术有部分难点，需要创建一个包含所有已知MD主机服务URL的防火墙规则，URL需要包类似以下的条目
```
*.blob.core.windows.net
*.azure-automation.net
```
但是这样可能会破坏某些windows服务，但是在实际渗透中，我们是不能够对客户产生过多的影响，以免被目标警觉
因此我们需要阻止特定的URL而不是所有类似的url，只要将特定的URL阻止即可实现端点的沉默而不会影响目标的使用。因此这里就需要我们找出哪些进程与端点的URL与哪些url进行通信，并阻止这些进程，这里我们需要的所有信息都在Defender for Endpoint收集，并通过Defender安全中心提供给我们。
Defender从所有正在运行的进程收集网络连接，因此可以用来找出哪些进程与已知Defender URL通信，此时我们可以通过运行下列kusto查询来查看这些进程
```
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess" 
    and (
        RemoteUrl endswith "ods.opinsights.azure.com" 
        or RemoteUrl endswith "oms.opinsights.azure.com" 
        or RemoteUrl endswith "azure-automation.net" 
        or RemoteUrl endswith "wdcp.microsoft.com"
        or RemoteUrl endswith "wdcpalt.microsoft.com"
        or RemoteUrl endswith "wd.microsoft.com"
        or RemoteUrl in (  
            "europe.x.cp.wd.microsoft.com",
            "eu.vortex-win.data.microsoft.com",
            "eu-v20.events.data.microsoft.com",
            "usseu1northprod.blob.core.windows.net",
            "usseu1westprod.blob.core.windows.net",
            "winatp-gw-neu.microsoft.com",
            "winatp-gw-weu.microsoft.com",
            "wseu1northprod.blob.core.windows.net",
            "wseu1westprod.blob.core.windows.net",
            "automatedirstrprdweu.blob.core.windows.net",
            "automatedirstrprdneu.blob.core.windows.net",
            "unitedkingdom.x.cp.wd.microsoft.com",
            "uk.vortex-win.data.microsoft.com",
            "uk-v20.events.data.microsoft.com",
            "ussuk1southprod.blob.core.windows.net",
            "ussuk1westprod.blob.core.windows.net",
            "winatp-gw-uks.microsoft.com",
            "winatp-gw-ukw.microsoft.com",
            "wsuk1southprod.blob.core.windows.net",
            "wsuk1westprod.blob.core.windows.net",
            "automatedirstrprduks.blob.core.windows.net",
            "automatedirstrprdukw.blob.core.windows.net",
            "unitedstates.x.cp.wd.microsoft.com",
            "us.vortex-win.data.microsoft.com",
            "us-v20.events.data.microsoft.com",
            "ussus1eastprod.blob.core.windows.net",
            "ussus1westprod.blob.core.windows.net",
            "ussus2eastprod.blob.core.windows.net",
            "ussus2westprod.blob.core.windows.net",
            "ussus3eastprod.blob.core.windows.net",
            "ussus3westprod.blob.core.windows.net",
            "ussus4eastprod.blob.core.windows.net",
            "ussus4westprod.blob.core.windows.net",
            "winatp-gw-cus.microsoft.com",
            "winatp-gw-eus.microsoft.com",
            "wsus1eastprod.blob.core.windows.net",
            "wsus1westprod.blob.core.windows.net",
            "wsus2eastprod.blob.core.windows.net",
            "wsus2westprod.blob.core.windows.net",
            "automatedirstrprdcus.blob.core.windows.net",
            "automatedirstrprdeus.blob.core.windows.net",
            "ussus1eastprod.blob.core.windows.net",
            "ussus1westprod.blob.core.windows.net",
            "usseu1northprod.blob.core.windows.net",
            "usseu1westprod.blob.core.windows.net",
            "ussuk1southprod.blob.core.windows.net",
            "ussuk1westprod.blob.core.windows.net",
            "ussas1eastprod.blob.core.windows.net",
            "ussas1southeastprod.blob.core.windows.net",
            "ussau1eastprod.blob.core.windows.net",
            "ussau1southeastprod.blob.core.windows.net"
        )
    )
| summarize 
    Count = count(),
    RemoteUrl = make_set(RemoteUrl),
    InitiatingProcessCommandLine = make_set(InitiatingProcessCommandLine) 
    by InitiatingProcessFileName 
| where Count > 10 
| sort by InitiatingProcessFileName
```
这里列出来的进程并不是所有的进程都会向defender发送警报请求，注意辨别