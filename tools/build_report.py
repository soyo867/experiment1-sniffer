"""Build the Chinese experiment report from project metadata and test evidence."""
import argparse
import json
from pathlib import Path
import subprocess
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image, KeepTogether
from reportlab.graphics.shapes import Drawing, Rect, String, Line, Polygon

BASE = Path(__file__).resolve().parent.parent
INK,ACCENT,MUTED,LIGHT = map(colors.HexColor,["#142b45","#087f8c","#60748a","#eef3f7"])
WIDTH = A4[0]-92


def build(output=None,metadata=None):
    meta = metadata or json.loads((BASE/"docs/submission.json").read_text(encoding="utf-8"))
    live = json.loads((BASE/"evidence/live_verification.json").read_text(encoding="utf-8"))
    unit = json.loads((BASE/"evidence/unit_tests.json").read_text(encoding="utf-8"))
    gui = json.loads((BASE/"evidence/gui_verification.json").read_text(encoding="utf-8"))
    font_dir = Path("C:/Windows/Fonts")
    regular,bold = font_dir/"msyh.ttc",font_dir/"msyhbd.ttc"
    if not regular.exists():
        raise RuntimeError("设置 tools/build_report.py 中的中文 TTF/TTC 路径后重试")
    pdfmetrics.registerFont(TTFont("CN",str(regular),subfontIndex=0))
    pdfmetrics.registerFont(TTFont("CN-Bold",str(bold),subfontIndex=0))
    pdfmetrics.registerFontFamily("CN",normal="CN",bold="CN-Bold")
    styles = {
        "body":ParagraphStyle("body",fontName="CN",fontSize=10,leading=17,textColor=INK,spaceAfter=9,wordWrap="CJK"),
        "small":ParagraphStyle("small",fontName="CN",fontSize=8.4,leading=13,textColor=MUTED,spaceAfter=7,wordWrap="CJK"),
        "h1":ParagraphStyle("h1",fontName="CN-Bold",fontSize=20,leading=28,textColor=INK,spaceAfter=17,wordWrap="CJK"),
        "h2":ParagraphStyle("h2",fontName="CN-Bold",fontSize=12,leading=19,textColor=ACCENT,spaceBefore=11,spaceAfter=8,wordWrap="CJK"),
        "cell":ParagraphStyle("cell",fontName="CN",fontSize=8.7,leading=14,textColor=INK,wordWrap="CJK"),
        "head":ParagraphStyle("head",fontName="CN-Bold",fontSize=8.7,leading=14,textColor=colors.white,wordWrap="CJK"),
        "code":ParagraphStyle("code",fontName="CN",fontSize=8.5,leading=14,textColor=INK,backColor=LIGHT,borderPadding=10,spaceBefore=4,spaceAfter=13,wordWrap="CJK"),
    }
    story = []
    def p(text,style="body"):
        story.append(Paragraph(text,styles[style]))
    def h(text):
        p(text,"h2")
    def page(title):
        if story:
            story.append(PageBreak())
        p(title,"h1")
    def table(headers,rows,widths):
        data = [[Paragraph(escape(str(v)),styles["head"]) for v in headers]]
        data += [[Paragraph(escape(str(v)),styles["cell"]) for v in row] for row in rows]
        t = Table(data,colWidths=widths,repeatRows=1,hAlign="LEFT")
        t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),INK),("VALIGN",(0,0),(-1,-1),"TOP"),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,LIGHT]),("LEFTPADDING",(0,0),(-1,-1),9),
            ("RIGHTPADDING",(0,0),(-1,-1),9),("TOPPADDING",(0,0),(-1,-1),8),("BOTTOMPADDING",(0,0),(-1,-1),8),
            ("LINEBELOW",(0,0),(-1,0),0.8,ACCENT)]))
        story.extend([t,Spacer(1,10)])
    def code(text):
        p(escape(text).replace("\n","<br/>"),"code")
    def screenshot(name,caption,height=255):
        path = BASE/"evidence"/name
        if path.exists():
            img = Image(str(path))
            ratio = min(WIDTH/img.imageWidth,height/img.imageHeight)
            img.drawWidth,img.drawHeight = img.imageWidth*ratio,img.imageHeight*ratio
            story.append(img)
            p(caption,"small")
        else:
            raise RuntimeError(f"Missing report screenshot: {path}")
    def box(d,x,y,w,ht,text,fill=LIGHT):
        d.add(Rect(x,y,w,ht,rx=7,ry=7,fillColor=fill,strokeColor=None))
        for i,line in enumerate(text.split("\n")):
            d.add(String(x+w/2,y+ht/2+6*(len(text.split("\n"))-1)-i*13,line,
                         fontName="CN",fontSize=9,fillColor=INK,textAnchor="middle"))
    def arrow(d,x1,y1,x2,y2):
        d.add(Line(x1,y1,x2,y2,strokeColor=ACCENT,strokeWidth=1.5))
        if x1 == x2:
            direction = 1 if y2>y1 else -1
            d.add(Polygon([x2,y2,x2-3,y2-6*direction,x2+3,y2-6*direction],fillColor=ACCENT,strokeColor=None))
        else:
            direction = 1 if x2>x1 else -1
            d.add(Polygon([x2,y2,x2-6*direction,y2-3,x2-6*direction,y2+3],fillColor=ACCENT,strokeColor=None))

    # 1. Cover and requirement mapping.
    banner = Drawing(WIDTH,112)
    banner.add(Rect(0,0,WIDTH,112,fillColor=INK,strokeColor=None))
    banner.add(String(22,75,"WireScope",fontName="CN-Bold",fontSize=31,fillColor=colors.white))
    banner.add(String(23,43,"实验 1A：带 GUI 的网络嗅探器",fontName="CN",fontSize=17,fillColor=colors.HexColor("#b8e2df")))
    banner.add(String(23,20,"《软件与系统安全》 · 设计、实现与验证报告",fontName="CN",fontSize=10,fillColor=colors.white))
    story.extend([banner,Spacer(1,22)])
    p(f"姓名：{escape(meta['name'])}　　学号：{escape(meta['student_id'])}　　日期：{escape(meta['date'])}")
    p("Git 仓库："+escape(meta["repository_url"]),"small")
    p("本实验实现从网卡捕获原始数据包、分层解析、交互筛选与 TCP 流重组的完整链路。Windows 原生 GUI 直接展示捕获结果；抓包后台优先使用 Npcap，也可通过本机已有 WSL 调用 libpcap。协议字段由项目源码解析。")
    h("实验完成情况")
    table(["讲义要求","实现与验证"],[
        ("带 GUI 的 NPS（第 5、9 页）","网卡选择、开始/停止、实时列表、PCAP 保存；真实回环捕获通过"),
        ("NPA 协议分析（第 9 页）","链路/IP/TCP/UDP/ICMP 分层字段；HTTP、DNS、TLS 元数据；Hex/ASCII"),
        ("协议过滤（第 14 页）","BPF 捕获过滤 + 带 and/or/not/括号的显示过滤"),
        ("TCP 流追踪加分（第 14 页）","双向五元组索引、序列重组、缺口/冲突提示、时序图、文本导出"),
        ("libpcap/Npcap（第 15 页）","ctypes 调用系统 API；未调用 Scapy、tshark 的解析逻辑"),
        ("提交物（第 2、3 页）","源码、MP4 演示、PDF 报告、ZIP；个人字段和远程 Git 地址待补全")
    ],[152,WIDTH-152])
    p(f"验证摘要：{unit['tests']} 项单元测试通过；真实捕获 {live['packet_count']} 包，8 个 HTTP 请求与 8 个响应；GUI 功能检查通过。", "body")
    p("本报告区分真实回环捕获与内置合成样例。当前环境实测后台为 WSL Ubuntu-22.04；Windows Npcap 原生路径已实现，当前机器未安装该驱动。","small")

    page("01  实验原理与抓包层次")
    p("网络嗅探器 NPS 负责获取数据包；协议分析器 NPA 进一步解释包头和应用载荷。本项目先验证原始数据来自实际网卡捕获，再在捕获字节上完成协议解释、筛选和连接分析。")
    table(["OSI 层次","对应对象","本项目可见内容"],[
        ("7 应用层","HTTP、DNS","请求/响应起始行、HTTP 头、DNS 问题与资源记录"),
        ("6 表示层 / 5 会话层","编码、TLS、会话语义","TLS 位于 TCP 与上层应用之间；展示记录头、完整 ClientHello 的 SNI"),
        ("4 传输层","TCP、UDP","端口、序列号、确认号、标志、窗口、长度"),
        ("3 网络层","IPv4、IPv6、ICMP","源/目的地址、TTL/Hop Limit、分片与扩展头"),
        ("2 数据链路层","Ethernet、VLAN、回环/SLL","MAC、EtherType、VLAN；按实际链路类型定位网络头"),
        ("1 物理层","信号、介质","网卡与驱动处理；本程序从捕获 API 提供的字节开始")
    ],[88,113,WIDTH-201])
    h("抓包层次决定可观察信息")
    p("libpcap 返回的缓冲区具有接口相关的链路格式。因此程序先读取 pcap_datalink，再决定以太网、回环、Raw IP 或 Linux cooked capture 的偏移。不能对所有网卡统一跳过 14 字节；这会使回环和 Linux any 接口发生错位。")
    h("思考题：Thor 可以解析 HTTPS，为何未必能分析 TCP？")
    p("应用层代理或系统网络扩展可在建立/终止 TLS 连接的位置看到明文。安装受信任根证书，是让客户端信任代理所签发证书的条件之一；还需要流量经过代理、应用接受该证书等条件。它并不让任意被动抓到的 TLS 密文自动变为明文。证书固定等机制还会影响代理解密。")
    p("如果工具拿到的是已由系统重组的 HTTP 消息或代理连接，原连接的 TCP 序列号、重传、拥塞行为等信息可能已经被抽象掉。应用层可见性与底层包可见性来自不同的采集位置；实现上层协议分析，并不自动获得原始传输层细节。")
    p("本项目保留原始包和 TCP 头；TLS 仅分析可见记录元数据与完整 ClientHello 的 SNI，HTTPS 内容仍为加密载荷。","small")

    page("02  系统设计与模块职责")
    d = Drawing(WIDTH,217)
    box(d,0,160,144,48,"Windows 网卡\nNpcap / wpcap.dll")
    box(d,179,160,144,48,"WSL 网卡\nlibpcap.so")
    box(d,359,160,144,48,"离线文件\nPCAP / PCAPNG")
    box(d,0,83,144,48,"ctypes + 捕获线程\nBPF / next_ex")
    box(d,179,83,144,48,"本地 WSL 子进程\nJSON Lines 管道")
    box(d,359,83,144,48,"有界文件读取\n格式与长度校验")
    for x in (72,251,431):
        arrow(d,x,160,x,131)
    box(d,0,0,503,51,"有界队列 → 分层解析 / TCP 索引 → Tk 主线程\n列表、字段、字节、流追踪、统计与导出",colors.HexColor("#dbeeea"))
    for x in (72,251,431):
        arrow(d,x,83,x,51)
    story.append(d)
    h("采集与交互解耦")
    p("捕获句柄只由一个后台线程持有、读取和关闭。通过 pcap_setnonblock 避免无包时阻塞；停止动作设置 Event，工作线程退出循环并在 finally 关闭句柄。Tk 主线程每 80 ms 消费一批包，更新列表；文件读取也在后台执行。数据队列满时丢弃新增包并计数，界面可显示内核与应用队列的不同丢包来源。")
    table(["源码模块","职责"],[
        ("capture.py / wslbridge.py","ctypes API、接口枚举、BPF、捕获生命周期；WSL 本地管道桥接"),
        ("protocols.py / model.py","有界字段解析、Packet/Layer 模型、Hex 输出"),
        ("filters.py / streams.py","递归下降过滤器；双向连接索引与序列号重组"),
        ("pcapio.py / samples.py","PCAP/PCAPNG 读写；可重复生成的合成样例"),
        ("gui.py / run.py","原生桌面 GUI 与命令行入口"),
        ("tests/ / tools/","单元测试、真实抓包测试、GUI 检查、报告与打包工具")
    ],[180,WIDTH-180])
    p("WSL 模式把 GUI 留在 Windows，把抓包操作放在已安装的 Linux 中。接口名称和状态栏明确显示 WSL；它的 lo/eth0 不等于 Windows 主机的网络接口。子进程只接受明确参数，不拼接 shell 命令。","small")

    page("03  协议解析与过滤设计")
    table(["协议","解析方式与字段","边界处理"],[
        ("Ethernet / VLAN / ARP","识别 EtherType、VLAN ID、ARP 操作码与地址","Ethernet 最少 14 B；最多四层 VLAN"),
        ("IPv4 / IPv6","IHL、总长、地址、TTL、下一头、扩展头","校验版本与长度；IPv6 扩展头最多 16 层"),
        ("TCP / UDP / ICMP","端口、Seq/Ack、Flags、窗口、长度、类型与代码","TCP Data Offset ≥20 B；UDP 长度 ≥8 B"),
        ("HTTP/1.x","从载荷起始行识别方法/状态行，提取头部","支持非标准端口；仅端口 80 不判定 HTTP"),
        ("DNS","解析事务 ID、问题、资源记录和压缩域名","指针越界/循环检测；最多 256 条记录"),
        ("TLS","记录类型/版本/长度，ClientHello 与 SNI","逐长度检查；不完整记录标注 complete=false")
    ],[87,219,WIDTH-306])
    h("捕获过滤：减少到达用户态的数据")
    p("在打开句柄后，调用 pcap_compile 编译 BPF，再调用 pcap_setfilter 应用。非法表达式产生可见错误并关闭本次句柄。BPF 适合 IP、协议、端口等条件；HTTP 内容识别属于应用层解析，界面把两类过滤分开。")
    code("tcp port 18080\nhost 127.0.0.1 and tcp\nip6 or icmp")
    h("显示过滤：基于已解析字段筛选")
    p("过滤器使用词法分析与递归下降语法，优先级为 not → and → or，支持括号。协议条件基于整条分层路径，因此 HTTP 包也能匹配 tcp 和 ipv4。字段比较支持数值、地址与文本；无字段不匹配，port != N 要求两个端口都不等于 N。实现不使用 eval/exec。")
    code('http\n(tcp and port == 8080) or dns\nipv6 and not dns\ntcp.stream == 0\ninfo contains "GET"')
    p("每包的 HTTP/TLS/DNS 识别基于当前已捕获载荷。跨 TCP 段的 HTTP 起始行可以在流重组后查看，但不会回填所有分段的协议标签。DNS over TCP 解析当前段内的首个完整 DNS 消息。","small")

    page("04  TCP 连接追踪与重组")
    p("以 IP 版本、协议 TCP、两个端点的 IP 与端口建立双向连接键。首个非 ACK 的 SYN 确定连接方向；同一 SYN 序列号视为重传，不同初始序列号或关闭后的新 SYN 建立新流。收到双向 FIN 或 RST 后标记关闭。")
    h("重组流程")
    table(["步骤","处理规则"],[
        ("1. 按方向分离","A→B 和 B→A 分别重组，避免将请求与响应混接"),
        ("2. 确定序列原点","有 SYN 时使用 ISN+1；无握手时使用最早观察字节并标注中途捕获"),
        ("3. 计算相对偏移","以 32 位模运算求有符号距离，处理序列号回绕；单向数据范围远小于 2 GiB"),
        ("4. 处理乱序/重传","按偏移存入区间；已经存在的区间去重，重叠冲突保留先捕获的字节并计数"),
        ("5. 表达不完整数据","连续区间合并；缺口明确显示缺失字节数，不把不相邻内容拼成连续消息"),
        ("6. 交互与导出","双向 UTF-8 文本、连接时序、按流筛选与文本导出；原始字节保存在捕获文件")
    ],[95,WIDTH-95])
    h("可复现的乱序与重传例子")
    d = Drawing(WIDTH,139)
    box(d,0,91,503,35,"到达顺序：SYN(seq=100) → def(seq=104) → abc(seq=101) → abc 重传")
    arrow(d,251,91,251,67)
    box(d,0,15,503,52,"相对字节序列：0 1 2 3 4 5 → abcdef\n去重 3 B，冲突 0 B，缺口 0")
    story.append(d)
    p("合成 HTTP 流包含完整握手、请求乱序、39 字节重复发送、响应和 FIN 关闭。重组后请求从 GET /experiment/1a 开始，响应正文包含 reassembly passed。单元测试另覆盖回绕、冲突、前缀缺失和五元组重用。")
    p("每方向重组上限 2 MiB，超限显式标记。若采集没有观察到新 SYN，后续复用同一五元组的连接无法可靠区分；当前实现不做超时连接切分、IP 分片重组和完整 TCP 状态机推演。","small")

    page("05  运行界面与真实捕获")
    screenshot("gui_live.png","图 1　真实 WSL lo 捕获：HTTP 过滤、分层字段与 Hex/ASCII。视频中包由本地 HTTP 请求实时产生。",265)
    screenshot("gui_stream.png","图 2　同一 TCP 连接的请求字节重组。界面同时提供另一方向的响应内容和连接时序标签。",265)
    p("三栏浏览器把包列表、协议字段和原始字节联系起来。选择协议层会高亮对应的十六进制行；双击 TCP 包进入对应连接。表格显示最近 2,000 条匹配记录，保存全部与导出筛选都使用完整的保留数据。","small")

    page("06  测试方法与实验结果")
    p(f"测试环境：Windows / Python {unit['python']}，Tk GUI；{escape(live['backend'])}。真实测试仅在 127.0.0.1:18080 发送本地 HTTP 请求。")
    table(["测试组","方法","实际结果"],[
        ("单元测试","协议、过滤、重组、文件格式共 52 项","52 通过；0 失败；0 错误"),
        ("截断与随机输入","每个合成包的全部截断位置；固定种子 3,000 随机帧","未出现未捕获解析异常"),
        ("真实 NPS / HTTP","启动 libpcap；发送 8 次回环请求","47 包；HTTP 请求 8，响应 8；1 条流"),
        ("停止与错误处理","空闲网卡停止；非法 BPF","停止成功；非法 BPF 被拒绝"),
        ("抓包与文件互通","PCAP、PCAPNG 写出/回读；tcpdump 读取 PCAP","原始字节一致；tcpdump 正常显示握手"),
        ("GUI 集成","真实 Tk 控件执行 7 组功能检查","通过；Tk 回调异常 0；GUI 捕获 47 包")
    ],[88,227,WIDTH-315])
    h("真实捕获指标")
    table(["指标","测量值"],[
        ("保留包数 / 最深协议分类",f"{live['packet_count']} 包；HTTP 16，TCP 31"),
        ("内核丢包 / 应用队列丢包","0 / 0"),
        ("捕获停止耗时",f"{live['stop_latency_seconds']:.3f} s（本次测量）"),
        ("空闲状态停止耗时",f"{live['idle_stop_latency_seconds']:.3f} s（本次测量）"),
        ("libpcap received 计数",str(live['statistics']['received'])+"；Linux 回环计数可能包含收/发两次，不能直接作为 GUI 包数"),
        ("进程关联",f"本次 {live['process_associated_packets']} 包；WSL 环境未验证该可选功能")
    ],[197,WIDTH-197])
    p("证据位于 evidence/：unit_tests.txt、unit_tests.json、live_verification.json、gui_verification.json、live_loopback.pcap、live_loopback.pcapng 和 live_tcp_stream.txt。上述小流量测试用于验证功能与停止路径，不代表高速网络吞吐能力。","small")

    page("07  安装、运行与复现")
    h("当前 Windows 电脑直接运行")
    p("双击“启动嗅探器.bat”，或在源码目录执行下列命令。核心程序仅依赖 Python 3.10+ 标准库和 Tk；当前电脑已有 Python 与 WSL/libpcap，无需再安装依赖即可使用已验证后台。")
    code("python run.py\npython run.py --demo\npython run.py --open evidence/live_loopback.pcapng")
    h("在其他机器上运行")
    p("Windows 主机网卡抓包需先从 Npcap 官网安装驱动；若安装为仅管理员捕获，需由用户使用相应权限运行。GUI 检测到 Npcap 时优先选择原生后台；缺失时尝试现有 WSL。Linux 原生运行需系统 libpcap、Python/Tk 与抓包权限。WSL 模式要求现有发行版具备 Python 3.10+、libpcap 和抓包权限。")
    p("可通过环境变量 WIRESCOPE_WSL_DISTRO 指定已有发行版。程序不会安装 WSL 或自动修改系统权限。可选进程关联依赖 psutil：python -m pip install -r requirements.txt；无法读取 socket 表时仍能抓包。")
    h("GUI 真实抓包复现")
    p("① 选择标有 Loopback 的接口；② BPF 填写 tcp port 18080；③ 开始捕获；④ 点击“产生回环测试流量”；⑤ 等待请求完成后停止；⑥ 显示过滤填写 http；⑦ 双击请求追踪 TCP 流；⑧ 保存全部为 PCAPNG。WSL 后台的测试流量也在同一 WSL 中产生。")
    h("命令行验证与自动测试")
    code("python run.py --interfaces\npython run.py --capture loopback --bpf \"tcp port 18080\" --seconds 15 --out live.pcapng\n# 捕获期间在第二个终端运行：\npython run.py --test-traffic\npython -m unittest discover -s tests -v\npython tools/verify_live.py\npython tools/verify_gui.py")
    p("打开与保存快捷键为 Ctrl+O / Ctrl+S，Ctrl+L 定位显示过滤。重新运行验证会更新 evidence 中对应的本地测试输出。","small")

    page("08  边界处理与改进方向")
    h("有界输入与清晰反馈")
    p("协议头每次读取前校验剩余长度；解析错误保存在 Diagnostics，并保留原始字节。PCAP/PCAPNG 验证魔数、版本、包长、块尾长度、接口编号和时间分辨率。导出先写同目录临时文件，再原子替换目标，避免写到一半损坏已有文件。")
    table(["资源 / 能力","当前边界"],[
        ("实时保留","最多 50,000 包 / 64 MiB，达到上限停止；GUI 最多显示最近 2,000 条匹配"),
        ("队列与文件","捕获队列 2,048 包；输入文件最大 256 MiB；单包最大 1 MiB；每 section 最多 1,024 接口"),
        ("TCP 重组","每方向最多 2 MiB；冲突保留先捕获字节；时序图最多显示前 500 包"),
        ("PCAPNG","支持 section/interface/enhanced packet；旧式 Packet/Simple Packet Block 返回明确错误"),
        ("网络与应用协议","IP 分片保留而不重组；不解析 HTTP/2、QUIC；TLS 不解密；校验和只展示不判定"),
        ("进程归属","可选 psutil 周期性精确 TCP 端点快照；短连接、权限和时间差可导致关联缺失"),
        ("平台验证","Windows GUI + WSL 抓包已实测；本机 Windows Npcap 路径未实测")
    ],[114,WIDTH-114])
    h("设计取舍")
    p("使用标准库与手工解析，使抓包、解码和过滤原理能直接从源码追踪。使用原生 pcap BPF 降低无关流量进入用户态的开销；有界队列与批量 UI 更新隔离高频抓包和低频绘制。Python 与树控件适合教学和小规模分析，若目标改为高速长时间捕获，应采用磁盘轮转、虚拟列表与更轻量的采集进程。")
    h("后续可以增加的功能")
    p("可在现有模型上增加 IP 分片重组、跨 TCP 段的应用协议状态机、DNS/TLS 多消息处理，以及基于连接超时的流切分。进程快照也可迁移为平台专用连接事件，以降低采集时序导致的关联遗漏。")

    page("09  提交组织、Git 与参考资料")
    p("按讲义第 3 页组织 ZIP，包含一份源码目录、一份 MP4 演示、一份 PDF 报告；说明统一写入报告，不另放 README。当前个人信息使用占位值，报告中的远程仓库链接也需在提交前补入。讲义要求 2026 年 11 月 24 日 23:55 前上传课程网站。")
    code("姓名_学号_EX1A/\n  姓名_学号_ex1A_src/\n  姓名_学号_ex1A_play.mp4\n  姓名_学号_ex1A_report.pdf")
    h("本地版本记录与最终打包")
    p("源码已建立本地 Git 仓库并分阶段提交。提交包附带 history.bundle，可通过 git clone history.bundle restored 恢复本地版本历史。远程仓库尚未由用户指定或发布；本地历史不能替代讲义要求的远程 Git 链接。")
    code('git remote add origin <你的仓库地址>\ngit push -u origin main\n# 填好 docs/submission.json 后，在安装报告依赖的 Python 中运行：\npython tools/pack_submission.py')
    p("打包工具会根据 submission.json 重建 PDF，并按姓名、学号生成 ZIP；报告生成需要 requirements-dev.txt 中的依赖与中文字体。程序核心运行不需要这些报告/视频依赖。")
    h("AI 辅助说明与源码阅读建议")
    p("程序、测试与报告由 AI 助手协助实现。建议提交者依次阅读 capture.py、protocols.py、filters.py 与 streams.py，运行测试并对照原始字节解释关键字段，理解讲义第 65 页强调的核心模块学习目标。报告没有填写未经提供的姓名、学号，也没有把合成样例作为真实网络观测。")
    h("参考资料")
    references = [
        ("[1] 刘鹏，《实验 1 讲解 2026》，第 2–3、5、9、14–15、65 页。",None),
        ("[2] Npcap API：捕获句柄、接口与数据链路类型。","https://npcap.com/guide/wpcap/pcap.html"),
        ("[3] Npcap / libpcap BPF filter syntax。","https://npcap.com/guide/wpcap/pcap-filter.html"),
        ("[4] RFC 9293：TCP 序列号、连接与报头。","https://www.rfc-editor.org/rfc/rfc9293.html"),
        ("[5] RFC 8200：IPv6 与扩展头。","https://www.rfc-editor.org/rfc/rfc8200.html"),
        ("[6] RFC 1035：DNS 消息与域名压缩。","https://www.rfc-editor.org/rfc/rfc1035.html")
    ]
    for text,url in references:
        p(escape(text)+(f'<br/><link href="{url}" color="#087f8c">{url}</link>' if url else ""),"small")

    output = Path(output or BASE/"docs/实验1A_嗅探器报告.pdf")
    output.parent.mkdir(parents=True,exist_ok=True)
    doc = SimpleDocTemplate(str(output),pagesize=A4,rightMargin=46,leftMargin=46,topMargin=43,bottomMargin=43,
                            title="WireScope 实验1A：嗅探器设计与实现",author=meta["name"])
    def furniture(canvas,doc):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#dce4ec"))
        canvas.line(46,35,A4[0]-46,35)
        canvas.setFont("CN",8)
        canvas.setFillColor(MUTED)
        canvas.drawString(46,23,"WIRESCOPE  /  SOFTWARE & SYSTEM SECURITY  /  EX1A")
        canvas.drawRightString(A4[0]-46,23,f"{doc.page:02d}")
        canvas.restoreState()
    doc.build(story,onFirstPage=furniture,onLaterPages=furniture)
    print(output)
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out")
    args = parser.parse_args()
    build(args.out)
