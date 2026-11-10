"""Native three-pane desktop UI; capture and file I/O never run in Tk's thread."""
from collections import Counter, deque
from pathlib import Path
import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import webbrowser

from .capture import CaptureError, CaptureSession, Pcap
from .filters import FilterError, compile_filter
from .model import endpoint
from .pcapio import MAX_CAPTURE_BYTES, MAX_PACKETS, read_capture, write_capture
from .protocols import hexdump, parse_http, parse_tls
from .samples import make_demo_packets
from .streams import FlowIndex
from .wslbridge import WslPcap, default_backend, make_session

BASE = Path(__file__).resolve().parent.parent
BG, WHITE, INK, MUTED, ACCENT, LINE = "#eef2f6", "#ffffff", "#142b45", "#60748a", "#087f8c", "#dce4ec"
COLORS = {"TCP":"#eaf2ff","UDP":"#edf8f3","HTTP":"#ddf5ee","DNS":"#f1ebff", "TLS":"#fff1db",
          "ICMP":"#fff2e9","ICMPv6":"#fff2e9","ARP":"#fceaf2","IPv6":"#edf3ff","IPv4":"#edf3ff"}
VISIBLE_LIMIT = 2000


class SnifferApp:
    def __init__(self, root):
        self.root = root
        root.title("WireScope — 实验 1A 网络嗅探器")
        root.geometry(f"{min(1480,root.winfo_screenwidth()-80)}x{min(850,root.winfo_screenheight()-110)}")
        root.minsize(1100,700)
        root.configure(bg=BG)
        self.packets, self.by_number, self.flow_index = [], {}, FlowIndex()
        self.protocol_counts, self.total_bytes = Counter(), 0
        self.predicate, self.visible_ids, self.matching = compile_filter(""), deque(), 0
        self.session, self.pcap, self.interfaces, self.current_flow = None,None,[],None
        self.io_results, self.loading = queue.SimpleQueue(),False
        self.pending_close = False
        self.limit_reached = False
        self.last_chart = 0
        self.source = "尚未开始"
        self.last_stats = {}
        self._theme()
        self._build()
        self.refresh_interfaces()
        root.protocol("WM_DELETE_WINDOW",self.close)
        root.bind("<Control-o>",lambda _:self.open_file())
        root.bind("<Control-s>",lambda _:self.save_file())
        root.bind("<Control-l>",lambda _:self.filter_entry.focus_set())
        root.after(80,self._pump)

    def _theme(self):
        self.root.option_add("*Font",("Microsoft YaHei UI",10))
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame",background=BG)
        style.configure("White.TFrame",background=WHITE)
        style.configure("TLabel",background=BG,foreground=INK)
        style.configure("TButton",font=("Microsoft YaHei UI",10),padding=(12,7),background=WHITE,foreground=INK,borderwidth=1)
        style.map("TButton",background=[("active","#e1edf3")],foreground=[("disabled","#99a8b6")])
        style.configure("Accent.TButton",background=ACCENT,foreground=WHITE,borderwidth=0)
        style.map("Accent.TButton",background=[("active","#066774"),("disabled","#a7bdc2")])
        style.configure("TEntry",padding=7,fieldbackground=WHITE)
        style.configure("TCombobox",padding=6,fieldbackground=WHITE)
        style.configure("Treeview",font=("Consolas",10),rowheight=29,background=WHITE,fieldbackground=WHITE,foreground=INK,borderwidth=0)
        style.configure("Treeview.Heading",font=("Microsoft YaHei UI",10,"bold"),padding=(8,8),background="#e9eff5",foreground=INK)
        style.map("Treeview",background=[("selected","#135d79")],foreground=[("selected",WHITE)])
        style.configure("TNotebook",background=BG,borderwidth=0)
        style.configure("TNotebook.Tab",padding=(18,9),background="#dfe8ef",foreground=INK)
        style.map("TNotebook.Tab",background=[("selected",WHITE)])
        style.configure("TPanedwindow",background=LINE)
        style.configure("TCheckbutton",background=BG,foreground=INK)

    def _build(self):
        mast = tk.Frame(self.root,bg=INK,height=85)
        mast.pack(fill="x")
        mast.pack_propagate(False)
        title = tk.Frame(mast,bg=INK)
        title.pack(side="left",padx=24,pady=13)
        tk.Label(title,text="WireScope",font=("Segoe UI",23,"bold"),bg=INK,fg=WHITE).pack(anchor="w")
        tk.Label(title,text="网络嗅探与协议分析  /  SOFTWARE & SYSTEM SECURITY",font=("Microsoft YaHei UI",9),bg=INK,fg="#a7c5d9").pack(anchor="w")
        self.mode = tk.Label(mast,text="READY  ·  实验 1A",font=("Microsoft YaHei UI",11,"bold"),bg="#26435f",fg="#bcebe6",padx=17,pady=9)
        self.mode.pack(side="right",padx=24)
        controls = ttk.Frame(self.root,padding=(18,12,18,4))
        controls.pack(fill="x")
        ttk.Label(controls,text="网卡").pack(side="left",padx=(0,10))
        self.interface_var = tk.StringVar()
        self.interface_box = ttk.Combobox(controls,textvariable=self.interface_var,state="readonly",width=57)
        self.interface_box.pack(side="left",fill="x",expand=True)
        self.refresh_button = ttk.Button(controls,text="刷新网卡",command=self.refresh_interfaces)
        self.refresh_button.pack(side="left",padx=8)
        self.start_button = ttk.Button(controls,text="▶  开始捕获",style="Accent.TButton",command=self.start_capture)
        self.start_button.pack(side="left",padx=(0,8))
        self.stop_button = ttk.Button(controls,text="■  停止",command=self.stop_capture,state="disabled")
        self.stop_button.pack(side="left")
        self.open_button = ttk.Button(controls,text="打开文件",command=self.open_file)
        self.open_button.pack(side="left",padx=8)
        ttk.Button(controls,text="保存全部",command=self.save_file).pack(side="left")
        bpfrow = ttk.Frame(self.root,padding=(18,4,18,10))
        bpfrow.pack(fill="x")
        ttk.Label(bpfrow,text="捕获 BPF").pack(side="left",padx=(0,10))
        self.bpf_var = tk.StringVar(value="")
        self.bpf_entry = ttk.Entry(bpfrow,textvariable=self.bpf_var,width=55)
        self.bpf_entry.pack(side="left",fill="x",expand=True)
        ttk.Label(bpfrow,text="例：tcp port 18080  ·  仅在开始捕获时生效",foreground=MUTED).pack(side="left",padx=14)
        self.promisc = tk.BooleanVar(value=False)
        self.promisc_check = ttk.Checkbutton(bpfrow,text="混杂模式",variable=self.promisc)
        self.promisc_check.pack(side="left")
        main = ttk.Frame(self.root,padding=(18,0,18,10))
        main.pack(fill="both",expand=True)
        sidebar = tk.Frame(main,bg=WHITE,width=184,highlightbackground=LINE,highlightthickness=1)
        sidebar.pack(side="left",fill="y",padx=(0,12))
        sidebar.pack_propagate(False)
        actions = tk.Frame(sidebar,bg=WHITE)
        actions.pack(side="bottom",fill="x",pady=(5,10))
        tk.Label(sidebar,text="协议导航",font=("Microsoft YaHei UI",12,"bold"),bg=WHITE,fg=INK).pack(anchor="w",padx=16,pady=(17,8))
        self.nav_buttons = {}
        for label,expr in [("全部数据包",""),("HTTP","http"),("TCP","tcp"),("UDP","udp"),("IPv4","ipv4"),("IPv6","ipv6"),("ICMP / ICMPv6","icmp or icmpv6"),("DNS","dns"),("TLS","tls"),("ARP","arp")]:
            button = tk.Button(sidebar,text=label,command=lambda e=expr:self.set_filter(e),anchor="w",bg=WHITE,fg=INK,
                               activebackground="#e5f3f2",activeforeground=ACCENT,relief="flat",padx=16,pady=1,
                               font=("Microsoft YaHei UI",9),cursor="hand2")
            button.pack(fill="x",padx=7,pady=0)
            self.nav_buttons[expr] = button
        tk.Frame(sidebar,bg=LINE,height=1).pack(fill="x",padx=16,pady=13)
        self.total_label = tk.Label(sidebar,text="0",font=("Segoe UI",23,"bold"),bg=WHITE,fg=INK)
        self.total_label.pack(anchor="w",padx=16)
        tk.Label(sidebar,text="已保留数据包",bg=WHITE,fg=MUTED,font=("Microsoft YaHei UI",9)).pack(anchor="w",padx=16)
        self.volume_label = tk.Label(sidebar,text="0 B  ·  0 TCP 流",bg=WHITE,fg=MUTED,font=("Microsoft YaHei UI",9))
        self.volume_label.pack(anchor="w",padx=16,pady=(7,12))
        ttk.Button(actions,text="加载内置样例",command=self.load_demo).pack(fill="x",padx=12,pady=(0,7))
        ttk.Button(actions,text="产生回环测试流量",command=self.generate_traffic).pack(fill="x",padx=12,pady=(0,7))
        ttk.Button(actions,text="使用帮助",command=self.show_help).pack(fill="x",padx=12)
        self.body = ttk.Frame(main)
        self.body.pack(side="left",fill="both",expand=True)
        filters = ttk.Frame(self.body,padding=(0,0,0,8))
        filters.pack(fill="x")
        ttk.Label(filters,text="显示过滤",font=("Microsoft YaHei UI",10,"bold")).pack(side="left",padx=(0,10))
        self.filter_var = tk.StringVar()
        self.filter_entry = ttk.Entry(filters,textvariable=self.filter_var)
        self.filter_entry.pack(side="left",fill="x",expand=True)
        self.filter_entry.bind("<Return>",lambda _:self.apply_filter())
        ttk.Button(filters,text="应用",command=self.apply_filter).pack(side="left",padx=6)
        ttk.Button(filters,text="清除",command=lambda:self.set_filter("")).pack(side="left")
        ttk.Button(filters,text="导出筛选",command=lambda:self.save_file(True)).pack(side="left",padx=(6,0))
        self.filter_hint = tk.Label(self.body,text="例：tcp and port == 8080  |  ipv6 or icmp  |  info contains \"GET\"",bg=BG,fg=MUTED,anchor="w",font=("Microsoft YaHei UI",9))
        self.filter_hint.pack(fill="x",pady=(0,9))
        self.notebook = ttk.Notebook(self.body)
        self.notebook.pack(fill="both",expand=True)
        self.packet_tab,self.flow_tab,self.stats_tab = ttk.Frame(self.notebook),ttk.Frame(self.notebook),ttk.Frame(self.notebook)
        self.notebook.add(self.packet_tab,text="数据包浏览")
        self.notebook.add(self.flow_tab,text="TCP 流追踪")
        self.notebook.add(self.stats_tab,text="流量统计")
        self.notebook.bind("<<NotebookTabChanged>>",self._tab_changed)
        pane = ttk.Panedwindow(self.packet_tab,orient="vertical")
        self.packet_pane = pane
        pane.pack(fill="both",expand=True,pady=(2,0))
        packet_frame = ttk.Frame(pane)
        pane.add(packet_frame,weight=3)
        columns = ("number","time","source","destination","protocol","length","info")
        self.packet_tree = ttk.Treeview(packet_frame,columns=columns,show="headings",selectmode="browse",height=11)
        for key,label,width in zip(columns,["No.","时间 (s)","源地址","目的地址","协议","长度","摘要"],[58,95,178,178,75,65,410]):
            self.packet_tree.heading(key,text=label)
            self.packet_tree.column(key,width=width,minwidth=45,stretch=key in ("source","destination","info"))
        self._scroll_tree(packet_frame,self.packet_tree)
        for protocol,color in COLORS.items():
            self.packet_tree.tag_configure(protocol,background=color)
        self.packet_tree.tag_configure("warning",foreground="#a33127")
        self.packet_tree.bind("<<TreeviewSelect>>",self.select_packet)
        self.packet_tree.bind("<Double-1>",lambda _:self.follow_selected())
        detail_frame = ttk.Frame(pane)
        pane.add(detail_frame,weight=2)
        detail_header = ttk.Frame(detail_frame,padding=(7,6))
        detail_header.pack(fill="x")
        self.selection_label = ttk.Label(detail_header,text="选择一条数据包，查看分层字段与原始字节",foreground=MUTED)
        self.selection_label.pack(side="left")
        ttk.Button(detail_header,text="追踪此 TCP 流 →",command=self.follow_selected).pack(side="right")
        split = ttk.Panedwindow(detail_frame,orient="horizontal")
        split.pack(fill="both",expand=True)
        layers_frame,hex_frame = ttk.Frame(split),ttk.Frame(split)
        split.add(layers_frame,weight=2)
        split.add(hex_frame,weight=3)
        self.detail_tree = ttk.Treeview(layers_frame,columns=("value",),show="tree headings",height=8)
        self.detail_tree.heading("#0",text="协议 / 字段")
        self.detail_tree.heading("value",text="值")
        self.detail_tree.column("#0",width=170,minwidth=120)
        self.detail_tree.column("value",width=250,minwidth=120)
        self._scroll_tree(layers_frame,self.detail_tree)
        self.hex_text = self._text(hex_frame,font=("Consolas",10))
        self.hex_text.tag_configure("range",background="#d5ede9")
        self.layer_ranges = {}
        self.detail_tree.bind("<<TreeviewSelect>>",self.highlight_layer)
        self._build_flows()
        self.stats_canvas = tk.Canvas(self.stats_tab,bg=WHITE,highlightthickness=0)
        self.stats_canvas.pack(fill="both",expand=True)
        self.stats_canvas.bind("<Configure>",lambda _:self.draw_stats())
        footer = tk.Frame(self.root,bg=WHITE,height=31)
        footer.pack(side="bottom",fill="x",before=main)
        self.status = tk.StringVar(value="就绪")
        tk.Label(footer,textvariable=self.status,bg=WHITE,fg=MUTED,anchor="w",padx=18,pady=6,font=("Microsoft YaHei UI",9)).pack(side="left",fill="x",expand=True)
        self.drop_label = tk.Label(footer,text="驱动丢包 —  ·  队列丢包 0",bg=WHITE,fg=MUTED,padx=18,font=("Microsoft YaHei UI",9))
        self.drop_label.pack(side="right")
        self.root.after(350,lambda:self.packet_pane.sashpos(0,int(self.packet_pane.winfo_height()*0.53)))

    def _scroll_tree(self,parent,tree):
        parent.rowconfigure(0,weight=1)
        parent.columnconfigure(0,weight=1)
        tree.grid(row=0,column=0,sticky="nsew")
        y = ttk.Scrollbar(parent,orient="vertical",command=tree.yview)
        y.grid(row=0,column=1,sticky="ns")
        x = ttk.Scrollbar(parent,orient="horizontal",command=tree.xview)
        x.grid(row=1,column=0,sticky="ew")
        tree.configure(yscrollcommand=y.set,xscrollcommand=x.set)

    def _text(self,parent,font=("Consolas",11)):
        text = tk.Text(parent,bg=WHITE,fg=INK,font=font,wrap="none",relief="flat",padx=12,pady=10,state="disabled")
        scroll_y = ttk.Scrollbar(parent,orient="vertical",command=text.yview)
        scroll_x = ttk.Scrollbar(parent,orient="horizontal",command=text.xview)
        scroll_y.pack(side="right",fill="y")
        scroll_x.pack(side="bottom",fill="x")
        text.pack(fill="both",expand=True)
        text.configure(yscrollcommand=scroll_y.set,xscrollcommand=scroll_x.set)
        return text

    @staticmethod
    def _replace_text(widget,value):
        widget.configure(state="normal")
        widget.delete("1.0","end")
        widget.insert("1.0",value)
        widget.configure(state="disabled")

    def _build_flows(self):
        top = ttk.Frame(self.flow_tab,padding=(10,10))
        top.pack(fill="x")
        self.flow_choice = ttk.Combobox(top,state="readonly",width=72)
        self.flow_choice.pack(side="left",fill="x",expand=True)
        self.flow_choice.bind("<<ComboboxSelected>>",lambda _:self.show_flow(self.flow_choice.current()))
        ttk.Button(top,text="筛选此流",command=self.filter_flow).pack(side="left",padx=7)
        ttk.Button(top,text="导出流文本",command=self.export_flow).pack(side="left")
        self.flow_summary = ttk.Label(self.flow_tab,text="双击 TCP 数据包，按双向 IP + Port 追踪连接",padding=(12,4))
        self.flow_summary.pack(fill="x")
        tabs = ttk.Notebook(self.flow_tab)
        tabs.pack(fill="both",expand=True,padx=8,pady=8)
        a,b,c = ttk.Frame(tabs),ttk.Frame(tabs),ttk.Frame(tabs)
        tabs.add(a,text="A → B  重组内容")
        tabs.add(b,text="B → A  重组内容")
        tabs.add(c,text="连接时序")
        self.flow_tabs = tabs
        self.flow_texts = [self._text(a),self._text(b)]
        self.flow_texts[0].tag_configure("header",foreground=ACCENT)
        self.flow_canvas = tk.Canvas(c,bg=WHITE,highlightthickness=0)
        scrollbar = ttk.Scrollbar(c,orient="vertical",command=self.flow_canvas.yview)
        scrollbar.pack(side="right",fill="y")
        self.flow_canvas.pack(fill="both",expand=True)
        self.flow_canvas.configure(yscrollcommand=scrollbar.set)
        self.flow_canvas.bind("<Configure>",lambda _:self.draw_flow())

    def refresh_interfaces(self):
        if self.session and self.session.thread.is_alive():
            return
        try:
            if self.pcap is None:
                self.pcap = default_backend()
            self.interfaces = self.pcap.interfaces()
            labels = [i.label for i in self.interfaces]
            self.interface_box.configure(values=labels)
            if labels:
                self.interface_box.current(next((n for n,i in enumerate(self.interfaces) if i.loopback),0))
                self.start_button.configure(state="normal")
            else:
                self.start_button.configure(state="disabled")
            self.status.set(self.pcap.version if labels else "未找到可捕获网卡")
        except CaptureError as exc:
            self.interface_box.configure(values=["Npcap 未安装 · 可先加载样例 / 打开 PCAP"])
            self.interface_box.current(0)
            self.start_button.configure(state="disabled")
            self.status.set(str(exc))

    def _can_replace(self):
        if self.loading:
            return False
        if self.session and self.session.thread.is_alive():
            messagebox.showinfo("捕获正在进行","请先停止捕获，再打开文件或切换会话。",parent=self.root)
            return False
        return not self.packets or messagebox.askyesno("切换会话","将替换当前会话。需要保留时请先保存全部数据包。继续？",parent=self.root)

    def _reset(self,source):
        self.packets,self.by_number,self.flow_index = [],{},FlowIndex()
        self.protocol_counts,self.total_bytes = Counter(),0
        self.visible_ids,self.matching = deque(),0
        self.current_flow,self.last_stats = None,{}
        self.source = source
        self.limit_reached = False
        self.packet_tree.delete(*self.packet_tree.get_children())
        self.detail_tree.delete(*self.detail_tree.get_children())
        self._replace_text(self.hex_text,"")
        for text in self.flow_texts:
            self._replace_text(text,"")
        self.flow_canvas.delete("all")
        self.flow_choice.configure(values=[])
        self.flow_choice.set("")
        self.flow_summary.configure(text="双击 TCP 数据包，按双向 IP + Port 追踪连接")
        self.selection_label.configure(text="选择数据包查看详情")
        self.drop_label.configure(text="驱动丢包 —  ·  队列丢包 0")

    def load_packets(self,packets,source):
        self._reset(source)
        for p in packets:
            self._add_packet(p,render=False)
        self.apply_filter()
        self.mode.configure(text="OFFLINE  ·  离线分析",fg="#c7deee")
        self._update_summary()
        if self.visible_ids:
            self.packet_tree.selection_set(self.visible_ids[0])
        self.draw_stats()

    def load_demo(self):
        if self._can_replace():
            self.load_packets(make_demo_packets(),"内置合成样例 · 非实抓流量")

    def open_file(self):
        if not self._can_replace():
            return
        filename = filedialog.askopenfilename(parent=self.root,title="打开捕获文件",filetypes=[("Packet captures","*.pcap *.pcapng *.cap"),("All files","*.*")])
        if filename:
            self.load_path(filename)

    def load_path(self,path):
        self.loading = True
        self.status.set("正在读取并解析文件…")
        self._set_running(True)
        self.stop_button.configure(state="disabled")
        def load():
            try:
                self.io_results.put(("loaded",(read_capture(path),Path(path).name)))
            except Exception as exc:
                self.io_results.put(("error",str(exc)))
        threading.Thread(target=load,name="capture-file-reader",daemon=True).start()

    def save_file(self,filtered=False):
        packets = [p for p in self.packets if self.predicate(p)] if filtered else list(self.packets)
        if not packets:
            messagebox.showinfo("保存捕获","当前没有可保存的数据包。",parent=self.root)
            return
        path = filedialog.asksaveasfilename(parent=self.root,title="导出筛选结果" if filtered else "保存全部数据包",defaultextension=".pcapng",
            filetypes=[("PCAPNG","*.pcapng"),("PCAP","*.pcap")])
        if path:
            try:
                write_capture(path,packets)
                self.status.set(f"已保存 {len(packets)} 包：{path}")
            except Exception as exc:
                messagebox.showerror("保存失败",str(exc),parent=self.root)

    def _set_running(self,running):
        for widget in (self.refresh_button,self.open_button,self.bpf_entry,self.promisc_check):
            widget.configure(state="disabled" if running else "normal")
        self.interface_box.configure(state="disabled" if running else "readonly")
        self.start_button.configure(state="disabled" if running or not self.interfaces else "normal")
        self.stop_button.configure(state="normal" if running else "disabled")

    def start_capture(self):
        if not self.pcap or not self.interfaces or not self._can_replace():
            return
        index = self.interface_box.current()
        if not 0 <= index < len(self.interfaces):
            return
        interface = self.interfaces[index]
        self._reset("实时捕获 · "+interface.description)
        self.session = make_session(self.pcap,interface,self.bpf_var.get(),self.promisc.get())
        self._set_running(True)
        self.mode.configure(text="STARTING  ·  打开网卡",fg="#bcebe6")
        self.session.start()

    def stop_capture(self):
        if self.session:
            self.session.stop()
            self.stop_button.configure(state="disabled")
            self.mode.configure(text="STOPPING  ·  停止中")

    def _add_packet(self,p,render=True):
        if len(self.packets) >= MAX_PACKETS or self.total_bytes+len(p.raw) > MAX_CAPTURE_BYTES:
            self.limit_reached = True
            self.stop_capture()
            self.status.set("达到保留上限：50,000 包 / 64 MiB。请保存后开始新会话。")
            return False
        p.number = len(self.packets)+1
        if p.layers:
            p.layers[0].fields["Number"] = p.number
        self.packets.append(p)
        self.by_number[str(p.number)] = p
        self.flow_index.add(p)
        self.total_bytes += len(p.raw)
        self.protocol_counts[p.protocol] += 1
        if render and self.predicate(p):
            self.matching += 1
            self._insert_row(p)
        return True

    def _insert_row(self,p):
        number = str(p.number)
        base = self.packets[0].timestamp if self.packets else p.timestamp
        tags = (p.protocol,"warning") if p.warnings else (p.protocol,)
        self.packet_tree.insert("","end",iid=number,values=(p.number,f"{p.timestamp-base:.6f}",p.source,p.destination,p.protocol,p.wire_length,p.info),tags=tags)
        self.visible_ids.append(number)
        if len(self.visible_ids) > VISIBLE_LIMIT:
            self.packet_tree.delete(self.visible_ids.popleft())

    def set_filter(self,expression):
        self.filter_var.set(expression)
        self.apply_filter()
        self.notebook.select(self.packet_tab)

    def apply_filter(self):
        try:
            predicate = compile_filter(self.filter_var.get())
        except (FilterError,RecursionError) as exc:
            self.filter_hint.configure(text="过滤错误："+str(exc)+"；仍显示上次有效结果",fg="#b2372c")
            return False
        self.predicate = predicate
        selected = self.packet_tree.selection()
        self.packet_tree.delete(*self.packet_tree.get_children())
        matches = [p for p in self.packets if self.predicate(p)]
        self.visible_ids,self.matching = deque(),len(matches)
        for p in matches[-VISIBLE_LIMIT:]:
            self._insert_row(p)
        for expr,button in self.nav_buttons.items():
            button.configure(bg="#e1f3f0" if expr == self.filter_var.get() else WHITE,fg=ACCENT if expr == self.filter_var.get() else INK)
        self.filter_hint.configure(text=f"显示过滤有效  ·  匹配 {self.matching:,} / {len(self.packets):,} 包  ·  表格最多显示最近 {VISIBLE_LIMIT:,} 条匹配记录",fg=ACCENT)
        if selected and self.packet_tree.exists(selected[0]):
            self.packet_tree.selection_set(selected[0])
        elif self.visible_ids:
            self.packet_tree.selection_set(self.visible_ids[0])
        else:
            self.detail_tree.delete(*self.detail_tree.get_children())
            self._replace_text(self.hex_text,"")
            self.selection_label.configure(text="无匹配数据包")
        self._update_summary()
        return True

    def select_packet(self,_=None):
        selected = self.packet_tree.selection()
        if not selected:
            return
        p = self.by_number[selected[0]]
        self.detail_tree.delete(*self.detail_tree.get_children())
        self.layer_ranges = {}
        for i,layer in enumerate(p.layers):
            item = self.detail_tree.insert("","end",text=layer.name,values=(f"bytes {layer.start}..{max(layer.start,layer.end-1)}",),
                                           open=layer.name in (p.protocol,"Diagnostics"))
            self.layer_ranges[item] = (layer.start,layer.end)
            for key,value in layer.fields.items():
                self.detail_tree.insert(item,"end",text=key,values=(str(value),))
        if p.flow_id is not None:
            self.detail_tree.insert("","end",text="TCP stream",values=(p.flow_id,))
        self.detail_tree.insert("","end",text="Process snapshot",values=(p.process or "未关联 / 离线捕获不含 PID",))
        self.selection_label.configure(text=f"#{p.number}  ·  {p.protocol}  ·  {len(p.raw)} / {p.wire_length} bytes"+("  ·  解析诊断" if p.warnings else ""))
        self._replace_text(self.hex_text,hexdump(p.raw))

    def highlight_layer(self,_=None):
        selected = self.detail_tree.selection()
        self.hex_text.tag_remove("range","1.0","end")
        if not selected:
            return
        item = selected[0]
        while item and item not in self.layer_ranges:
            item = self.detail_tree.parent(item)
        if item:
            start,end = self.layer_ranges[item]
            if end > start:
                self.hex_text.tag_add("range",f"{start//16+1}.0",f"{(min(end,65536)-1)//16+2}.0")
                self.hex_text.see(f"{start//16+1}.0")

    def follow_selected(self):
        selected = self.packet_tree.selection()
        if not selected:
            return
        p = self.by_number[selected[0]]
        if p.flow_id is None:
            self.status.set("所选数据包不属于 TCP 流")
            return
        self.notebook.select(self.flow_tab)
        self.show_flow(p.flow_id)

    def show_flow(self,flow_id):
        if not 0 <= flow_id < len(self.flow_index.flows):
            return
        self.current_flow = self.flow_index.flows[flow_id]
        self.flow_choice.configure(values=[f.label for f in self.flow_index.flows])
        self.flow_choice.current(flow_id)
        total_overlap,total_conflict,gaps = 0,0,0
        protocols = []
        for direction in (0,1):
            result = self.current_flow.assembled(direction)
            total_overlap += result.overlap_bytes
            total_conflict += result.conflict_bytes
            gaps += len(result.gaps)
            protocol = parse_http(result.data)
            if protocol:
                protocols.append("HTTP")
            self._replace_text(self.flow_texts[direction],result.text() or "[此方向暂无应用层载荷]")
        processes = "; ".join(sorted({p.process for p in self.current_flow.packets if p.process}))
        self.flow_summary.configure(text=f"{len(self.current_flow.packets)} 包  ·  重叠 {total_overlap} B  ·  冲突 {total_conflict} B  ·  缺口 {gaps}  ·  "+
                                   ("HTTP 内容识别" if protocols else "按 TCP 序列号重组")+("  ·  "+processes if processes else ""))
        self.draw_flow()

    def draw_flow(self):
        c = self.flow_canvas
        c.delete("all")
        if self.current_flow is None:
            return
        flow = self.current_flow
        width = max(c.winfo_width(),650)
        left,right = 180,width-180
        packets = flow.packets[:500]
        height = 100+len(packets)*48
        c.configure(scrollregion=(0,0,width,height))
        for x,end,name in [(left,flow.a,"A"),(right,flow.b,"B")]:
            c.create_text(x,22,text=f"{name}  {endpoint(*end)}",fill=INK,font=("Consolas",11,"bold"))
            c.create_line(x,47,x,height-18,fill=LINE,width=2,dash=(4,3))
        for i,p in enumerate(packets):
            y = 76+i*48
            x1,x2 = (left,right) if flow.direction(p) == 0 else (right,left)
            color = ACCENT if flow.direction(p) == 0 else "#b87527"
            c.create_line(x1,y,x2,y,arrow="last",fill=color,width=2)
            flags = next((layer.fields.get("Flags","") for layer in p.layers if layer.name == "TCP"),"")
            c.create_text((left+right)/2,y-12,text=f"#{p.number} {flags}  seq={p.seq}  len={len(p.payload)}",fill=INK,font=("Consolas",10))
            c.create_text(63,y,text=f"{p.timestamp-flow.packets[0].timestamp:.4f}s",fill=MUTED,font=("Consolas",9))
        if len(flow.packets)>500:
            c.create_text(width/2,height-15,text="时序图显示前 500 包；重组和导出使用整条流",fill=MUTED)

    def filter_flow(self):
        if self.current_flow:
            self.set_filter(f"tcp.stream == {self.current_flow.id}")

    def export_flow(self):
        if not self.current_flow:
            return
        path = filedialog.asksaveasfilename(parent=self.root,defaultextension=".txt",filetypes=[("UTF-8 text","*.txt")],initialfile=f"tcp_stream_{self.current_flow.id}.txt")
        if path:
            try:
                Path(path).write_text(self.current_flow.export_text(),encoding="utf-8")
                self.status.set("流文本已导出："+path)
            except OSError as exc:
                messagebox.showerror("导出失败",str(exc),parent=self.root)

    def _tab_changed(self,_=None):
        if self.notebook.select() == str(self.flow_tab):
            self.flow_choice.configure(values=[f.label for f in self.flow_index.flows])
            if self.current_flow is None and self.flow_index.flows:
                self.show_flow(0)
        elif self.notebook.select() == str(self.stats_tab):
            self.draw_stats()

    def draw_stats(self):
        c = self.stats_canvas
        c.delete("all")
        width,height = max(c.winfo_width(),700),max(c.winfo_height(),450)
        c.create_text(30,32,text="捕获概况",anchor="w",font=("Microsoft YaHei UI",17,"bold"),fill=INK)
        c.create_text(30,61,text=self.source,anchor="w",font=("Microsoft YaHei UI",10),fill=MUTED)
        summary = [("保留包数",f"{len(self.packets):,}"),("捕获字节",self._size(self.total_bytes)),("TCP 流",str(len(self.flow_index.flows))),
                   ("有诊断的包",str(sum(bool(p.warnings) for p in self.packets)))]
        for i,(label,value) in enumerate(summary):
            x = 30+i*(width-60)/4
            c.create_rectangle(x,88,x+(width-90)/4,173,fill=BG,outline="")
            c.create_text(x+15,109,text=label,anchor="w",fill=MUTED,font=("Microsoft YaHei UI",10))
            c.create_text(x+15,145,text=value,anchor="w",fill=INK,font=("Segoe UI",23,"bold"))
        c.create_text(30,208,text="协议分布 · 按最深识别层计数",anchor="w",fill=INK,font=("Microsoft YaHei UI",11,"bold"))
        max_count = max(self.protocol_counts.values(),default=1)
        for i,(protocol,count) in enumerate(self.protocol_counts.most_common(10)):
            y = 242+i*25
            c.create_text(30,y,text=protocol,anchor="w",fill=INK,font=("Consolas",10))
            c.create_rectangle(102,y-7,102+(width*0.43-130)*count/max_count,y+7,fill=ACCENT,outline="")
            c.create_text(width*0.43+7,y,text=str(count),anchor="w",fill=MUTED,font=("Consolas",10))
        x0,x1,y0,y1 = width*0.54,width-36,240,min(height-60,450)
        c.create_text(x0,208,text="包时间分布 · 32 个等宽时间桶",anchor="w",fill=INK,font=("Microsoft YaHei UI",11,"bold"))
        bins = [0]*32
        if self.packets:
            first,last = min(p.timestamp for p in self.packets),max(p.timestamp for p in self.packets)
            span = max(last-first,0.001)
            for p in self.packets:
                bins[min(31,int((p.timestamp-first)/span*32))] += 1
        high = max(bins,default=1) or 1
        for i,count in enumerate(bins):
            x = x0+i*(x1-x0)/32
            c.create_rectangle(x,y1-(y1-y0)*count/high,x+(x1-x0)/32-3,y1,fill="#52a9b2",outline="")
        c.create_line(x0,y1,x1,y1,fill=LINE)
        c.create_text(x0,y1+20,text="开始",anchor="w",fill=MUTED)
        c.create_text(x1,y1+20,text="结束",anchor="e",fill=MUTED)

    @staticmethod
    def _size(n):
        return f"{n/1048576:.2f} MiB" if n >= 1048576 else f"{n/1024:.1f} KiB" if n >= 1024 else f"{n} B"

    def _update_summary(self):
        self.total_label.configure(text=f"{len(self.packets):,}")
        self.volume_label.configure(text=f"{self._size(self.total_bytes)}  ·  {len(self.flow_index.flows)} TCP 流")
        self.status.set(f"{self.source}  |  保留 {len(self.packets):,} 包  ·  匹配 {self.matching:,}  ·  表格 {len(self.visible_ids):,}"+
                        ("  |  达到保留上限，已停止；请保存后开始新会话" if self.limit_reached else ""))

    def _pump(self):
        try:
            while True:
                kind,value = self.io_results.get_nowait()
                if kind == "traffic":
                    self.status.set(value)
                    continue
                if kind == "traffic_error":
                    messagebox.showerror("测试流量失败",value,parent=self.root)
                    continue
                self.loading = False
                self._set_running(False)
                if kind == "loaded":
                    self.load_packets(*value)
                else:
                    messagebox.showerror("文件读取失败",value,parent=self.root)
        except queue.Empty:
            pass
        if self.session:
            session = self.session
            changed = False
            for _ in range(350):
                try:
                    p = session.packets.get_nowait()
                except queue.Empty:
                    break
                self._add_packet(p)
                changed = True
            try:
                while True:
                    kind,value = session.events.get_nowait()
                    if kind == "started":
                        self.mode.configure(text="LIVE  ●  实时捕获",fg="#b5f4d3")
                    elif kind == "error":
                        self.status.set("捕获失败："+value)
                        messagebox.showerror("捕获失败",value,parent=self.root)
                    elif kind == "stats":
                        self.last_stats = value
                        self.drop_label.configure(text=f"驱动丢包 {value.get('kernel_dropped','—')}  ·  队列丢包 {value.get('queue_dropped',0)}")
                    elif kind == "stopped":
                        self.mode.configure(text="STOPPED  ·  已停止",fg="#c7deee")
            except queue.Empty:
                pass
            if changed:
                self._update_summary()
                if self.notebook.select() == str(self.stats_tab) and time.monotonic()-self.last_chart>1:
                    self.draw_stats()
                    self.last_chart = time.monotonic()
            if not session.thread.is_alive() and session.packets.empty():
                self._set_running(False)
                self.session = None
                self.draw_stats()
        if self.pending_close and self.session is None:
            self.root.destroy()
            return
        self.root.after(80,self._pump)

    def close(self):
        if self.session:
            self.pending_close = True
            self.stop_capture()
        else:
            self.root.destroy()

    def generate_traffic(self):
        def work():
            try:
                if isinstance(self.pcap,WslPcap):
                    result = self.pcap.generate_traffic()
                else:
                    from tools.local_traffic import generate
                    generate()
                    result = "已完成 localhost:18080 的受控 HTTP 测试"
                self.io_results.put(("traffic",result))
            except Exception as exc:
                self.io_results.put(("traffic_error",str(exc)))
        threading.Thread(target=work,name="local-test-traffic",daemon=True).start()
        self.status.set("正在本地回环端口 18080 产生 HTTP 请求…")

    def show_help(self):
        window = tk.Toplevel(self.root)
        window.title("WireScope 使用帮助")
        window.geometry("820x660")
        holder = ttk.Frame(window)
        holder.pack(fill="both",expand=True)
        text = self._text(holder,font=("Microsoft YaHei UI",11))
        content = """WireScope / 实验 1A

快速开始
1. 安装 Python 3.10+（包含 Tk），Windows 实时捕获另需 Npcap。
   若未安装 Npcap，会尝试现有 WSL 的 libpcap；网卡显示 WSL 标记。
   WSL 网卡捕获的是 WSL 网络，Windows 主机网卡需要 Npcap。
2. 选择网卡，按需填写 BPF，然后开始捕获。停止后可保存全部包。
3. 双击 TCP 数据包查看双向重组内容与连接时序。
4. 无驱动时可加载内置合成样例，或打开 PCAP / PCAPNG。

捕获过滤 BPF（开始前设置）
tcp port 18080
host 127.0.0.1 and tcp
ip6 or icmp
由 libpcap 编译并应用；HTTP 没有通用 BPF 关键字。

显示过滤（不会删除原始包）
http                          内容识别 HTTP/1.x
tcp and port == 8080           协议与端口
(ipv6 or icmp) and not dns     逻辑运算和括号
ip.addr == 127.0.0.1           任一 IP 端点
tcp.stream == 0               追踪指定 TCP 连接
info contains "GET"            摘要包含文本
process contains "python"      本机 socket 快照关联（可选 psutil）
端口不等于条件要求两端均不等于；缺失字段不匹配。

保存与重组
保存全部：保存当前会话的全部保留数据。
导出筛选：保存全部匹配数据，即使表格只显示最近 2,000 条。
TCP 重组处理乱序、重传、32 位序列号回绕；冲突采用先捕获字节。
缺口会显式标记，单方向重组上限 2 MiB。
TLS 展示记录头与完整 ClientHello 的 SNI，加密正文保持原始字节。
IP 分片不重组；HTTP 内容识别以完整起始行为依据。
PCAPNG 支持多 section / 多接口的 Enhanced Packet Block。
实时保留上限：50,000 包 / 64 MiB；内核和应用队列丢包分别计数。

受控实时验证
选择 Loopback，BPF 填 tcp port 18080，开始捕获。
点击左侧“产生回环测试流量”，或运行 python run.py --test-traffic。
查看 HTTP 请求/响应，停止，保存为 PCAPNG。

快捷键：Ctrl+O 打开；Ctrl+S 保存；Ctrl+L 定位显示过滤。
"""
        self._replace_text(text,content)
        ttk.Button(window,text="打开 Npcap 官方下载页",command=lambda:webbrowser.open("https://npcap.com/#download")).pack(pady=8)


def launch(path=None,demo=False):
    root = tk.Tk()
    app = SnifferApp(root)
    if path:
        root.after(100,lambda:app.load_path(path))
    elif demo:
        root.after(100,lambda:app.load_packets(make_demo_packets(),"内置合成样例 · 非实抓流量"))
    root.mainloop()
