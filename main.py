#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
我的世界联机工具 - UPnP 直连 (增强版)
修复 Action Failed 兼容性问题，增加多层 NAT 检测与自动端口协商
"""

import sys
import os
import socket
import traceback
import time
import random

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QTextEdit, QTabWidget, QMessageBox,
    QFormLayout, QSpinBox, QCheckBox
)
from PyQt5.QtCore import Qt, QObject, pyqtSignal, QThread
from PyQt5.QtGui import QFont

# ==================== 依赖检查 ====================
MISSING_DEPS = []
try:
    import miniupnpc
except ImportError:
    MISSING_DEPS.append("miniupnpc")
try:
    import requests
except ImportError:
    MISSING_DEPS.append("requests")
try:
    import pyperclip
except ImportError:
    MISSING_DEPS.append("pyperclip")


# ==================== 后台工作线程 ====================
class UPnPWorker(QObject):
    status_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str, str)  # success, address, guide

    def __init__(self, local_port, external_port=None, auto_port=False):
        super().__init__()
        self.local_port = local_port
        self.external_port = external_port if external_port is not None else local_port
        self.auto_port = auto_port  # 端口冲突时自动换端口
        self._running = True
        self.upnp = None
        self.protocol = None
        self.public_ip = None
        self.local_ip = None
        self.gateway_ip = None
        self.final_ext_port = self.external_port

    def log(self, msg):
        self.status_signal.emit(msg)

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            raise Exception(f"获取内网IP失败: {e}")

    def get_public_ip(self):
        urls = [
            ("https://api.ip.sb/geoip/", "json", "ip"),
            ("https://ifconfig.me/ip", "text", None),
            ("https://icanhazip.com", "text", None),
            ("https://ipinfo.io/ip", "text", None),
            ("https://myip.ipip.net", "text", None),
        ]
        for url, fmt, key in urls:
            if not self._running:
                raise Exception("操作已取消")
            try:
                self.log(f"尝试获取公网IP: {url}")
                resp = requests.get(url, timeout=5, proxies={"http": None, "https": None})
                resp.raise_for_status()
                if fmt == "json":
                    ip = resp.json().get(key, "").strip()
                else:
                    ip = resp.text.strip()
                if ip:
                    self.log(f"✅ 公网IP: {ip}")
                    return ip
            except Exception as e:
                self.log(f"❌ {url} 失败: {e}")
                continue
        raise Exception("无法获取公网 IP")

    def check_port_listening(self, port):
        """检查本地端口是否已有程序监听"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex(("127.0.0.1", port))
            s.close()
            return result == 0
        except:
            return False

    def is_private_ip(self, ip):
        """判断是否为内网IP（检测多层NAT）"""
        parts = ip.split(".")
        if len(parts) != 4:
            return True
        a, b, c, d = [int(x) for x in parts]
        # 10.0.0.0/8
        if a == 10:
            return True
        # 172.16.0.0/12
        if a == 172 and 16 <= b <= 31:
            return True
        # 192.168.0.0/16
        if a == 192 and b == 168:
            return True
        # 100.64.0.0/10 (CGNAT)
        if a == 100 and 64 <= b <= 127:
            return True
        return False

    def discover_upnp(self):
        """发现 UPnP 设备，兼容多种版本"""
        self.upnp = miniupnpc.UPnP()
        # 尝试多种 discover 调用方式
        methods = [
            lambda: self.upnp.discover(delay=200),
            lambda: self.upnp.discover(delay=500),
            lambda: (setattr(self.upnp, "discoverdelay", 200), self.upnp.discover())[1],
            lambda: (setattr(self.upnp, "discoverdelay", 500), self.upnp.discover())[1],
        ]
        last_err = None
        for i, method in enumerate(methods):
            try:
                self.log(f"UPnP 发现尝试 #{i+1}...")
                ndevices = method()
                self.log(f"发现 {ndevices} 个设备")
                if ndevices > 0:
                    return ndevices
            except Exception as e:
                last_err = e
                self.log(f"发现尝试 #{i+1} 失败: {e}")
                continue
        if last_err:
            raise Exception(f"UPnP 发现失败: {last_err}")
        return 0

    def get_existing_mappings(self):
        """获取当前已存在的端口映射列表"""
        mappings = []
        try:
            i = 0
            while True:
                try:
                    m = self.upnp.getgenericportmapping(i)
                    if m is None:
                        break
                    # m = (port, protocol, (internal_ip, internal_port), desc, remote_host, lease)
                    mappings.append(m)
                    i += 1
                except Exception:
                    break
        except Exception as e:
            self.log(f"获取现有映射失败: {e}")
        return mappings

    def try_add_mapping(self, ext_port, proto, local_ip, local_port, desc, remote_host, lease):
        """尝试添加映射，返回 (success, error_msg)"""
        try:
            # 使用位置参数，兼容所有 miniupnpc 版本
            result = self.upnp.addportmapping(
                ext_port,      # 0: external port
                proto,         # 1: protocol
                local_ip,      # 2: internal host
                local_port,    # 3: internal port
                desc,          # 4: description
                remote_host,   # 5: remote host
                lease          # 6: lease duration
            )
            return result, None
        except Exception as e:
            return False, str(e)

    def setup_upnp(self, local_ip):
        """UPnP 端口映射，带多重兼容处理"""
        ndevices = self.discover_upnp()
        if ndevices == 0:
            raise Exception("未发现 UPnP 路由器，请检查路由器是否开启 UPnP")

        try:
            self.upnp.selectigd()
            self.gateway_ip = self.upnp.externalipaddress()
            self.log(f"✅ 网关: {self.gateway_ip}")
        except Exception as e:
            raise Exception(f"选择网关失败: {e}")

        # 检测多层 NAT
        if self.is_private_ip(self.gateway_ip):
            self.log(f"⚠️ 警告: 网关返回的是内网IP ({self.gateway_ip})，可能存在多层NAT")
            self.log("   这意味着即使映射成功，外部玩家可能仍无法直接连接")
            self.log("   建议: 将电脑直接连接到光猫/主路由，或要求主路由做端口转发")

        # 检查现有映射
        existing = self.get_existing_mappings()
        self.log(f"当前已有 {len(existing)} 条端口映射")
        for m in existing:
            try:
                eport, eproto, (iip, iport), edesc = m[0], m[1], m[2], m[3]
                if eport == self.final_ext_port and eproto in ("UDP", "TCP"):
                    self.log(f"   发现已有映射: {eproto} {eport} -> {iip}:{iport} ({edesc})")
            except:
                pass

        # 准备多种参数组合进行尝试
        protocols = ["UDP", "TCP"]
        leases = [86400, 0, 3600]
        descriptions = [
            "Minecraft-LAN",
            "Minecraft",
            "MC",
            ""
        ]
        remote_hosts = ["", "0.0.0.0"]

        # 如果用户允许，准备备选端口
        candidate_ports = [self.final_ext_port]
        if self.auto_port:
            # 生成附近端口和高位随机端口
            for offset in [1, -1, 10, -10]:
                p = self.final_ext_port + offset
                if 1024 <= p <= 65535:
                    candidate_ports.append(p)
            # 添加高位随机端口
            for _ in range(5):
                p = random.randint(30000, 65000)
                if p not in candidate_ports:
                    candidate_ports.append(p)

        for ext_port in candidate_ports:
            if not self._running:
                raise Exception("操作已取消")

            for proto in protocols:
                for lease in leases:
                    for desc in descriptions:
                        for rhost in remote_hosts:
                            if not self._running:
                                raise Exception("操作已取消")
                            try:
                                self.log(f"尝试 {proto} 外{ext_port}->内{local_ip}:{self.local_port} (租期={lease}, 描述='{desc}')...")
                                result, err = self.try_add_mapping(
                                    ext_port, proto, local_ip, self.local_port,
                                    desc, rhost, lease
                                )
                                if result:
                                    self.final_ext_port = ext_port
                                    self.protocol = proto
                                    self.log(f"✅ 映射成功！{proto} {ext_port} -> {local_ip}:{self.local_port}")
                                    return proto
                                else:
                                    self.log(f"   失败: {err}")
                                    # 如果错误包含 Invalid Args，可能是参数格式问题，继续尝试其他组合
                                    if "Invalid Args" in str(err):
                                        continue
                                    # Action Failed 可能是端口被占或路由器限制，换端口
                                    if "Action Failed" in str(err):
                                        break
                            except Exception as e:
                                self.log(f"   异常: {e}")
                                continue

        # 全部失败
        raise Exception("UPNP_ALL_FAILED")

    def get_manual_guide(self):
        pub_ip = self.public_ip if self.public_ip else "获取失败"
        loc_ip = self.local_ip if self.local_ip else "获取失败"
        gw_ip = self.gateway_ip if self.gateway_ip else "未知"

        nat_warning = ""
        if self.gateway_ip and self.is_private_ip(self.gateway_ip):
            nat_warning = f"""
⚠️ 重要提示：检测到多层 NAT！
   你的 UPnP 网关 ({gw_ip}) 返回的是内网地址，
   说明你的电脑不是直接连接到公网路由器的。

   解决方案：
   1. 将电脑网线直接插到光猫/主路由的 LAN 口
   2. 或者在主路由（{gw_ip} 的上一级）中做端口转发
   3. 或者联系网络管理员/运营商申请公网IP
"""

        return f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
【手动端口转发设置指南】
UPnP 自动映射失败，请按以下步骤手动设置：

1. 打开浏览器，输入路由器管理地址
   你的网关可能是: {gw_ip}
   常见地址: 192.168.1.1 / 192.168.0.1 / 192.168.2.1

2. 登录后找到「端口转发」「虚拟服务器」或「NAT设置」

3. 添加新规则，参数如下：
   ├─ 外部端口: {self.final_ext_port}
   ├─ 内部端口: {self.local_port}
   ├─ 内部IP地址: {loc_ip}
   ├─ 协议: UDP + TCP（同时添加两条）
   └─ 描述/名称: Minecraft-LAN

4. 保存并应用设置

5. 将以下地址分享给好友：
   【{pub_ip}:{self.final_ext_port}】
{nat_warning}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""

    def run(self):
        try:
            if MISSING_DEPS:
                raise Exception(
                    f"缺少依赖: {', '.join(MISSING_DEPS)}\n"
                    f"请运行: pip install {' '.join(MISSING_DEPS)}"
                )

            self.log("=" * 44)
            self.log('欢迎使用鱼丸联机-v1.0 By XiaoWang')
            self.log("🚀 开始创建房间...")

            # 检查本地端口
            self.log(f"📡 检查本地端口 {self.local_port}...")
            if not self.check_port_listening(self.local_port):
                self.log(f"⚠️ 警告: 端口 {self.local_port} 似乎没有程序在监听")
                self.log("   请确认你已在 Minecraft 中「对局域网开放」了世界")
            else:
                self.log(f"✅ 端口 {self.local_port} 已有程序监听")

            # 获取内网 IP
            self.log("📡 获取本机内网IP...")
            self.local_ip = self.get_local_ip()
            self.log(f"✅ 内网IP: {self.local_ip}")

            # 获取公网 IP
            self.log("🌐 获取公网IP...")
            self.public_ip = self.get_public_ip()

            # UPnP 映射
            self.log("🔧 开始 UPnP 端口映射...")
            proto = self.setup_upnp(self.local_ip)

            addr = f"{self.public_ip}:{self.final_ext_port}"
            self.log(f"\n🎉 房间创建成功！")
            self.log(f"📍 公网地址: {addr}")
            self.log(f"📍 内网地址: {self.local_ip}:{self.local_port}")
            self.log(f"📍 协议: {proto}")
            self.log(f"\n💡 请将公网地址分享给好友加入！")
            self.finished_signal.emit(True, addr, "")

        except Exception as e:
            err_msg = str(e)
            full_trace = traceback.format_exc()

            if "UPNP_ALL_FAILED" in err_msg:
                guide = self.get_manual_guide()
                self.log(guide)
                self.log(f"\n详细错误:\n{full_trace}")
                self.finished_signal.emit(False, "UPnP失败", guide)
            else:
                self.log(f"\n❌ 错误: {err_msg}")
                self.log(f"详细堆栈:\n{full_trace}")
                self.finished_signal.emit(False, err_msg, "")

    def stop(self):
        self._running = False

    def cleanup(self):
        if self.upnp:
            if self.protocol:
                try:
                    self.upnp.deleteportmapping(self.final_ext_port, self.protocol)
                    self.log(f"🧹 已删除 {self.protocol} 映射")
                except Exception as e:
                    self.log(f"⚠️ 删除 {self.protocol} 映射失败: {e}")
            # 清理另一个协议
            other = "TCP" if self.protocol == "UDP" else "UDP"
            try:
                self.upnp.deleteportmapping(self.final_ext_port, other)
            except:
                pass


# ==================== 主界面 ====================
class MinecraftLANTool(QWidget):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.worker_thread = None
        self.current_address = None
        self.init_ui()
        self.apply_style()

    def init_ui(self):
        self.setWindowTitle("鱼丸联机v1.0 - By XiaoWang")
        self.setMinimumWidth(460)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        self.tabs = QTabWidget()

        # ===== 主机页面 =====
        host_tab = QWidget()
        host_layout = QVBoxLayout(host_tab)
        host_layout.setSpacing(12)

        form = QFormLayout()
        form.setSpacing(10)

        self.local_port_input = QSpinBox()
        self.local_port_input.setRange(1, 65535)
        self.local_port_input.setValue(25565)
        self.local_port_input.setToolTip("Minecraft 局域网开放后显示的端口号")
        form.addRow("本地游戏端口:", self.local_port_input)

        self.ext_port_input = QLineEdit()
        self.ext_port_input.setPlaceholderText("留空则与本地端口相同")
        form.addRow("外部端口 (可选):", self.ext_port_input)

        self.auto_port_cb = QCheckBox("端口冲突时自动尝试其他端口")
        self.auto_port_cb.setChecked(True)
        self.auto_port_cb.setToolTip("如果指定端口映射失败，自动尝试附近端口")
        form.addRow("", self.auto_port_cb)

        host_layout.addLayout(form)

        btn_layout = QHBoxLayout()
        self.btn_start = QPushButton("▶️ 开启房间")
        self.btn_start.setObjectName("btn_primary")
        self.btn_start.clicked.connect(self.start_room)

        self.btn_stop = QPushButton("⏹️ 关闭房间")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_room)

        self.btn_copy_host = QPushButton("📋 复制房间地址")
        self.btn_copy_host.setEnabled(False)
        self.btn_copy_host.clicked.connect(self.copy_host_address)

        btn_layout.addWidget(self.btn_start)
        btn_layout.addWidget(self.btn_stop)
        btn_layout.addWidget(self.btn_copy_host)
        host_layout.addLayout(btn_layout)

        self.host_log = QTextEdit()
        self.host_log.setReadOnly(True)
        self.host_log.setMaximumHeight(160)
        self.host_log.setPlaceholderText("操作日志将显示在这里...")
        host_layout.addWidget(self.host_log)

        self.tabs.addTab(host_tab, "🏠 创建房间")

        # ===== 客机页面 =====
        client_tab = QWidget()
        client_layout = QVBoxLayout(client_tab)
        client_layout.setSpacing(12)

        client_form = QFormLayout()
        self.client_addr = QLineEdit()
        self.client_addr.setPlaceholderText("例如: 123.45.67.89:25565")
        client_form.addRow("房间地址 (IP:端口):", self.client_addr)
        client_layout.addLayout(client_form)

        client_btn = QHBoxLayout()
        self.btn_copy_client = QPushButton("📋 复制地址到剪贴板")
        self.btn_copy_client.clicked.connect(self.copy_client_address)
        client_btn.addStretch()
        client_btn.addWidget(self.btn_copy_client)
        client_layout.addLayout(client_btn)

        hint = QTextEdit()
        hint.setReadOnly(True)
        hint.setHtml("""
        <h3>🎮 如何加入房间</h3>
        <ol>
            <li>点击上方「复制地址到剪贴板」</li>
            <li>打开 Minecraft 游戏</li>
            <li>进入「多人游戏」→「直接连接」</li>
            <li>粘贴地址，点击「加入服务器」</li>
        </ol>
        <p style="color:#888;">💡 提示：如果连接失败，请确认房主已开启房间，且防火墙已放行。</p>
        """)
        client_layout.addWidget(hint)

        self.tabs.addTab(client_tab, "🎮 加入房间")

        layout.addWidget(self.tabs)

        self.status = QLabel("就绪")
        self.status.setObjectName("status_label")
        layout.addWidget(self.status)

    def apply_style(self):
        self.setStyleSheet("""
            QWidget {
                font-family: "Microsoft YaHei", "PingFang SC", sans-serif;
                font-size: 13px;
            }
            QTabWidget::pane {
                border: 1px solid #ddd;
                border-radius: 8px;
                background: #fafafa;
                padding: 12px;
            }
            QTabBar::tab {
                padding: 10px 20px;
                margin-right: 4px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                background: #e0e0e0;
            }
            QTabBar::tab:selected {
                background: #fafafa;
                font-weight: bold;
            }
            QLineEdit, QSpinBox {
                padding: 8px;
                border: 1px solid #ccc;
                border-radius: 6px;
                background: white;
            }
            QLineEdit:focus, QSpinBox:focus {
                border: 2px solid #4CAF50;
            }
            QPushButton {
                padding: 10px 20px;
                border-radius: 6px;
                border: none;
                background: #e0e0e0;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #d0d0d0;
            }
            #btn_primary {
                background: #4CAF50;
                color: white;
            }
            #btn_primary:hover {
                background: #45a049;
            }
            #btn_primary:disabled {
                background: #a5d6a7;
            }
            QTextEdit {
                border: 1px solid #ddd;
                border-radius: 6px;
                background: #f5f5f5;
                padding: 8px;
                line-height: 1.5;
            }
            QCheckBox {
                spacing: 6px;
            }
            #status_label {
                color: #666;
                font-size: 12px;
                padding: 4px;
            }
        """)

    def log(self, msg):
        timestamp = time.strftime("%H:%M:%S")
        self.host_log.append(f"[{timestamp}] {msg}")

    def start_room(self):
        local_port = self.local_port_input.value()
        ext_text = self.ext_port_input.text().strip()
        try:
            external_port = int(ext_text) if ext_text else local_port
        except ValueError:
            QMessageBox.warning(self, "错误", "外部端口必须是数字")
            return

        if not (1 <= external_port <= 65535):
            QMessageBox.warning(self, "错误", "外部端口必须在 1-65535 之间")
            return

        self.host_log.clear()
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.btn_copy_host.setEnabled(False)
        self.current_address = None

        auto_port = self.auto_port_cb.isChecked()
        self.worker = UPnPWorker(local_port, external_port, auto_port)
        self.worker.status_signal.connect(self.log)
        self.worker.finished_signal.connect(self.on_worker_finished)

        self.worker_thread = QThread()
        self.worker.moveToThread(self.worker_thread)
        self.worker_thread.started.connect(self.worker.run)
        self.worker_thread.start()

        self.status.setText("正在创建房间...")

    def on_worker_finished(self, success, result, guide):
        if success:
            self.current_address = result
            self.btn_copy_host.setEnabled(True)
            self.status.setText(f"房间已开启: {result}")
        else:
            self.status.setText(f"创建失败: {result}")
            # 如果失败但有指南，显示提示
            if guide:
                self.status.setText("UPnP失败，请查看日志中的手动设置指南")
            self.btn_start.setEnabled(True)
            self.btn_stop.setEnabled(False)

    def stop_room(self):
        if self.worker:
            self.worker.stop()
            self.worker.cleanup()
            self.worker = None

        if self.worker_thread:
            self.worker_thread.quit()
            self.worker_thread.wait()
            self.worker_thread = None

        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.btn_copy_host.setEnabled(False)
        self.current_address = None
        self.log("⏹️ 房间已关闭")
        self.status.setText("房间已关闭")

    def copy_host_address(self):
        if self.current_address:
            try:
                pyperclip.copy(self.current_address)
                QMessageBox.information(
                    self, "已复制",
                    f"房间地址已复制到剪贴板:\n{self.current_address}"
                )
            except Exception as e:
                QMessageBox.warning(self, "复制失败", str(e))

    def copy_client_address(self):
        addr = self.client_addr.text().strip()
        if not addr:
            QMessageBox.warning(self, "提示", "请先输入房间地址")
            return
        try:
            pyperclip.copy(addr)
            QMessageBox.information(
                self, "已复制",
                f"地址已复制到剪贴板:\n{addr}\n\n"
                f"请在游戏内「直接连接」中粘贴使用。"
            )
        except Exception as e:
            QMessageBox.warning(self, "复制失败", str(e))

    def closeEvent(self, event):
        self.stop_room()
        event.accept()


# ==================== 入口 ====================
def main():
    if MISSING_DEPS:
        msg = (
            f"缺少以下依赖，请先安装:\n\n"
            + "\n".join(MISSING_DEPS)
            + f"\n\n运行命令:\npip install {' '.join(MISSING_DEPS)}"
        )
        try:
            app = QApplication(sys.argv)
            QMessageBox.critical(None, "缺少依赖", msg)
        except:
            print(msg)
        sys.exit(1)

    app = QApplication(sys.argv)
    app.setFont(QFont("Microsoft YaHei", 10))

    window = MinecraftLANTool()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
