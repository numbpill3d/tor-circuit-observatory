#!/usr/bin/env python3
"""Compact native Tor health observatory. No browser, Electron, or disk log."""
from __future__ import annotations

import sys
from datetime import datetime
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QFont, QPalette
from PyQt6.QtWidgets import (
    QApplication, QDialog, QFrame, QGridLayout, QHBoxLayout, QLabel,
    QListWidget, QListWidgetItem, QMainWindow, QMessageBox, QPushButton,
    QProgressBar, QVBoxLayout, QWidget,
)


INK = "#111111"
PAPER = "#d8d8d2"
LIGHT = "#eeeeea"
MID = "#555550"
GREEN = "#075b35"
AMBER = "#805100"
FONT = "Courier New"


def label(text: str, size: int = 11, bold: bool = False) -> QLabel:
    item = QLabel(text)
    item.setFont(QFont(FONT, size, QFont.Weight.Bold if bold else QFont.Weight.Normal))
    return item


class Metric(QFrame):
    def __init__(self, name: str, value: str, suffix: str, status: str, good: bool = False):
        super().__init__()
        self.setObjectName("metric")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(13, 10, 13, 10)
        layout.setSpacing(2)
        layout.addWidget(label(name, 10, True))
        value_row = QHBoxLayout()
        value_row.setSpacing(4)
        value_row.addWidget(label(value, 25, True))
        value_row.addWidget(label(suffix, 11))
        value_row.addStretch()
        layout.addLayout(value_row)
        status_label = label(status, 10, True)
        status_label.setProperty("good", good)
        layout.addWidget(status_label)


class CircuitRow(QFrame):
    def __init__(self, circuit: str, kind: str, middle: str, exit_node: str, age: str):
        super().__init__()
        self.setObjectName("circuitRow")
        layout = QGridLayout(self)
        layout.setContentsMargins(8, 10, 8, 10)
        layout.setHorizontalSpacing(8)
        id_box = QVBoxLayout()
        id_box.setSpacing(1)
        id_box.addWidget(label(f"●  {circuit}", 11, True))
        id_box.addWidget(label(kind, 10))
        layout.addLayout(id_box, 0, 0)
        route = QHBoxLayout()
        route.setSpacing(3)
        for node, country in (("GUARD", "DE"), ("MIDDLE", middle), ("EXIT", exit_node)):
            box = QLabel(f"{node}\n{country}")
            box.setAlignment(Qt.AlignmentFlag.AlignCenter)
            box.setObjectName("relay")
            route.addWidget(box)
            if node != "EXIT":
                route.addWidget(label("—", 10))
        layout.addLayout(route, 0, 1)
        age_label = label(age, 11, True)
        age_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(age_label, 0, 2)
        layout.setColumnStretch(1, 1)


class PrivacyDialog(QDialog):
    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self.setWindowTitle("Privacy Report")
        self.setModal(True)
        self.setMinimumWidth(390)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)
        title = label("QUIET BY DEFAULT", 15, True)
        layout.addWidget(title)
        layout.addWidget(label("Aggregate health metrics are kept in memory only.\nDestination addresses, hostnames, and stream history are never written to disk.", 11))
        facts = label("✓ relay identities: current snapshot only\n✓ destination history: disabled\n✓ event detail: rolling 30 minutes", 11)
        facts.setObjectName("privacyFacts")
        layout.addWidget(facts)
        close = QPushButton("OKAY")
        close.clicked.connect(self.accept)
        layout.addWidget(close)


class Observatory(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Tor Circuit Observatory")
        self.setObjectName("observatory")
        self.setMinimumSize(880, 610)
        self.resize(980, 670)
        self.build_ui()
        self.clock = QTimer(self)
        self.clock.timeout.connect(self.update_time)
        self.clock.start(1000)

    def build_ui(self):
        root = QWidget()
        root.setObjectName("root")
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        menu = QFrame(); menu.setObjectName("menuBar")
        menu_layout = QHBoxLayout(menu); menu_layout.setContentsMargins(10, 2, 10, 2)
        menu_layout.addWidget(label("⌘", 17, True))
        for text in ("Observatory", "File", "View", "Window"):
            button = QPushButton(text); button.setObjectName("menuButton")
            if text == "Observatory": button.setProperty("active", True)
            menu_layout.addWidget(button)
        menu_layout.addStretch()
        menu_layout.addWidget(label("●  LOCAL ONLY   ", 10, True))
        self.time_label = label(datetime.now().strftime("%H:%M:%S"), 10)
        menu_layout.addWidget(self.time_label)
        outer.addWidget(menu)

        shell = QFrame(); shell.setObjectName("windowShell")
        shell_layout = QVBoxLayout(shell); shell_layout.setContentsMargins(0, 0, 0, 0); shell_layout.setSpacing(0)
        titlebar = QFrame(); titlebar.setObjectName("titlebar")
        title_layout = QHBoxLayout(titlebar); title_layout.setContentsMargins(10, 4, 10, 4)
        title_layout.addWidget(label("////", 11)); title_layout.addStretch(); title_layout.addWidget(label("TOR CIRCUIT OBSERVATORY", 12, True)); title_layout.addStretch(); title_layout.addWidget(label("////", 11))
        shell_layout.addWidget(titlebar)
        toolbar = QFrame(); toolbar.setObjectName("toolbar")
        tool_layout = QHBoxLayout(toolbar); tool_layout.setContentsMargins(14, 7, 14, 7)
        tool_layout.addWidget(label("●  TOR RUNNING   v0.4.7 / local control port", 11, True)); tool_layout.addStretch()
        refresh = QPushButton("REFRESH  ↻"); refresh.clicked.connect(self.refresh)
        privacy = QPushButton("PRIVACY"); privacy.clicked.connect(lambda: PrivacyDialog(self).exec())
        tool_layout.addWidget(refresh); tool_layout.addWidget(privacy)
        shell_layout.addWidget(toolbar)

        body = QFrame(); body_layout = QHBoxLayout(body); body_layout.setContentsMargins(0, 0, 0, 0); body_layout.setSpacing(0)
        sidebar = QFrame(); sidebar.setObjectName("sidebar"); side = QVBoxLayout(sidebar); side.setContentsMargins(12, 16, 12, 12); side.setSpacing(6)
        side.addWidget(label("OBSERVE", 10, True))
        self.tabs = QListWidget(); self.tabs.setObjectName("tabs")
        for item in ("▦  OVERVIEW", "⌘  CIRCUITS        3", "≋  STREAMS         8", "!  EVENTS          2"):
            self.tabs.addItem(QListWidgetItem(item))
        self.tabs.setCurrentRow(0); self.tabs.currentRowChanged.connect(self.select_view)
        side.addWidget(self.tabs)
        side.addWidget(label("CAPTURE", 10, True))
        side.addWidget(label("☑  Aggregate metrics", 11))
        side.addWidget(label("☐  Destination history", 11))
        privacy_note = label("DESTINATION HISTORY\nNOT RECORDED", 10, True); privacy_note.setObjectName("privacyNote"); side.addWidget(privacy_note)
        side.addStretch(); side.addWidget(label("●  daemon reachable", 10))
        body_layout.addWidget(sidebar)

        content = QWidget(); content_layout = QVBoxLayout(content); content_layout.setContentsMargins(20, 17, 20, 18); content_layout.setSpacing(12)
        heading = QHBoxLayout(); heading.addWidget(label("LIVE SNAPSHOT / UTC", 10, True)); heading.addStretch(); heading.addWidget(label("●  NOMINAL", 11, True)); content_layout.addLayout(heading)
        content_layout.addWidget(label("Network at a glance", 20, True))
        metrics = QHBoxLayout(); metrics.setSpacing(0)
        for args in (("ACTIVE GUARDS", "3", "/ 3", "stable set", True), ("CIRCUIT AGE", "08", "m 41s", "median lifetime", False), ("STREAMS", "8", " open", "0 unassigned", False), ("CONGESTION", "12", "%", "below threshold", True)):
            metrics.addWidget(Metric(*args))
        content_layout.addLayout(metrics)

        panels = QHBoxLayout(); panels.setSpacing(12)
        circuits = QFrame(); circuits.setObjectName("panel"); circuit_layout = QVBoxLayout(circuits); circuit_layout.setContentsMargins(0, 0, 0, 0); circuit_layout.setSpacing(0)
        circuit_header = QHBoxLayout(); circuit_header.setContentsMargins(10, 9, 10, 9); circuit_header.addWidget(label("ACTIVE CIRCUITS", 11, True)); circuit_header.addStretch(); circuit_header.addWidget(label("3 live / 0 rebuilding", 10)); circuit_layout.addLayout(circuit_header)
        circuit_layout.addWidget(CircuitRow("C-7A91", "GENERAL", "NL", "SE", "08:41")); circuit_layout.addWidget(CircuitRow("C-18F2", "GENERAL", "FR", "US", "04:12")); circuit_layout.addWidget(CircuitRow("C-4D20", "HS_CLIENT_INTRO", "CH", "—", "01:07"))
        panels.addWidget(circuits, 7)
        diversity = QFrame(); diversity.setObjectName("panel"); div = QVBoxLayout(diversity); div.setContentsMargins(14, 14, 14, 14); div.setSpacing(10)
        div.addWidget(label("OPERATOR DIVERSITY", 11, True)); div.addWidget(label("4 COUNTRIES\n7 OPERATORS\n9 RELAYS SEEN", 12)); div.addWidget(label("DE     NL     SE     US", 12, True)); div.addSpacing(4); div.addWidget(label("STREAM ASSIGNMENTS", 10, True));
        for assignment in ("C-7A91  →  4 streams", "C-18F2  →  3 streams", "C-4D20  →  1 stream"):
            div.addWidget(label(assignment, 10))
        div.addStretch(); panels.addWidget(diversity, 4)
        content_layout.addLayout(panels)
        lower = QHBoxLayout(); lower.setSpacing(12)
        health = QFrame(); health.setObjectName("panel"); health_layout = QVBoxLayout(health); health_layout.setContentsMargins(14, 14, 14, 14); health_layout.addWidget(label("HEALTH / LAST 30 MIN", 11, True)); bar = QProgressBar(); bar.setRange(0, 100); bar.setValue(98); bar.setTextVisible(False); health_layout.addWidget(bar); health_layout.addWidget(label("success / 98.2%     rebuilds / 2\nrolling, not retained", 11)); lower.addWidget(health, 3)
        events = QFrame(); events.setObjectName("panel"); ev = QVBoxLayout(events); ev.setContentsMargins(14, 14, 14, 14); ev.setSpacing(7); ev.addWidget(label("RECENT SIGNALS", 11, True));
        for text in ("14:30:04  amber  circuit rebuilt", "14:26:11  amber  2 stream failures", "14:18:22  green  bootstrap complete", "14:03:51  green  bridge transport healthy", "13:58:17  amber  consensus took 11.2s"):
            ev.addWidget(label(text, 11))
        lower.addWidget(events, 2); content_layout.addLayout(lower)
        body_layout.addWidget(content, 1); shell_layout.addWidget(body, 1)
        status = QFrame(); status.setObjectName("statusbar"); status_layout = QHBoxLayout(status); status_layout.setContentsMargins(12, 6, 12, 6); status_layout.addWidget(label("● CONNECTED TO TOR CONTROL PORT", 10)); status_layout.addStretch(); status_layout.addWidget(label("NO DESTINATIONS STORED", 10)); shell_layout.addWidget(status)
        outer.addWidget(shell, 1)

    def update_time(self):
        self.time_label.setText(datetime.now().strftime("%H:%M:%S"))

    def refresh(self):
        button = self.sender()
        button.setEnabled(False)
        button.setText("CHECKING…")
        QTimer.singleShot(500, lambda: (button.setText("REFRESH  ↻"), button.setEnabled(True)))

    def select_view(self, row: int):
        titles = ("Network at a glance", "Circuit inventory", "Stream assignments", "Signal log")
        if 0 <= row < len(titles):
            self.setWindowTitle(f"Tor Circuit Observatory — {titles[row]}")


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("Tor Circuit Observatory")
    app.setStyle("Fusion")
    palette = app.palette()
    palette.setColor(QPalette.ColorRole.Highlight, QColor(INK))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(LIGHT))
    palette.setColor(QPalette.ColorRole.Base, QColor(LIGHT))
    palette.setColor(QPalette.ColorRole.Button, QColor(LIGHT))
    app.setPalette(palette)
    app.setStyleSheet(STYLESHEET)
    window = Observatory(); window.show()
    return app.exec()


STYLESHEET = f"""
QWidget{{background:{PAPER};color:{INK};font-family:'{FONT}';}}
QMainWindow#observatory{{background:#51514e;}}
QFrame#menuBar,QFrame#titlebar,QFrame#toolbar,QFrame#statusbar{{background:{LIGHT};border:1px solid {INK};}}
QFrame#menuBar{{border-width:2px 2px 1px 2px;}}
QFrame#titlebar{{border-width:1px 2px 1px 2px;background:qlineargradient(y1:0,y2:1,stop:0 {LIGHT},stop:.5 {PAPER},stop:1 {LIGHT});}}
QFrame#toolbar{{border-width:0 2px 1px 2px;}}
QFrame#statusbar{{border-width:1px 2px 2px 2px;}}
QFrame#windowShell{{border:2px solid {INK};background:{PAPER};}}
QFrame#sidebar{{border-right:1px solid {INK};}}
QFrame#panel,QFrame#metric{{border:1px solid {INK};background:{LIGHT};}}
QFrame#metric{{border-width:1px 0 1px 1px;min-width:125px;}}
QFrame#metric:last-child{{border-right:1px solid {INK};}}
QPushButton{{background:{LIGHT};color:{INK};border:1px solid {INK};padding:6px 10px;font-weight:bold;}}
QPushButton:pressed{{background:{INK};color:{LIGHT};}}
QPushButton#menuButton{{border:0;padding:5px 9px;background:transparent;}}
QPushButton#menuButton[active="true"]{{background:{INK};color:{LIGHT};}}
QListWidget#tabs{{background:transparent;border:0;outline:0;}}
QListWidget#tabs::item{{padding:9px 5px;margin:2px 0;}}
QListWidget#tabs::item:selected{{background-color:{INK};color:{LIGHT};}}
QLabel#privacyNote{{border:1px solid {INK};padding:10px;background:{LIGHT};}}
QLabel#relay{{border:1px solid {MID};padding:4px;}}
QLabel[good="true"]{{color:{GREEN};}}
QProgressBar{{border:1px solid {INK};height:16px;background:{PAPER};text-align:center;}}
QProgressBar::chunk{{background-color:{GREEN};}}
QDialog{{background:{PAPER};border:2px solid {INK};}}
"""


if __name__ == "__main__":
    raise SystemExit(main())
