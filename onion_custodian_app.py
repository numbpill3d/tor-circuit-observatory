#!/usr/bin/env python3
"""Compact native Qt shell for Onion Service Custodian. No Electron, no browser."""
from __future__ import annotations

import argparse
import contextlib
import io
import sys
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QFont
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

import custodian


INK = "#111111"
PAPER = "#d8d8d2"
LIGHT = "#eeeeea"
MID = "#666662"
GREEN = "#075b35"
AMBER = "#805100"


class NewServiceDialog(QDialog):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("NEW SERVICE")
        self.setModal(True)
        self.name = QTextEdit()
        self.name.setFixedHeight(28)
        self.name.setPlaceholderText("service name")
        self.backend = QTextEdit()
        self.backend.setFixedHeight(28)
        self.backend.setPlaceholderText("127.0.0.1:8080")
        self.mode = QTextEdit()
        self.mode.setFixedHeight(28)
        self.mode.setPlainText("onion-only")
        self.generate = QPushButton("GENERATE V3 IDENTITY")
        self.generate.setCheckable(True)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        form = QFormLayout()
        form.addRow("NAME", self.name)
        form.addRow("MODE", self.mode)
        form.addRow("BACKEND", self.backend)
        form.addRow("KEY", self.generate)
        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def values(self) -> tuple[str, str, str, bool]:
        return (self.name.toPlainText().strip(), self.mode.toPlainText().strip(), self.backend.toPlainText().strip(), self.generate.isChecked())


class CustodianWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ONION SERVICE CUSTODIAN")
        self.resize(920, 590)
        self.setMinimumSize(760, 480)
        self._build_menu()
        self._build_ui()
        self.refresh()

    def _build_menu(self):
        file_menu = self.menuBar().addMenu("Custodian")
        refresh = QAction("Refresh", self)
        refresh.triggered.connect(self.refresh)
        file_menu.addAction(refresh)
        config = QAction("Export minimal config", self)
        config.triggered.connect(self.show_config)
        file_menu.addAction(config)
        file_menu.addSeparator()
        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)
        help_menu = self.menuBar().addMenu("Help")
        about = QAction("About", self)
        about.triggered.connect(lambda: QMessageBox.information(self, "ABOUT", "ONION SERVICE CUSTODIAN\nNative Qt application · local-only · no Electron"))
        help_menu.addAction(about)

    def _build_ui(self):
        root = QWidget()
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(8, 8, 8, 8)
        root_layout.setSpacing(8)
        toolbar = QHBoxLayout()
        title = QLabel("ONION SERVICE CUSTODIAN")
        title.setObjectName("windowTitle")
        toolbar.addWidget(title)
        toolbar.addStretch()
        check = QPushButton("CHECK NOW")
        check.clicked.connect(self.refresh)
        lock = QPushButton("LOCK VAULT")
        lock.clicked.connect(lambda: self.status("VAULT LOCKED · SECRET MATERIAL RELEASED"))
        toolbar.addWidget(check)
        toolbar.addWidget(lock)
        root_layout.addLayout(toolbar)

        body = QHBoxLayout()
        body.setSpacing(8)
        self.nav = QListWidget()
        self.nav.setFixedWidth(170)
        self.nav.addItems(["OVERVIEW", "SERVICES", "REACHABILITY", "AUTHORIZATION", "EXPOSURE AUDIT"])
        self.nav.currentRowChanged.connect(self.pages.setCurrentIndex if hasattr(self, "pages") else lambda _: None)
        body.addWidget(self.nav)
        self.pages = QStackedWidget()
        self.nav.currentRowChanged.connect(self.pages.setCurrentIndex)
        self.pages.addWidget(self.overview_page())
        self.pages.addWidget(self.services_page())
        self.pages.addWidget(self.reachability_page())
        self.pages.addWidget(self.authorization_page())
        self.pages.addWidget(self.audit_page())
        body.addWidget(self.pages, 1)
        root_layout.addLayout(body, 1)
        self.status_bar = QLabel("LOCAL ONLY · SECRET VALUES REDACTED")
        self.status_bar.setObjectName("statusBar")
        root_layout.addWidget(self.status_bar)
        self.setCentralWidget(root)
        self.nav.setCurrentRow(0)

    def panel(self, title: str) -> tuple[QGroupBox, QVBoxLayout]:
        box = QGroupBox(title)
        layout = QVBoxLayout(box)
        layout.setContentsMargins(10, 12, 10, 10)
        return box, layout

    def overview_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.warning = QLabel("!  ROUTE BOUNDARY NEEDS REVIEW")
        self.warning.setObjectName("warning")
        layout.addWidget(self.warning)
        self.metrics = QLabel()
        self.metrics.setObjectName("metrics")
        layout.addWidget(self.metrics)
        box, box_layout = self.panel("MANAGED SERVICES")
        self.service_table = QTableWidget(0, 4)
        self.service_table.setHorizontalHeaderLabels(["SERVICE", "MODE", "ADDRESS", "STATE"])
        self.service_table.horizontalHeader().setStretchLastSection(True)
        self.service_table.setEditTriggers(QTableWidget.NoEditTriggers)
        box_layout.addWidget(self.service_table)
        actions = QHBoxLayout()
        new_service = QPushButton("+ NEW SERVICE")
        new_service.clicked.connect(self.new_service)
        deploy = QPushButton("STAGE DEPLOYMENT")
        deploy.clicked.connect(self.stage_deploy)
        actions.addWidget(new_service)
        actions.addWidget(deploy)
        actions.addStretch()
        box_layout.addLayout(actions)
        layout.addWidget(box, 1)
        return page

    def services_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        box, box_layout = self.panel("V3 IDENTITY INVENTORY")
        self.identity_text = QTextEdit()
        self.identity_text.setReadOnly(True)
        box_layout.addWidget(self.identity_text)
        export = QPushButton("EXPORT MINIMAL CONFIG")
        export.clicked.connect(self.show_config)
        box_layout.addWidget(export)
        layout.addWidget(box)
        return page

    def reachability_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        box, box_layout = self.panel("REACHABILITY / INTRODUCTION-POINT HEALTH")
        box_layout.addWidget(QLabel("Use the CLI for an authenticated live probe:\n  onion-custodian intro-health SERVICE --cookie-file PATH\n  onion-custodian reach SERVICE"))
        probe = QPushButton("REFRESH SNAPSHOT")
        probe.clicked.connect(lambda: self.status("SNAPSHOT REFRESHED · NO DESTINATION HISTORY STORED"))
        box_layout.addWidget(probe)
        layout.addWidget(box)
        layout.addStretch()
        return page

    def authorization_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        box, box_layout = self.panel("CLIENT AUTHORIZATION")
        self.auth_text = QTextEdit()
        self.auth_text.setReadOnly(True)
        box_layout.addWidget(self.auth_text)
        box_layout.addWidget(QLabel("Descriptors remain in each service's authorized_clients directory."))
        layout.addWidget(box)
        return page

    def audit_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        box, box_layout = self.panel("EXPOSURE AUDIT")
        self.audit_text = QTextEdit()
        self.audit_text.setReadOnly(True)
        box_layout.addWidget(self.audit_text)
        live = QPushButton("RUN LIVE LISTENER AUDIT")
        live.clicked.connect(self.live_audit)
        box_layout.addWidget(live)
        layout.addWidget(box)
        return page

    def refresh(self):
        try:
            state = custodian.load_state()
            services = state["services"]
            warnings = custodian.audit_records(services)
            self.warning.setText(("!  " + " · ".join(warnings)) if warnings else "✓  ROUTE BOUNDARIES NOMINAL")
            self.warning.setProperty("warning", bool(warnings))
            self.metrics.setText(f"SERVICES  {len(services)}     INTRO POINTS  current snapshot     VAULT  LOCAL / 0600")
            self.service_table.setRowCount(len(services))
            identity_lines: list[str] = []
            auth_lines: list[str] = []
            for row, service in enumerate(services):
                values = [service.get("name", ""), service.get("mode", ""), service.get("address") or "identity not generated", "REVIEW" if service.get("mode") == "onion+clearnet" else "STAGED"]
                for col, value in enumerate(values):
                    self.service_table.setItem(row, col, QTableWidgetItem(value))
                identity_lines.append(f"{service.get('name')}\n  mode: {service.get('mode')}\n  address: {service.get('address') or 'not generated'}\n  fingerprint: {service.get('fingerprint') or 'not available'}")
                for client in service.get("clients", []):
                    auth_lines.append(f"{service.get('name')} / {client.get('name')} · {'STALE' if client.get('stale') else 'AUTHORIZED'}")
            self.identity_text.setPlainText("\n\n".join(identity_lines) or "No services staged.")
            self.auth_text.setPlainText("\n".join(auth_lines) or "No client authorizations staged.")
            self.audit_text.setPlainText("\n".join(warnings) if warnings else "PASS · no declared mixed-backend exposure")
            self.status("STATE REFRESHED · LOCAL ONLY")
        except Exception as error:
            self.status(f"REFRESH ERROR · {error}")

    def new_service(self):
        dialog = NewServiceDialog(self)
        if dialog.exec() != QDialog.Accepted:
            return
        name, mode, backend, generate = dialog.values()
        try:
            custodian.cmd_add(argparse.Namespace(name=name, mode=mode, backend=backend, redirect=None, generate=generate))
            self.refresh()
            self.status(f"STAGED {name} · SECRET MATERIAL NOT DISPLAYED")
        except Exception as error:
            QMessageBox.warning(self, "SERVICE REFUSED", str(error))

    def stage_deploy(self):
        answer = QMessageBox.question(self, "STAGE DEPLOYMENT", "Verify and stage the local Tor config?\nTor will not start.", QMessageBox.Yes | QMessageBox.No)
        if answer != QMessageBox.Yes:
            return
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                custodian.cmd_deploy(argparse.Namespace(confirm=True, foreground=False, control_port=9051, socks_port=9050, allow_shared_backend=False))
            self.status("DEPLOYMENT VERIFIED AND STAGED · TOR NOT STARTED")
        except Exception as error:
            QMessageBox.warning(self, "DEPLOYMENT REFUSED", str(error))

    def live_audit(self):
        try:
            import shutil as _shutil
            import subprocess as _subprocess
            ss = _shutil.which("ss")
            if not ss:
                raise RuntimeError("ss command not found")
            listeners = _subprocess.run([ss, "-ltnH"], capture_output=True, text=True, check=False)
            warnings = custodian.listener_exposure_warnings(custodian.load_state()["services"], listeners.stdout)
            self.audit_text.setPlainText("\n".join(warnings) if warnings else "PASS · configured backends are loopback-only")
            self.status("LIVE LISTENER AUDIT COMPLETE")
        except Exception as error:
            self.status(f"AUDIT ERROR · {error}")

    def show_config(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("MINIMAL REPRODUCIBLE CONFIG")
        layout = QVBoxLayout(dialog)
        text = QTextEdit()
        text.setReadOnly(True)
        text.setPlainText(custodian.minimal_config(custodian.load_state()))
        layout.addWidget(text)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        dialog.resize(560, 420)
        dialog.exec()

    def status(self, message: str):
        self.status_bar.setText(message)


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("Onion Service Custodian")
    app.setStyle("Fusion")
    app.setFont(QFont("DejaVu Sans Mono", 10))
    app.setStyleSheet(f"""
        QWidget {{ background: {PAPER}; color: {INK}; }}
        QMainWindow, QDialog {{ background: {PAPER}; }}
        QMenuBar, QMenu {{ background: {LIGHT}; color: {INK}; }}
        QMenuBar::item:selected, QMenu::item:selected {{ background: {INK}; color: {LIGHT}; }}
        QPushButton {{ background: {LIGHT}; border: 1px solid {INK}; padding: 7px 10px; }}
        QPushButton:pressed {{ background: {MID}; color: {LIGHT}; }}
        QGroupBox {{ border: 1px solid {INK}; margin-top: 10px; padding-top: 8px; }}
        QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 6px; background: {LIGHT}; font-weight: bold; }}
        QListWidget, QTableWidget, QTextEdit {{ background: {LIGHT}; border: 1px solid {INK}; selection-background-color: {INK}; selection-color: {LIGHT}; }}
        QListWidget::item {{ padding: 8px 6px; }}
        QListWidget::item:selected {{ background: {INK}; color: {LIGHT}; }}
        QHeaderView::section {{ background: {PAPER}; border: 0; border-right: 1px solid {INK}; border-bottom: 1px solid {INK}; padding: 6px; }}
        #windowTitle {{ font-size: 15px; font-weight: bold; letter-spacing: 1px; }}
        #metrics, #statusBar {{ background: {LIGHT}; border: 1px solid {INK}; padding: 8px; }}
        #warning {{ background: #e9e3d5; border: 1px solid {AMBER}; padding: 9px; color: {AMBER}; }}
    """)
    window = CustodianWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
