"""PySide6 local operator control room."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from .cli import default_data, initialize, submit_spec
from .store import Store


def main() -> int:
    from PySide6.QtCore import QProcess, QTimer
    from PySide6.QtWidgets import (
        QApplication, QFileDialog, QHBoxLayout, QLabel, QMainWindow, QMessageBox,
        QPlainTextEdit, QProgressBar, QPushButton, QTableWidget, QTableWidgetItem,
        QTabWidget, QVBoxLayout, QWidget,
    )

    class Window(QMainWindow):
        def __init__(self) -> None:
            super().__init__()
            self.data = default_data()
            initialize(self.data)
            self.store = Store(self.data)
            self.hub = QProcess(self)
            self.demo = QProcess(self)
            self.setWindowTitle("Heterogeneous Worker Control Plane")
            self.resize(1050, 700)

            root = QWidget()
            layout = QVBoxLayout(root)
            self.summary = QLabel()
            self.progress = QProgressBar()
            self.progress.setRange(0, 1)
            layout.addWidget(self.summary)
            layout.addWidget(self.progress)

            actions = QHBoxLayout()
            for label, slot in (
                ("Start hub", self.start_hub), ("Stop hub", self.stop_hub),
                ("Submit job", self.submit_job), ("Cancel selected", self.cancel_selected),
                ("Run synthetic demo", self.run_demo), ("Refresh", self.refresh),
            ):
                button = QPushButton(label)
                button.clicked.connect(slot)
                actions.addWidget(button)
            layout.addLayout(actions)

            tabs = QTabWidget()
            self.jobs = QTableWidget(0, 7)
            self.jobs.setHorizontalHeaderLabels(["ID", "Name", "State", "Worker", "Attempt", "Phase", "Reason"])
            self.workers = QTableWidget(0, 7)
            self.workers.setHorizontalHeaderLabels(["ID", "Platform", "Arch", "State", "CPU", "RAM free MB", "Disk free MB"])
            self.output = QPlainTextEdit()
            self.output.setReadOnly(True)
            tabs.addTab(self.jobs, "Jobs")
            tabs.addTab(self.workers, "Workers")
            tabs.addTab(self.output, "Status and errors")
            layout.addWidget(tabs)
            self.setCentralWidget(root)

            self.hub.setProgram(sys.executable)
            self.hub.setArguments(["-m", "hwcp.cli", "--data", str(self.data), "serve"])
            self.hub.readyReadStandardOutput.connect(lambda: self._read(self.hub, False))
            self.hub.readyReadStandardError.connect(lambda: self._read(self.hub, True))
            self.hub.finished.connect(lambda code, _: self._line(f"Hub exited with code {code}"))
            self.demo.setProgram(sys.executable)
            self.demo.setArguments(["-m", "hwcp.cli", "demo"])
            self.demo.readyReadStandardOutput.connect(lambda: self._read(self.demo, False))
            self.demo.readyReadStandardError.connect(lambda: self._read(self.demo, True))
            self.demo.finished.connect(lambda code, _: self._line(f"Demo exited with code {code}"))

            self.timer = QTimer(self)
            self.timer.timeout.connect(self.refresh)
            self.timer.start(1000)
            self.refresh()

        def _line(self, value: str) -> None:
            self.output.appendPlainText(value.rstrip())

        def _read(self, process: QProcess, error: bool) -> None:
            data = process.readAllStandardError() if error else process.readAllStandardOutput()
            if data:
                self._line(bytes(data).decode("utf-8", "replace"))

        def start_hub(self) -> None:
            if self.hub.state() == QProcess.ProcessState.NotRunning:
                self._line("Starting loopback hub on port 8789…")
                self.hub.start()

        def stop_hub(self) -> None:
            if self.hub.state() != QProcess.ProcessState.NotRunning:
                self._line("Stopping hub…")
                self.hub.terminate()
                if not self.hub.waitForFinished(3000):
                    self.hub.kill()

        def submit_job(self) -> None:
            path, _ = QFileDialog.getOpenFileName(self, "Submit bounded job JSON", "", "JSON (*.json)")
            if not path:
                return
            try:
                job = submit_spec(self.store, Path(path))
                self._line(f"Queued {job['id']}: {job['name']}")
                self.refresh()
            except Exception as exc:
                QMessageBox.critical(self, "Job rejected", str(exc))

        def selected_job(self) -> str | None:
            row = self.jobs.currentRow()
            return None if row < 0 else self.jobs.item(row, 0).text()

        def cancel_selected(self) -> None:
            job_id = self.selected_job()
            if not job_id:
                QMessageBox.information(self, "Select a job", "Select a queued or active job first.")
                return
            try:
                self.store.cancel(job_id)
                self._line(f"Cancellation requested for {job_id}")
                self.refresh()
            except Exception as exc:
                QMessageBox.critical(self, "Cancellation rejected", str(exc))

        def run_demo(self) -> None:
            if self.demo.state() == QProcess.ProcessState.NotRunning:
                self._line("Running isolated synthetic end-to-end demo…")
                self.demo.start()

        def refresh(self) -> None:
            try:
                status = self.store.status()
            except Exception as exc:
                self.summary.setText(f"State error: {exc}")
                return
            counts = status["job_counts"]
            self.summary.setText(
                f"Hub: {'running' if self.hub.state() != QProcess.ProcessState.NotRunning else 'stopped'}   "
                f"Workers: {len(status['workers'])}   Jobs: {len(status['jobs'])}   "
                + "  ".join(f"{key}={value}" for key, value in sorted(counts.items()))
            )
            active = [job for job in status["jobs"] if job["state"] == "active"]
            if active and active[0]["progress"].get("total") is not None:
                self.progress.setRange(0, max(1, int(active[0]["progress"]["total"])))
                self.progress.setValue(int(active[0]["progress"]["completed"]))
                self.progress.setFormat(active[0]["progress"]["phase"] + " %v/%m")
            elif active:
                self.progress.setRange(0, 0)
                self.progress.setFormat(active[0]["progress"]["phase"])
            else:
                self.progress.setRange(0, 1)
                self.progress.setValue(1)
                self.progress.setFormat("No active job")
            self.jobs.setRowCount(len(status["jobs"]))
            for row, job in enumerate(sorted(status["jobs"], key=lambda item: item["created_at"], reverse=True)):
                values = [job["id"], job["name"], job["state"], job.get("worker_id") or "—", str(job["attempts"]), job["progress"]["phase"], job.get("last_error") or ""]
                for column, value in enumerate(values):
                    self.jobs.setItem(row, column, QTableWidgetItem(value))
            self.workers.setRowCount(len(status["workers"]))
            for row, worker in enumerate(sorted(status["workers"], key=lambda item: item["id"])):
                resources = worker["resources"]
                values = [worker["id"], worker["platform"], worker["architecture"], worker["state"], str(int(resources["cpu_count"])), f"{resources['ram_available_mb']:.0f}", f"{resources['disk_free_mb']:.0f}"]
                for column, value in enumerate(values):
                    self.workers.setItem(row, column, QTableWidgetItem(value))

        def closeEvent(self, event) -> None:  # type: ignore[no-untyped-def]
            self.stop_hub()
            if self.demo.state() != QProcess.ProcessState.NotRunning:
                self.demo.terminate()
                self.demo.waitForFinished(2000)
            event.accept()

    app = QApplication(sys.argv)
    window = Window()
    window.show()
    if os.environ.get("HWCP_GUI_SMOKE") == "1":
        QTimer.singleShot(100, app.quit)
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
