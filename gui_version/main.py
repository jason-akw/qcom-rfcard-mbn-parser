from __future__ import annotations

import argparse
import re
import sys
import threading
import traceback
from pathlib import Path
from typing import Any, Sequence

import qualcomm_rf_combo_analyzer as analyzer

VERSION = analyzer.VERSION
TABLE_DISPLAY = analyzer.TABLE_DISPLAY
ModuleRecord = analyzer.ModuleRecord
ToolError = analyzer.ToolError
scan_source = analyzer.scan_source
export_many = analyzer.export_many
write_comparison_reports = analyzer.write_comparison_reports


class ExtractorGUI:
    def __init__(self) -> None:
        import tkinter as tk
        from tkinter import ttk

        self.tk = tk
        self.ttk = ttk
        self.root = tk.Tk()
        self.root.title(f"qcom-rfcard-mbn-parser GUI {VERSION}")
        self.root.geometry("900x720")
        self.root.minsize(900, 400)

        self.source: Path | None = None  # most recently imported source
        self.imported_sources: list[Path] = []
        self.records: list[ModuleRecord] = []
        self.visible_by_iid: dict[str, ModuleRecord] = {}
        self.checked_keys: set[str] = set()
        self.busy = False

        self.source_var = tk.StringVar(value="No imports")
        self.status_var = tk.StringVar(value="Import a modem.img or RF MBN to begin.")
        self.format_vars = {
            "mbn": tk.BooleanVar(value=True),
            "json": tk.BooleanVar(value=False),
            "csv": tk.BooleanVar(value=False),
            "b0cd": tk.BooleanVar(value=False),
            "b826": tk.BooleanVar(value=False),
        }

        outer = ttk.Frame(self.root, padding=12)
        outer.pack(fill="both", expand=True)

        top = ttk.Frame(outer)
        top.pack(fill="x", pady=(0, 10))
        self.import_button = ttk.Button(top, text="Import .img or .mbn", command=self.choose_source)
        self.import_button.pack(side="left")
        ttk.Label(top, textvariable=self.source_var).pack(
            side="left", fill="x", expand=True, padx=(12, 12)
        )
        self.clear_imports_button = ttk.Button(
            top,
            text="Clear imports",
            command=self.clear_imports,
            state="disabled",
        )
        self.clear_imports_button.pack(side="right")

        tree_frame = ttk.Frame(outer)
        tree_frame.pack(fill="both", expand=True)
        columns = ("extract", "generation", "identity", "size", "lte", "nr", "path")
        self.tree = ttk.Treeview(
            tree_frame, columns=columns, show="headings", selectmode="browse"
        )
        headings = {
            "generation": "Format",
            "identity": "HWID_FSID_BID",
            "size": "Size",
            "lte": "LTE combos",
            "nr": "NR combos",
            "path": "Path inside image",
            "extract": "Extract",
        }
        widths = {
            "extract": 70,
            "generation": 120,
            "identity": 145,
            "size": 95,
            "lte": 90,
            "nr": 140,
            "path": 620,
        }
        for column in columns:
            self.tree.heading(column, text=headings[column])
            self.tree.column(
                column,
                width=widths[column],
                anchor="center" if column in {"extract", "generation", "identity", "size", "lte", "nr"} else "w",
                stretch=column == "path",
            )
        y_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        x_scroll = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        self.tree.bind("<Button-1>", self.toggle_checkbox)
        self.tree.bind("<space>", self.toggle_selected_row)
        self.tree.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        export_row = ttk.LabelFrame(outer, text="Export formats", padding=10)
        export_row.pack(fill="x", pady=(10, 8))
        labels = {
            "mbn": "MBN dump",
            "json": "JSON",
            "csv": "CSV",
            "b0cd": "0xB0CD (LTE)",
            "b826": "0xB826 (NR)",
        }
        for key in ("mbn", "json", "csv", "b0cd", "b826"):
            ttk.Checkbutton(
                export_row,
                text=labels[key],
                variable=self.format_vars[key],
            ).pack(side="left", padx=(0, 16))

        # Selection buttons
        selection_frame = ttk.Frame(export_row)
        selection_frame.pack(side="right", padx=(12, 0))

        BUTTON_WIDTH = 12

        ttk.Button(
            selection_frame,
            text="Deselect all",
            width=BUTTON_WIDTH,
            command=self.clear_selection,
        ).pack(side="left")

        ttk.Button(
            selection_frame,
            text="Select all",
            width=BUTTON_WIDTH,
            command=self.select_all,
        ).pack(side="left", padx=(8, 0))

        self.compare_button = ttk.Button(
            selection_frame,
            text="Compare",
            command=self.choose_compare,
        )
        self.compare_button.pack(side="right", padx=(20, 0))

        self.export_button = ttk.Button(
            selection_frame,
            text="Export",
            command=self.choose_export,
        )
        self.export_button.pack(side="right", padx=(8, 0))

        ttk.Label(outer, textvariable=self.status_var).pack(fill="x")
        self.log = tk.Text(outer, height=7, wrap="word", state="disabled")
        self.log.pack(fill="x", pady=(5, 0))

    def append_log(self, message: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", message.rstrip() + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def set_busy(self, value: bool, message: str | None = None) -> None:
        self.busy = value
        state = "disabled" if value else "normal"
        self.import_button.configure(state=state)
        self.export_button.configure(state=state)
        self.compare_button.configure(state=state)
        self.clear_imports_button.configure(
            state="disabled" if value or not self.records else "normal"
        )
        if message:
            self.status_var.set(message)
        self.root.configure(cursor="watch" if value else "")

    @staticmethod
    def _record_key(record: ModuleRecord) -> str:
        # Deduplicate by file name and SHA-256 hash so the same content is not
        # shown again when it is extracted from different scratch directories or
        # imported more than once in the same session.
        digest = record.sha256 or ""
        return f"{record.name}\0{digest}"

    def _update_source_label(self) -> None:
        count = len(self.imported_sources)
        if count == 0:
            self.source_var.set("No imports")
        elif count == 1:
            self.source_var.set(str(self.imported_sources[0]))
        else:
            self.source_var.set(
                f"{self.imported_sources[-1]}"
            )

    def choose_source(self) -> None:
        from tkinter import filedialog

        filenames = filedialog.askopenfilenames(
            title="Choose Qualcomm modem images or RF MBNs",
            filetypes=(
                (
                    "Modem images, archives, and MBNs",
                    "*.img *.bin *.mbn *.gz *.xz *.zst *.zip *.tar *.tar.md5 *.tgz *.lz4 *.7z",
                ),
                ("MBN files", "*.mbn"),
                ("Modem images and archives", "*.img *.bin *.gz *.xz *.zst *.zip *.tar *.tar.md5 *.tgz *.lz4 *.7z"),
                ("All files", "*.*"),
            ),
        )
        if not filenames:
            return

        sources = [Path(filename).resolve() for filename in filenames]

        self.set_busy(
            True,
            f"Scanning {len(sources)} selected source(s)…",
        )

        for source in sources:
            self.append_log(f"Scanning {source}")

        def work() -> None:
            results: list[tuple[Path, list[ModuleRecord]]] = []
            failures: list[tuple[Path, str]] = []

            for source in sources:
                try:
                    records = scan_source(source)
                    results.append((source, records))
                except Exception:
                    failures.append((source, traceback.format_exc()))

            self.root.after(
                0,
                lambda: self.multi_scan_finished(results, failures),
            )

        threading.Thread(target=work, daemon=True).start()

    def multi_scan_finished(
        self,
        results: list[tuple[Path, list[ModuleRecord]]],
        failures: list[tuple[Path, str]],
    ) -> None:
        from tkinter import messagebox

        existing_keys = {
            self._record_key(record)
            for record in self.records
        }

        total_found = 0
        total_added = 0
        total_duplicates = 0

        for source, records in results:
            total_found += len(records)
            added_from_source = 0

            for record in records:
                key = self._record_key(record)

                if key in existing_keys:
                    total_duplicates += 1
                    continue

                existing_keys.add(key)
                self.records.append(record)
                self.checked_keys.add(key)
                total_added += 1
                added_from_source += 1

            if source not in self.imported_sources:
                self.imported_sources.append(source)

            self.append_log(
                f"Added {added_from_source} candidate RF MBN(s) "
                f"from {source.name}."
            )

        for source, error in failures:
            final_line = error.strip().splitlines()[-1]
            self.append_log(f"Failed to scan {source}: {final_line}")

        self._update_source_label()
        self.refresh_tree()

        self.set_busy(
            False,
            f"Added {total_added} MBN(s) from {len(results)} source(s); "
            f"{len(self.records)} total imported.",
        )

        if total_duplicates:
            self.append_log(
                f"Skipped {total_duplicates} duplicate MBN row(s)."
            )

        if failures:
            messagebox.showwarning(
                "Some imports failed",
                f"Successfully scanned {len(results)} source(s).\n"
                f"Failed to scan {len(failures)} source(s).\n\n"
                "See the log for details.",
            )
    def multi_scan_finished(
        self,
        results: list[tuple[Path, list[ModuleRecord]]],
        failures: list[tuple[Path, str]],
    ) -> None:
        from tkinter import messagebox

        existing_keys = {
            self._record_key(record)
            for record in self.records
        }

        total_found = 0
        total_added = 0
        total_duplicates = 0

        for source, records in results:
            total_found += len(records)
            added_from_source = 0

            for record in records:
                key = self._record_key(record)

                if key in existing_keys:
                    total_duplicates += 1
                    continue

                existing_keys.add(key)
                self.records.append(record)
                self.checked_keys.add(key)
                total_added += 1
                added_from_source += 1

            if source not in self.imported_sources:
                self.imported_sources.append(source)

            self.append_log(
                f"Added {added_from_source} candidate RF MBN(s) "
                f"from {source.name}."
            )

        for source, error in failures:
            final_line = error.strip().splitlines()[-1]
            self.append_log(f"Failed to scan {source}: {final_line}")

        self._update_source_label()
        self.refresh_tree()

        self.set_busy(
            False,
            f"Added {total_added} MBN(s) from {len(results)} source(s); "
            f"{len(self.records)} total imported.",
        )

        if total_duplicates:
            self.append_log(
                f"Skipped {total_duplicates} duplicate MBN row(s)."
            )

        if failures:
            messagebox.showwarning(
                "Some imports failed",
                f"Successfully scanned {len(results)} source(s).\n"
                f"Failed to scan {len(failures)} source(s).\n\n"
                "See the log for details.",
            )

        def work() -> None:
            try:
                records = scan_source(source)
            except Exception:
                error = traceback.format_exc()
                self.root.after(0, lambda: self.scan_failed(error))
                return
            self.root.after(0, lambda: self.scan_finished(source, records))

        threading.Thread(target=work, daemon=True).start()

    def scan_failed(self, error: str) -> None:
        from tkinter import messagebox

        self.set_busy(False, "Scan failed.")
        self.append_log(error)
        messagebox.showerror("Scan failed", error.splitlines()[-1])

    def scan_finished(self, source: Path, records: list[ModuleRecord]) -> None:
        existing_keys = {self._record_key(record) for record in self.records}
        added: list[ModuleRecord] = []
        for record in records:
            key = self._record_key(record)
            if key in existing_keys:
                continue
            existing_keys.add(key)
            self.records.append(record)
            self.checked_keys.add(key)
            added.append(record)

        if source not in self.imported_sources:
            self.imported_sources.append(source)
        self._update_source_label()
        self.refresh_tree()
        self.set_busy(
            False,
            f"Added {len(added)} MBN(s); {len(self.records)} total imported.",
        )
        if len(added) == len(records):
            self.append_log(
                f"Added {len(added)} candidate RF MBN(s) from {source.name}."
            )
        else:
            skipped = len(records) - len(added)
            self.append_log(
                f"Added {len(added)} candidate RF MBN(s) from {source.name}; "
                f"skipped {skipped} duplicate(s)."
            )

    def clear_imports(self) -> None:
        if self.busy:
            return
        self.source = None
        self.imported_sources.clear()
        self.records.clear()
        self.visible_by_iid.clear()
        self.checked_keys.clear()
        self.refresh_tree()
        self._update_source_label()
        self.status_var.set("Imports cleared. Import a modem.img or RF MBN to begin.")
        self.clear_imports_button.configure(state="disabled")
        self.append_log("Cleared all imported sources and MBN rows.")

    def refresh_tree(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self.visible_by_iid.clear()
        for index, record in enumerate(self.records):
            iid = f"module-{index}"
            self.visible_by_iid[iid] = record
            self.tree.insert(
                "",
                "end",
                iid=iid,
                values=(
                    "☑" if self._record_key(record) in self.checked_keys else "☐",
                    {"DAT/protobuf": "XML DAT"}.get(record.generation, record.generation),
                    record.identity,
                    f"{record.size / 1024:,.1f} KB",
                    str(record.lte_combos) if record.lte_combos >= 0 else "—",
                    record.nr_combos,
                    f"{record.inner_path}"
                    if record.source_path else record.inner_path,
                ),
            )

    def _toggle_iid(self, iid: str) -> None:
        record = self.visible_by_iid.get(iid)
        if record is None:
            return
        key = self._record_key(record)
        if key in self.checked_keys:
            self.checked_keys.remove(key)
        else:
            self.checked_keys.add(key)
        values = list(self.tree.item(iid, "values"))
        values[0] = "☑" if key in self.checked_keys else "☐"
        self.tree.item(iid, values=values)

    def toggle_checkbox(self, event: Any) -> None:
        region = self.tree.identify_region(event.x, event.y)
        column = self.tree.identify_column(event.x)
        iid = self.tree.identify_row(event.y)
        if region == "cell" and column == "#1" and iid:
            self._toggle_iid(iid)
            return "break"
        return None

    def toggle_selected_row(self, _event: Any = None) -> str:
        selection = self.tree.selection()
        if selection:
            self._toggle_iid(selection[0])
        return "break"

    def select_all(self) -> None:
        self.checked_keys = {self._record_key(record) for record in self.records}
        self.refresh_tree()

    def clear_selection(self) -> None:
        self.checked_keys.clear()
        self.refresh_tree()

    def choose_compare(self) -> None:
        from tkinter import filedialog, messagebox

        if not self.records:
            messagebox.showwarning("No imports", "Import a modem image or RF MBN first.")
            return
        selected = [
            record for record in self.records
            if self._record_key(record) in self.checked_keys
        ]
        if len(selected) < 2:
            messagebox.showwarning(
                "Not enough MBNs",
                "Check at least two MBNs in the Extract column.",
            )
            return
        directory = filedialog.askdirectory(
            title="Choose comparison report directory"
        )
        if not directory:
            return
        output = Path(directory)
        reference = selected[0]
        self.set_busy(
            True,
            f"Comparing {len(selected)} MBN(s); reference: {reference.name}…",
        )
        self.append_log(
            f"Comparing {len(selected)} MBN(s); reference is {reference.name}"
        )

        def progress(message: str) -> None:
            self.root.after(0, lambda: self.append_log(message))

        def work() -> None:
            try:
                reports = write_comparison_reports(
                    Path(selected[0].source_path),
                    selected,
                    output,
                    progress,
                )
            except Exception:
                error = traceback.format_exc()
                self.root.after(0, lambda: self.compare_failed(error))
                return
            self.root.after(
                0,
                lambda: self.compare_finished(output, reports, len(selected)),
            )

        threading.Thread(target=work, daemon=True).start()

    def compare_failed(self, error: str) -> None:
        from tkinter import messagebox

        self.set_busy(False, "Comparison failed.")
        self.append_log(error)
        messagebox.showerror("Comparison failed", error.splitlines()[-1])

    def compare_finished(
        self,
        output: Path,
        reports: tuple[Path, Path],
        count: int,
    ) -> None:
        from tkinter import messagebox

        self.set_busy(False, f"Compared {count} MBN(s); reports written to {output}")
        messagebox.showinfo(
            "Comparison complete",
            f"Compared {count} MBN(s).\\n\\n"
            f"LTE report: {reports[0].name}\\n"
            f"NR report: {reports[1].name}\\n\\n"
            f"{output}",
        )

    def choose_export(self) -> None:
        from tkinter import filedialog, messagebox

        if not self.records:
            messagebox.showwarning("No imports", "Import a modem image or RF MBN first.")
            return
        selected = [
            record for record in self.records
            if self._record_key(record) in self.checked_keys
        ]
        if not selected:
            messagebox.showwarning("No MBN selected", "Check at least one MBN in the Extract column.")
            return
        formats = {key for key, variable in self.format_vars.items() if variable.get()}
        if not formats:
            messagebox.showwarning("No format", "Tick at least one export format.")
            return
        directory = filedialog.askdirectory(title="Choose export directory")
        if not directory:
            return
        output = Path(directory)
        self.set_busy(True, f"Exporting {len(selected)} MBN(s)…")
        self.append_log(f"Exporting to {output}")

        def progress(message: str) -> None:
            self.root.after(0, lambda: self.append_log(message))

        def work() -> None:
            try:
                summaries = export_many(
                    Path(selected[0].source_path), selected, output, formats, progress
                )
            except Exception:
                error = traceback.format_exc()
                self.root.after(0, lambda: self.export_failed(error))
                return
            self.root.after(0, lambda: self.export_finished(output, summaries))

        threading.Thread(target=work, daemon=True).start()

    def export_failed(self, error: str) -> None:
        from tkinter import messagebox

        self.set_busy(False, "Export failed.")
        self.append_log(error)
        messagebox.showerror("Export failed", error.splitlines()[-1])

    def export_finished(self, output: Path, summaries: list[dict[str, Any]]) -> None:
        from tkinter import messagebox

        self.set_busy(False, f"Exported {len(summaries)} MBN(s) to {output}")
        messagebox.showinfo(
            "Export complete",
            f"Exported {len(summaries)} MBN(s).\n\n{output}",
        )

    def run(self) -> None:
        self.root.mainloop()


def build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan and export Qualcomm legacy and DAT/protobuf RF combinations."
    )
    parser.add_argument(
        "source",
        nargs="?",
        type=Path,
        help="FAT16 modem.img or a directly named RF MBN",
    )
    parser.add_argument("--list", action="store_true", help="list candidate MBNs")
    parser.add_argument("-o", "--output", type=Path, help="export directory")
    parser.add_argument(
        "--match",
        default=".*",
        help="regular expression matched against MBN name and inner path",
    )
    parser.add_argument(
        "--formats",
        nargs="+",
        choices=("mbn", "json", "csv", "b0cd", "b826"),
        default=("json", "csv", "b0cd", "b826"),
    )
    parser.add_argument("--version", action="version", version=VERSION)
    return parser


def cli_main(argv: Sequence[str] | None = None) -> int:
    args = build_cli().parse_args(argv)
    if args.source is None:
        ExtractorGUI().run()
        return 0
    try:
        records = scan_source(args.source)
        matcher = re.compile(args.match, re.IGNORECASE)
        records = [
            record
            for record in records
            if matcher.search(f"{record.name} {record.inner_path}")
        ]
        if args.list or args.output is None:
            for record in records:
                print(
                    f"{record.generation:12} {record.identity:14} "
                    f"{record.size:10}  {record.inner_path}"
                )
            if args.output is None:
                return 0
        if not records:
            raise ToolError("No candidate RF MBN matched the selection")
        export_many(
            args.source,
            records,
            args.output,
            set(args.formats),
            print,
        )
        return 0
    except (OSError, ToolError, ValueError, analyzer.ParseError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(cli_main())

