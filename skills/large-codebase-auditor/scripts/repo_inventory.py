#!/usr/bin/env python3
"""为大型代码库审查任务概览仓库结构。"""

from __future__ import annotations

import argparse
import os
from collections import Counter
from pathlib import Path

DEFAULT_EXCLUDES = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    "__pycache__",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "target",
    ".next",
    ".turbo",
    ".venv",
    "venv",
    "coverage",
}

LANGUAGE_BY_EXTENSION = {
    ".c": "C",
    ".cc": "C++",
    ".cpp": "C++",
    ".cs": "C#",
    ".css": "CSS",
    ".go": "Go",
    ".h": "C/C++ Header",
    ".hpp": "C++ Header",
    ".html": "HTML",
    ".java": "Java",
    ".js": "JavaScript",
    ".json": "JSON",
    ".kt": "Kotlin",
    ".m": "Objective-C",
    ".md": "Markdown",
    ".php": "PHP",
    ".py": "Python",
    ".rb": "Ruby",
    ".rs": "Rust",
    ".sh": "Shell",
    ".sql": "SQL",
    ".swift": "Swift",
    ".toml": "TOML",
    ".ts": "TypeScript",
    ".tsx": "TSX",
    ".txt": "Text",
    ".xml": "XML",
    ".yaml": "YAML",
    ".yml": "YAML",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="概览仓库规模、文件类型和高密度目录。",
    )
    parser.add_argument("root", nargs="?", default=".", help="仓库根目录")
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="每个汇总区块展示的行数",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="在默认排除目录之外额外排除的目录名",
    )
    return parser.parse_args()


def iter_files(root: Path, excluded_names: set[str]):
    for current_root, dir_names, file_names in os.walk(root, topdown=True):
        dir_names[:] = [
            dir_name for dir_name in dir_names if dir_name not in excluded_names
        ]
        current_root_path = Path(current_root)
        for file_name in file_names:
            path = current_root_path / file_name
            if path.is_file():
                yield path


def normalize_relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def summarize(root: Path, top_n: int, excluded_names: set[str]) -> str:
    extension_counts: Counter[str] = Counter()
    language_counts: Counter[str] = Counter()
    directory_counts: Counter[str] = Counter()
    largest_files: list[tuple[int, str]] = []
    total_files = 0
    total_bytes = 0

    for path in iter_files(root, excluded_names):
        total_files += 1
        size = path.stat().st_size
        total_bytes += size

        suffix = path.suffix.lower() or "<no-ext>"
        extension_counts[suffix] += 1
        language_counts[LANGUAGE_BY_EXTENSION.get(path.suffix.lower(), "Other")] += 1

        relative_path = normalize_relative(path, root)
        directory = str(Path(relative_path).parent)
        directory_counts[directory] += 1

        largest_files.append((size, relative_path))

    largest_files.sort(reverse=True)
    largest_files = largest_files[:top_n]

    lines = [
        f"根目录: {root.resolve()}",
        f"文件数: {total_files}",
        f"总大小: {format_size(total_bytes)}",
        "",
        f"语言分布前 {top_n} 项",
    ]
    lines.extend(render_counter(language_counts, top_n))
    lines.extend(["", f"扩展名前 {top_n} 项"])
    lines.extend(render_counter(extension_counts, top_n))
    lines.extend(["", f"文件最密集目录前 {top_n} 项"])
    lines.extend(render_counter(directory_counts, top_n))
    lines.extend(["", f"最大文件前 {top_n} 项"])
    lines.extend(
        f"{format_size(size):>8}  {path}" for size, path in largest_files
    )
    return "\n".join(lines)


def render_counter(counter: Counter[str], top_n: int) -> list[str]:
    if not counter:
        return ["(无)"]
    width = len(str(counter.most_common(1)[0][1]))
    return [
        f"{count:>{width}}  {name}"
        for name, count in counter.most_common(top_n)
    ]


def format_size(size: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)}{unit}"
            return f"{value:.1f}{unit}"
        value /= 1024
    return f"{size}B"


def main() -> int:
    args = parse_args()
    root = Path(args.root).resolve()
    if not root.exists():
        raise SystemExit(f"路径不存在：{root}")
    if not root.is_dir():
        raise SystemExit(f"路径不是目录：{root}")

    excluded_names = DEFAULT_EXCLUDES | {name for name in args.exclude if name}
    print(summarize(root, args.top, excluded_names))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
