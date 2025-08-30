#!/usr/bin/env python3
"""
ReconForge Display Module
Terminal-First Professional Reconnaissance Platform

This module provides comprehensive terminal display functionality including
tables, progress bars, status indicators, and formatted output.
"""

import os
import sys
import time
import shutil
from enum import Enum
from typing import List, Dict, Any, Optional, Union, Tuple
from dataclasses import dataclass
from datetime import datetime, timezone
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, TaskID, BarColumn, TextColumn, TimeRemainingColumn
from rich.text import Text
from rich.align import Align
from rich.columns import Columns
from rich.layout import Layout
from rich.live import Live
from rich.spinner import Spinner
from rich.tree import Tree
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.syntax import Syntax
from rich.markdown import Markdown


class DisplayTheme(Enum):
    """Display color themes"""
    DEFAULT = "default"
    DARK = "dark"
    LIGHT = "light"
    HACKER = "hacker"


class StatusType(Enum):
    """Status indicator types"""
    SUCCESS = "✅"
    ERROR = "❌"
    WARNING = "⚠️"
    INFO = "ℹ️"
    RUNNING = "🔄"
    PENDING = "⏳"
    STOPPED = "⏹️"


@dataclass
class TableColumn:
    """Table column configuration"""
    name: str
    key: str
    width: Optional[int] = None
    justify: str = "left"
    style: Optional[str] = None
    header_style: Optional[str] = None


@dataclass
class ProgressTask:
    """Progress tracking task"""
    task_id: TaskID
    description: str
    total: Optional[int] = None
    completed: int = 0


class ReconForgeDisplay:
    """Main display class for ReconForge terminal interface"""
    
    def __init__(self, theme: DisplayTheme = DisplayTheme.DEFAULT):
        """Initialize display with theme"""
        self.console = Console()
        self.theme = theme
        self.terminal_width = shutil.get_terminal_size().columns
        self.terminal_height = shutil.get_terminal_size().lines
        
        # Progress tracking
        self.active_progress: Optional[Progress] = None
        self.progress_tasks: Dict[str, ProgressTask] = {}
        
        # Display state
        self.current_live: Optional[Live] = None
        
        self._setup_theme()
    
    def _setup_theme(self):
        """Setup theme colors and styles"""
        if self.theme == DisplayTheme.HACKER:
            self.colors = {
                'primary': 'green',
                'secondary': 'bright_green', 
                'accent': 'cyan',
                'success': 'bright_green',
                'warning': 'yellow',
                'error': 'red',
                'info': 'cyan',
                'muted': 'dim',
                'highlight': 'bright_white'
            }
        elif self.theme == DisplayTheme.DARK:
            self.colors = {
                'primary': 'blue',
                'secondary': 'bright_blue',
                'accent': 'magenta',
                'success': 'green',
                'warning': 'yellow', 
                'error': 'red',
                'info': 'cyan',
                'muted': 'dim',
                'highlight': 'white'
            }
        else:  # Default theme
            self.colors = {
                'primary': 'blue',
                'secondary': 'bright_blue',
                'accent': 'cyan',
                'success': 'green',
                'warning': 'yellow',
                'error': 'red', 
                'info': 'blue',
                'muted': 'dim',
                'highlight': 'bright_white'
            }
    
    def clear_screen(self):
        """Clear terminal screen"""
        self.console.clear()
    
    def print_banner(self, version: str = "2.0.0"):
        """Print ReconForge banner"""
        banner_text = f"""
╭─────────────────────────────────────────────────────────────╮
│                                                             │
│    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗             │
│    ██╔══██╗██╔════╝██╔═══██╗██╔══██╗████╗  ██║             │
│    ██████╔╝█████╗  ██║   ██║██████╔╝██╔██╗ ██║             │
│    ██╔══██╗██╔══╝  ██║   ██║██╔══██╗██║╚██╗██║             │
│    ██║  ██║███████╗╚██████╔╝██║  ██║██║ ╚████║             │
│    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝             │
│                                                             │
│    ███████╗ ██████╗ ██████╗  ██████╗ ███████╗               │
│    ██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝               │
│    █████╗  ██║   ██║██████╔╝██║  ███╗█████╗                 │
│    ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝                 │
│    ██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗               │
│    ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝               │
│                                                             │
│            Terminal-First Reconnaissance Platform           │
│                        Version {version:8}                     │
│                                                             │
╰─────────────────────────────────────────────────────────────╯
        """
        
        self.console.print(banner_text, style=self.colors['primary'])
        self.console.print()
    
    def print_header(self, title: str, subtitle: Optional[str] = None):
        """Print section header"""
        if subtitle:
            header_text = f"{title}\n{subtitle}"
        else:
            header_text = title
        
        panel = Panel(
            Align.center(Text(header_text, style=self.colors['highlight'])),
            border_style=self.colors['primary'],
            padding=(1, 2)
        )
        self.console.print(panel)
        self.console.print()
    
    def print_status(self, message: str, status_type: StatusType = StatusType.INFO):
        """Print status message"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        status_color = {
            StatusType.SUCCESS: self.colors['success'],
            StatusType.ERROR: self.colors['error'],
            StatusType.WARNING: self.colors['warning'],
            StatusType.INFO: self.colors['info'],
            StatusType.RUNNING: self.colors['accent'],
            StatusType.PENDING: self.colors['muted'],
            StatusType.STOPPED: self.colors['muted']
        }.get(status_type, self.colors['info'])
        
        formatted_message = f"[{timestamp}] {status_type.value} {message}"
        self.console.print(formatted_message, style=status_color)
    
    def print_table(self, 
                   columns: List[TableColumn],
                   rows: List[Dict[str, Any]],
                   title: Optional[str] = None,
                   show_lines: bool = True,
                   max_rows: Optional[int] = None) -> None:
        """Print formatted table"""
        
        table = Table(
            title=title,
            show_lines=show_lines,
            border_style=self.colors['primary']
        )
        
        # Add columns
        for col in columns:
            table.add_column(
                col.name,
                justify=col.justify,
                style=col.style,
                header_style=col.header_style or self.colors['highlight'],
                width=col.width
            )
        
        # Add rows
        display_rows = rows[:max_rows] if max_rows else rows
        for row in display_rows:
            row_data = []
            for col in columns:
                value = row.get(col.key, "")
                if value is None:
                    value = ""
                row_data.append(str(value))
            table.add_row(*row_data)
        
        # Show truncation info
        if max_rows and len(rows) > max_rows:
            truncated_count = len(rows) - max_rows
            self.console.print(table)
            self.console.print(f"[{self.colors['muted']}]... and {truncated_count} more rows[/]")
        else:
            self.console.print(table)
    
    def print_key_value_pairs(self, 
                             data: Dict[str, Any], 
                             title: Optional[str] = None,
                             columns: int = 1) -> None:
        """Print key-value pairs in columns"""
        if title:
            self.console.print(f"[{self.colors['highlight']}]{title}[/]")
            self.console.print()
        
        items = []
        for key, value in data.items():
            key_text = Text(f"{key}:", style=self.colors['accent'])
            value_text = Text(str(value), style=self.colors['primary'])
            items.append(f"{key_text} {value_text}")
        
        if columns > 1:
            # Split items into columns
            columns_data = [[] for _ in range(columns)]
            for i, item in enumerate(items):
                columns_data[i % columns].append(item)
            
            column_panels = []
            for col_data in columns_data:
                if col_data:
                    column_panels.append("\n".join(col_data))
            
            self.console.print(Columns(column_panels, equal=True))
        else:
            for item in items:
                self.console.print(item)
    
    def create_progress_bar(self, description: str = "Processing") -> str:
        """Create and start a progress bar"""
        if not self.active_progress:
            self.active_progress = Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                "[progress.percentage]{task.percentage:>3.0f}%",
                TimeRemainingColumn(),
                console=self.console
            )
            self.active_progress.start()
        
        task_id = self.active_progress.add_task(description, total=100)
        task_key = f"task_{len(self.progress_tasks)}"
        self.progress_tasks[task_key] = ProgressTask(
            task_id=task_id,
            description=description
        )
        
        return task_key
    
    def update_progress(self, task_key: str, completed: int, total: Optional[int] = None):
        """Update progress bar"""
        if task_key not in self.progress_tasks or not self.active_progress:
            return
        
        task = self.progress_tasks[task_key]
        
        if total is not None:
            self.active_progress.update(task.task_id, total=total)
        
        self.active_progress.update(task.task_id, completed=completed)
        task.completed = completed
    
    def complete_progress(self, task_key: str):
        """Complete a progress task"""
        if task_key not in self.progress_tasks or not self.active_progress:
            return
        
        task = self.progress_tasks[task_key]
        self.active_progress.update(task.task_id, completed=task.total or 100)
        self.progress_tasks.pop(task_key)
        
        # Stop progress if no more tasks
        if not self.progress_tasks:
            self.active_progress.stop()
            self.active_progress = None
    
    def show_spinner(self, message: str = "Loading...") -> Live:
        """Show spinner with message"""
        spinner = Spinner("dots", text=message, style=self.colors['accent'])
        live = Live(spinner, console=self.console)
        live.start()
        return live
    
    def print_tree(self, data: Dict[str, Any], title: str = "Data Structure"):
        """Print hierarchical data as tree"""
        tree = Tree(f"[{self.colors['highlight']}]{title}[/]")
        
        def add_items(parent, items):
            for key, value in items.items():
                if isinstance(value, dict):
                    branch = parent.add(f"[{self.colors['accent']}]{key}[/]")
                    add_items(branch, value)
                elif isinstance(value, list):
                    branch = parent.add(f"[{self.colors['accent']}]{key}[/] ({len(value)} items)")
                    for i, item in enumerate(value):
                        if isinstance(item, dict):
                            item_branch = branch.add(f"[{self.colors['muted']}][{i}][/]")
                            add_items(item_branch, item)
                        else:
                            branch.add(f"[{self.colors['muted']}][{i}][/] {str(item)}")
                else:
                    parent.add(f"[{self.colors['accent']}]{key}[/]: {str(value)}")
        
        add_items(tree, data)
        self.console.print(tree)
    
    def print_code(self, code: str, language: str = "bash", theme: str = "monokai"):
        """Print syntax highlighted code"""
        syntax = Syntax(code, language, theme=theme, line_numbers=True)
        self.console.print(syntax)
    
    def print_markdown(self, markdown_text: str):
        """Print formatted markdown"""
        md = Markdown(markdown_text)
        self.console.print(md)
    
    def print_panel(self, content: str, title: Optional[str] = None, 
                   style: str = "blue", border_style: str = "blue"):
        """Print content in a panel"""
        panel = Panel(
            content,
            title=title,
            style=style,
            border_style=border_style,
            padding=(1, 2)
        )
        self.console.print(panel)
    
    def print_columns(self, items: List[str], columns: int = 3):
        """Print items in columns"""
        self.console.print(Columns(items, equal=True, expand=True))
    
    def prompt_input(self, message: str, default: Optional[str] = None) -> str:
        """Prompt for user input"""
        return Prompt.ask(message, default=default, console=self.console)
    
    def prompt_confirm(self, message: str, default: bool = True) -> bool:
        """Prompt for yes/no confirmation"""
        return Confirm.ask(message, default=default, console=self.console)
    
    def prompt_integer(self, message: str, default: Optional[int] = None,
                      min_value: Optional[int] = None, max_value: Optional[int] = None) -> int:
        """Prompt for integer input"""
        while True:
            try:
                value = IntPrompt.ask(message, default=default, console=self.console)
                if min_value is not None and value < min_value:
                    self.print_status(f"Value must be at least {min_value}", StatusType.ERROR)
                    continue
                if max_value is not None and value > max_value:
                    self.print_status(f"Value must be at most {max_value}", StatusType.ERROR)
                    continue
                return value
            except KeyboardInterrupt:
                raise
    
    def prompt_choice(self, message: str, choices: List[str], default: Optional[str] = None) -> str:
        """Prompt for choice from list"""
        while True:
            self.console.print(f"[{self.colors['info']}]{message}[/]")
            for i, choice in enumerate(choices, 1):
                prefix = ">" if choice == default else " "
                self.console.print(f"  {prefix} {i}. {choice}")
            
            try:
                response = self.prompt_input("Enter your choice (number or name)", str(choices.index(default) + 1) if default else None)
                
                # Try to parse as number
                try:
                    choice_num = int(response) - 1
                    if 0 <= choice_num < len(choices):
                        return choices[choice_num]
                except ValueError:
                    pass
                
                # Try to match by name
                for choice in choices:
                    if choice.lower().startswith(response.lower()):
                        return choice
                
                self.print_status("Invalid choice, please try again", StatusType.ERROR)
                
            except KeyboardInterrupt:
                raise
    
    def print_separator(self, char: str = "─", width: Optional[int] = None):
        """Print separator line"""
        if width is None:
            width = self.terminal_width
        
        separator = char * width
        self.console.print(separator, style=self.colors['muted'])
    
    def print_empty_lines(self, count: int = 1):
        """Print empty lines"""
        for _ in range(count):
            self.console.print()
    
    def get_terminal_size(self) -> Tuple[int, int]:
        """Get terminal dimensions (width, height)"""
        return self.terminal_width, self.terminal_height
    
    def set_title(self, title: str):
        """Set terminal window title"""
        if os.name == 'nt':  # Windows
            os.system(f'title {title}')
        else:  # Unix-like
            sys.stdout.write(f'\033]2;{title}\007')
            sys.stdout.flush()
    
    def cleanup(self):
        """Cleanup display resources"""
        if self.active_progress:
            self.active_progress.stop()
            self.active_progress = None
        
        if self.current_live:
            self.current_live.stop()
            self.current_live = None
        
        self.progress_tasks.clear()


# Convenience functions for quick access
def create_display(theme: DisplayTheme = DisplayTheme.DEFAULT) -> ReconForgeDisplay:
    """Create a ReconForge display instance"""
    return ReconForgeDisplay(theme)


def print_success(message: str, display: Optional[ReconForgeDisplay] = None):
    """Print success message"""
    if display is None:
        display = create_display()
    display.print_status(message, StatusType.SUCCESS)


def print_error(message: str, display: Optional[ReconForgeDisplay] = None):
    """Print error message"""
    if display is None:
        display = create_display()
    display.print_status(message, StatusType.ERROR)


def print_warning(message: str, display: Optional[ReconForgeDisplay] = None):
    """Print warning message"""
    if display is None:
        display = create_display()
    display.print_status(message, StatusType.WARNING)


def print_info(message: str, display: Optional[ReconForgeDisplay] = None):
    """Print info message"""
    if display is None:
        display = create_display()
    display.print_status(message, StatusType.INFO)