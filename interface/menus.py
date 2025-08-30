#!/usr/bin/env python3
"""
ReconForge Menu System
Terminal-First Professional Reconnaissance Platform

This module provides a comprehensive menu system for terminal navigation
including hierarchical menus, breadcrumb tracking, and menu state management.
"""

from enum import Enum
from typing import List, Dict, Any, Optional, Callable, Union, Tuple
from dataclasses import dataclass, field
from abc import ABC, abstractmethod

from interface.display import ReconForgeDisplay, StatusType, DisplayTheme


class MenuType(Enum):
    """Menu item types"""
    SUBMENU = "submenu"
    ACTION = "action"
    SEPARATOR = "separator"
    BACK = "back"
    EXIT = "exit"


class MenuState(Enum):
    """Menu navigation states"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    DISABLED = "disabled"


@dataclass
class MenuItem:
    """Individual menu item"""
    key: str
    title: str
    description: Optional[str] = None
    menu_type: MenuType = MenuType.ACTION
    action: Optional[Callable] = None
    submenu: Optional['Menu'] = None
    enabled: bool = True
    visible: bool = True
    shortcut: Optional[str] = None
    requires_confirmation: bool = False
    confirmation_message: Optional[str] = None
    icon: Optional[str] = None


@dataclass
class MenuConfig:
    """Menu configuration options"""
    show_numbers: bool = True
    show_shortcuts: bool = True
    show_descriptions: bool = True
    show_breadcrumbs: bool = True
    show_status_bar: bool = True
    allow_back: bool = True
    auto_exit: bool = False
    case_sensitive: bool = False
    clear_on_navigate: bool = True
    max_items_per_page: Optional[int] = None


class MenuContext:
    """Menu execution context"""
    def __init__(self, logger=None, config=None, database=None, utils=None):
        self.logger = logger
        self.config = config
        self.database = database
        self.utils = utils
        self.user_data: Dict[str, Any] = {}
        self.session_data: Dict[str, Any] = {}


class Menu:
    """Menu class for hierarchical navigation"""
    
    def __init__(self, 
                 title: str, 
                 description: Optional[str] = None,
                 parent: Optional['Menu'] = None,
                 config: Optional[MenuConfig] = None):
        self.title = title
        self.description = description
        self.parent = parent
        self.config = config or MenuConfig()
        
        # Menu items
        self.items: List[MenuItem] = []
        self.item_lookup: Dict[str, MenuItem] = {}
        
        # Navigation state
        self.current_page = 0
        self.state = MenuState.ACTIVE
        
        # Add default back/exit items if needed
        if self.config.allow_back and parent is not None:
            self.add_separator()
            self.add_back_item()
        
        if parent is None:  # Root menu
            self.add_separator()
            self.add_exit_item()
    
    def add_item(self, item: MenuItem) -> 'Menu':
        """Add menu item"""
        self.items.append(item)
        self.item_lookup[item.key] = item
        if item.shortcut:
            self.item_lookup[item.shortcut] = item
        return self
    
    def add_action(self, 
                   key: str,
                   title: str,
                   action: Callable,
                   description: Optional[str] = None,
                   shortcut: Optional[str] = None,
                   requires_confirmation: bool = False,
                   confirmation_message: Optional[str] = None,
                   icon: Optional[str] = None) -> 'Menu':
        """Add action menu item"""
        item = MenuItem(
            key=key,
            title=title,
            description=description,
            menu_type=MenuType.ACTION,
            action=action,
            shortcut=shortcut,
            requires_confirmation=requires_confirmation,
            confirmation_message=confirmation_message,
            icon=icon
        )
        return self.add_item(item)
    
    def add_submenu(self,
                    key: str,
                    title: str,
                    submenu: 'Menu',
                    description: Optional[str] = None,
                    shortcut: Optional[str] = None,
                    icon: Optional[str] = None) -> 'Menu':
        """Add submenu item"""
        submenu.parent = self
        item = MenuItem(
            key=key,
            title=title,
            description=description,
            menu_type=MenuType.SUBMENU,
            submenu=submenu,
            shortcut=shortcut,
            icon=icon
        )
        return self.add_item(item)
    
    def add_separator(self, title: Optional[str] = None) -> 'Menu':
        """Add separator line"""
        key = f"sep_{len([i for i in self.items if i.menu_type == MenuType.SEPARATOR])}"
        item = MenuItem(
            key=key,
            title=title or "─" * 40,
            menu_type=MenuType.SEPARATOR
        )
        return self.add_item(item)
    
    def add_back_item(self) -> 'Menu':
        """Add back navigation item"""
        if self.parent:
            item = MenuItem(
                key="back",
                title="← Back",
                description=f"Return to {self.parent.title}",
                menu_type=MenuType.BACK,
                shortcut="b",
                icon="←"
            )
            return self.add_item(item)
        return self
    
    def add_exit_item(self) -> 'Menu':
        """Add exit item"""
        item = MenuItem(
            key="exit",
            title="Exit ReconForge",
            description="Exit the application",
            menu_type=MenuType.EXIT,
            shortcut="x",
            requires_confirmation=True,
            confirmation_message="Are you sure you want to exit ReconForge?",
            icon="✕"
        )
        return self.add_item(item)
    
    def get_visible_items(self) -> List[MenuItem]:
        """Get list of visible menu items"""
        return [item for item in self.items if item.visible]
    
    def get_enabled_items(self) -> List[MenuItem]:
        """Get list of enabled menu items"""
        return [item for item in self.items if item.visible and item.enabled]
    
    def find_item(self, key: str) -> Optional[MenuItem]:
        """Find menu item by key or shortcut"""
        key_lower = key.lower() if not self.config.case_sensitive else key
        
        # Direct lookup
        if key_lower in self.item_lookup:
            return self.item_lookup[key_lower]
        
        # Case-insensitive search if needed
        if not self.config.case_sensitive:
            for lookup_key, item in self.item_lookup.items():
                if lookup_key.lower() == key_lower:
                    return item
        
        return None
    
    def get_breadcrumb_path(self) -> List[str]:
        """Get breadcrumb navigation path"""
        path = []
        current = self
        while current:
            path.insert(0, current.title)
            current = current.parent
        return path
    
    def enable_item(self, key: str):
        """Enable menu item"""
        item = self.find_item(key)
        if item:
            item.enabled = True
    
    def disable_item(self, key: str):
        """Disable menu item"""
        item = self.find_item(key)
        if item:
            item.enabled = False
    
    def show_item(self, key: str):
        """Show menu item"""
        item = self.find_item(key)
        if item:
            item.visible = True
    
    def hide_item(self, key: str):
        """Hide menu item"""
        item = self.find_item(key)
        if item:
            item.visible = False
    
    def update_item_title(self, key: str, new_title: str):
        """Update menu item title"""
        item = self.find_item(key)
        if item:
            item.title = new_title
    
    def update_item_description(self, key: str, new_description: str):
        """Update menu item description"""
        item = self.find_item(key)
        if item:
            item.description = new_description


class MenuNavigator:
    """Handles menu navigation and display"""
    
    def __init__(self, display: ReconForgeDisplay, context: MenuContext):
        self.display = display
        self.context = context
        self.menu_stack: List[Menu] = []
        self.running = True
        
        # Navigation history
        self.navigation_history: List[Tuple[str, str]] = []  # (menu_title, item_key)
    
    def run_menu(self, menu: Menu) -> Optional[str]:
        """Run menu navigation loop"""
        self.menu_stack.append(menu)
        
        try:
            while self.running and menu.state == MenuState.ACTIVE:
                if menu.config.clear_on_navigate:
                    self.display.clear_screen()
                
                self._display_menu(menu)
                
                try:
                    choice = self._get_user_choice(menu)
                    if choice is None:  # Exit requested
                        break
                    
                    result = self._handle_choice(menu, choice)
                    if result == "exit":
                        self.running = False
                        break
                    elif result == "back":
                        break
                
                except KeyboardInterrupt:
                    if self.display.prompt_confirm("\nExit ReconForge?", default=False):
                        self.running = False
                        break
                    else:
                        continue
                
                except Exception as e:
                    error_msg = f"Menu navigation error: {str(e)}"
                    self.display.print_status(error_msg, StatusType.ERROR)
                    if self.context.logger:
                        self.context.logger.log_error(error_msg)
                    
                    self.display.prompt_input("Press Enter to continue...")
        
        finally:
            if self.menu_stack:
                self.menu_stack.pop()
        
        return "exit" if not self.running else "back"
    
    def _display_menu(self, menu: Menu):
        """Display menu interface"""
        # Display header
        if menu.config.show_breadcrumbs:
            breadcrumbs = " > ".join(menu.get_breadcrumb_path())
            self.display.print_header(menu.title, breadcrumbs)
        else:
            self.display.print_header(menu.title, menu.description)
        
        # Get visible items
        visible_items = menu.get_visible_items()
        
        # Handle pagination if needed
        if menu.config.max_items_per_page:
            start_idx = menu.current_page * menu.config.max_items_per_page
            end_idx = start_idx + menu.config.max_items_per_page
            page_items = visible_items[start_idx:end_idx]
            
            # Show pagination info
            if len(visible_items) > menu.config.max_items_per_page:
                total_pages = (len(visible_items) + menu.config.max_items_per_page - 1) // menu.config.max_items_per_page
                page_info = f"Page {menu.current_page + 1} of {total_pages}"
                self.display.print_status(page_info, StatusType.INFO)
                self.display.print_empty_lines()
        else:
            page_items = visible_items
        
        # Display menu items
        item_number = 1
        for item in page_items:
            self._display_menu_item(item, item_number, menu.config)
            
            if item.menu_type != MenuType.SEPARATOR:
                item_number += 1
        
        self.display.print_empty_lines()
        
        # Display status bar
        if menu.config.show_status_bar:
            self._display_status_bar(menu)
    
    def _display_menu_item(self, item: MenuItem, number: int, config: MenuConfig):
        """Display individual menu item"""
        if item.menu_type == MenuType.SEPARATOR:
            self.display.print_separator()
            if item.title != "─" * 40:  # Custom separator title
                self.display.console.print(f"    {item.title}", style=self.display.colors['accent'])
            return
        
        # Build item display
        parts = []
        
        # Number
        if config.show_numbers:
            parts.append(f"[{self.display.colors['muted']}]{number:2}.[/]")
        
        # Icon
        if item.icon:
            parts.append(f"[{self.display.colors['accent']}]{item.icon}[/]")
        
        # Title
        title_style = self.display.colors['primary'] if item.enabled else self.display.colors['muted']
        parts.append(f"[{title_style}]{item.title}[/]")
        
        # Shortcut
        if config.show_shortcuts and item.shortcut:
            parts.append(f"[{self.display.colors['muted']}]({item.shortcut})[/]")
        
        # Type indicator
        if item.menu_type == MenuType.SUBMENU:
            parts.append(f"[{self.display.colors['accent']}]→[/]")
        elif item.menu_type == MenuType.EXIT:
            parts.append(f"[{self.display.colors['error']}]✕[/]")
        elif item.requires_confirmation:
            parts.append(f"[{self.display.colors['warning']}]⚠[/]")
        
        line = " ".join(parts)
        
        # Description
        if config.show_descriptions and item.description:
            line += f"\n    [i][{self.display.colors['muted']}]{item.description}[/][/i]"
        
        # Show enabled/disabled state
        if not item.enabled:
            line = f"[dim]{line}[/dim]"
        
        self.display.console.print(line)
    
    def _display_status_bar(self, menu: Menu):
        """Display status bar with navigation hints"""
        hints = []
        
        if menu.config.show_numbers:
            hints.append("Enter number")
        
        if menu.config.show_shortcuts:
            hints.append("shortcut key")
        
        if menu.parent and menu.config.allow_back:
            hints.append("'b' for back")
        
        hints.append("'?' for help")
        
        if menu.parent is None:
            hints.append("'x' to exit")
        
        status_text = " | ".join(hints)
        self.display.print_separator("─", len(status_text) + 4)
        self.display.console.print(f"  {status_text}", style=self.display.colors['muted'])
        self.display.print_empty_lines()
    
    def _get_user_choice(self, menu: Menu) -> Optional[str]:
        """Get user menu choice"""
        while True:
            try:
                choice = self.display.prompt_input("Enter your choice").strip()
                
                if not choice:
                    continue
                
                # Handle special commands
                if choice.lower() == '?':
                    self._show_help(menu)
                    continue
                elif choice.lower() == 'q' and menu.parent is None:
                    return None  # Exit
                
                return choice
                
            except KeyboardInterrupt:
                return None
    
    def _handle_choice(self, menu: Menu, choice: str) -> Optional[str]:
        """Handle user menu choice"""
        # Try to find item by number
        visible_items = [item for item in menu.get_visible_items() if item.menu_type != MenuType.SEPARATOR]
        
        try:
            choice_num = int(choice)
            if 1 <= choice_num <= len(visible_items):
                item = visible_items[choice_num - 1]
            else:
                self.display.print_status("Invalid choice number", StatusType.ERROR)
                return None
        except ValueError:
            # Try to find by key or shortcut
            item = menu.find_item(choice)
            if not item:
                self.display.print_status("Invalid choice", StatusType.ERROR)
                return None
        
        # Check if item is enabled
        if not item.enabled:
            self.display.print_status("This option is currently disabled", StatusType.WARNING)
            return None
        
        # Record navigation
        self.navigation_history.append((menu.title, item.key))
        if self.context.logger:
            self.context.logger.log_user_action(f"Menu selection: {menu.title} -> {item.title}")
        
        # Handle confirmation if required
        if item.requires_confirmation:
            message = item.confirmation_message or f"Are you sure you want to {item.title.lower()}?"
            if not self.display.prompt_confirm(message, default=False):
                return None
        
        # Execute item action
        return self._execute_item(item)
    
    def _execute_item(self, item: MenuItem) -> Optional[str]:
        """Execute menu item action"""
        try:
            if item.menu_type == MenuType.SUBMENU:
                return self.run_menu(item.submenu)
            
            elif item.menu_type == MenuType.ACTION:
                if item.action:
                    # Pass context to action
                    result = item.action(self.context)
                    
                    # Handle different return types
                    if result == "exit":
                        return "exit"
                    elif result == "back":
                        return "back"
                    else:
                        # Wait for user input before returning to menu
                        if not item.key.startswith("silent_"):
                            self.display.prompt_input("\nPress Enter to continue...")
                
                return None
            
            elif item.menu_type == MenuType.BACK:
                return "back"
            
            elif item.menu_type == MenuType.EXIT:
                return "exit"
            
            else:
                self.display.print_status(f"Unknown menu type: {item.menu_type}", StatusType.ERROR)
                return None
        
        except Exception as e:
            error_msg = f"Error executing menu item '{item.title}': {str(e)}"
            self.display.print_status(error_msg, StatusType.ERROR)
            if self.context.logger:
                self.context.logger.log_error(error_msg)
                import traceback
                self.context.logger.log_error(f"Menu execution traceback: {traceback.format_exc()}")
            
            self.display.prompt_input("Press Enter to continue...")
            return None
    
    def _show_help(self, menu: Menu):
        """Show menu help"""
        self.display.print_header("Menu Help")
        
        help_items = [
            ("Navigation", "Use numbers or shortcut keys to select items"),
            ("Back", "'b' to go back to previous menu (if available)"),
            ("Exit", "'x' to exit ReconForge (from main menu)"),
            ("Help", "'?' to show this help message"),
            ("Shortcuts", "Items with shortcuts are shown in parentheses")
        ]
        
        for title, description in help_items:
            self.display.console.print(f"[{self.display.colors['accent']}]{title}:[/] {description}")
        
        self.display.print_empty_lines()
        
        # Show available shortcuts in current menu
        shortcuts = []
        for item in menu.get_enabled_items():
            if item.shortcut and item.menu_type != MenuType.SEPARATOR:
                shortcuts.append(f"'{item.shortcut}' - {item.title}")
        
        if shortcuts:
            self.display.print_header("Available Shortcuts")
            for shortcut in shortcuts:
                self.display.console.print(f"  {shortcut}")
        
        self.display.prompt_input("\nPress Enter to continue...")
    
    def get_navigation_history(self) -> List[Tuple[str, str]]:
        """Get navigation history"""
        return self.navigation_history.copy()
    
    def clear_history(self):
        """Clear navigation history"""
        self.navigation_history.clear()


def create_menu(title: str, description: Optional[str] = None, 
               parent: Optional[Menu] = None, config: Optional[MenuConfig] = None) -> Menu:
    """Create a new menu"""
    return Menu(title, description, parent, config)


def create_menu_config(**kwargs) -> MenuConfig:
    """Create menu configuration with custom options"""
    return MenuConfig(**kwargs)