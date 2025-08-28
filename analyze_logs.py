#!/usr/bin/env python3
"""
ReconForge Terminal Test Log Analyzer
Analyzes terminal interface test logs for errors and issues
"""

import re
from pathlib import Path
from datetime import datetime

def analyze_terminal_logs():
    """Analyze terminal test logs and provide summary"""
    
    log_file = Path("logs/terminal_test.log")
    
    if not log_file.exists():
        print("❌ No terminal test log found!")
        return
    
    print("🔍 ReconForge Terminal Interface Test Analysis")
    print("=" * 50)
    
    # Read log file
    with open(log_file, 'r') as f:
        log_content = f.read()
    
    # Extract log entries
    log_lines = log_content.strip().split('\n')
    
    # Statistics
    total_lines = len(log_lines)
    error_lines = []
    warning_lines = []
    info_lines = []
    debug_lines = []
    critical_lines = []
    
    # User interactions
    user_choices = []
    targets_entered = []
    modules_accessed = []
    
    # Parse each line
    for line_num, line in enumerate(log_lines, 1):
        # Skip header lines and empty lines
        if not line.strip() or line.startswith('#') or line.startswith('===') or 'Test Start Time' in line:
            continue
            
        # Categorize by log level
        if '| ERROR   ' in line:
            error_lines.append((line_num, line))
        elif '| WARNING ' in line:
            warning_lines.append((line_num, line))
        elif '| CRITICAL' in line:
            critical_lines.append((line_num, line))
        elif '| INFO    ' in line:
            info_lines.append((line_num, line))
        elif '| DEBUG   ' in line:
            debug_lines.append((line_num, line))
        
        # Extract user interactions
        if "User selected:" in line:
            match = re.search(r"User selected: '([^']+)'", line)
            if match:
                user_choices.append(match.group(1))
        
        if "Target validated and normalized to:" in line:
            match = re.search(r"Target validated and normalized to: ([^\|]+)", line)
            if match:
                targets_entered.append(match.group(1).strip())
        
        if "Entering " in line and " module" in line:
            match = re.search(r"Entering ([^|]+) module", line)
            if match:
                modules_accessed.append(match.group(1).strip())
    
    # Print summary
    print(f"📊 LOG ANALYSIS SUMMARY")
    print(f"   Total log entries: {total_lines}")
    print(f"   🔴 Critical errors: {len(critical_lines)}")
    print(f"   🟠 Errors: {len(error_lines)}")
    print(f"   🟡 Warnings: {len(warning_lines)}")
    print(f"   🔵 Info messages: {len(info_lines)}")
    print(f"   🔍 Debug messages: {len(debug_lines)}")
    print()
    
    # Critical errors
    if critical_lines:
        print("🚨 CRITICAL ERRORS:")
        for line_num, line in critical_lines:
            print(f"   Line {line_num}: {line.strip()}")
        print()
    
    # Errors
    if error_lines:
        print("❌ ERRORS FOUND:")
        for line_num, line in error_lines:
            print(f"   Line {line_num}: {line.strip()}")
        print()
    
    # Warnings
    if warning_lines:
        print("⚠️  WARNINGS:")
        for line_num, line in warning_lines:
            print(f"   Line {line_num}: {line.strip()}")
        print()
    
    # User interactions
    if user_choices:
        print(f"👤 USER INTERACTIONS:")
        print(f"   Menu choices made: {', '.join(user_choices)}")
        print(f"   Targets entered: {', '.join(targets_entered) if targets_entered else 'None'}")
        print(f"   Modules accessed: {', '.join(set(modules_accessed)) if modules_accessed else 'None'}")
        print()
    
    # Overall status
    if critical_lines:
        status = "🚨 CRITICAL ISSUES DETECTED"
    elif error_lines:
        status = "❌ ERRORS DETECTED"
    elif warning_lines:
        status = "⚠️  WARNINGS DETECTED"
    else:
        status = "✅ NO MAJOR ISSUES"
    
    print(f"🎯 OVERALL STATUS: {status}")
    print()
    
    # Recommendations
    print("💡 RECOMMENDATIONS:")
    if critical_lines or error_lines:
        print("   - Review error messages above")
        print("   - Check if any functionality failed")
        print("   - Verify all menu options work correctly")
    if not user_choices:
        print("   - No user interactions detected - test all menu options")
    if not targets_entered:
        print("   - No targets entered - test discovery and scanning functions")
    if not modules_accessed:
        print("   - No modules accessed - test each main menu option")
    
    if not (critical_lines or error_lines or warning_lines):
        print("   - Great! No issues detected in the logs")
        print("   - Terminal interface appears to be working correctly")
    
    print("\n" + "=" * 50)
    print(f"Analysis completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    analyze_terminal_logs()