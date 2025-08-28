# ReconForge Terminal Interface Testing Instructions

## 🧪 **Comprehensive Test Plan**

### **1. Start Testing Session**
```bash
cd /home/linux/reconforge
python reconforge.py
```

### **2. Suggested Test Sequence**

#### **Main Menu Navigation (Test All Options):**
- Try each menu option (1-10, 0)
- Test invalid options (like 'abc', '99')
- Test going back and forth between menus

#### **Subdomain Discovery (Option 1):**
1. Select "1" from main menu
2. Try each discovery option:
   - Option 1: Start New Discovery Scan
   - Option 2: Passive Discovery Only  
   - Option 3: Active Discovery Only
   - Option 4: Custom Source Selection
   - Option 5: View Recent Discoveries
   - Option 6: Export Discovery Results
3. **Test with target**: Use `example.com` as test target
4. Test invalid targets: Try `invalid-domain`, ``, `123.456`

#### **Vulnerability Scanning (Option 2):**
1. Select "2" from main menu  
2. Try the vulnerability scanning options
3. Test with `example.com` if discovery worked

#### **Other Modules (Options 3-8):**
- Test each module briefly
- Check for proper "Coming soon" messages
- Verify navigation works correctly

#### **Web Dashboard (Option 9):**
- Test launching web dashboard from terminal
- Verify it starts correctly
- Use Ctrl+C to return to terminal

#### **Tool Configuration (Option 10):**
- Check if it shows proper status

#### **Exit Testing (Option 0):**
- Test exit confirmation
- Try both "Yes" and "No" responses

### **3. Error Testing**
- Press Ctrl+C during operations
- Enter invalid inputs
- Try empty inputs where validation is expected
- Test with very long inputs

### **4. Navigation Testing**
- Use "b" (back) options in submenus
- Test breadcrumb navigation
- Verify you can navigate to all sections

### **5. Database Testing**
- If you complete any scans, check scan history
- Try export functionality

## 📝 **What to Look For**

### **✅ Should Work:**
- Beautiful colored terminal interface
- Professional menu system
- Breadcrumb navigation
- Real-time progress bars (if running scans)
- Proper error messages (not crashes)
- Back/exit options work
- Input validation

### **❌ Issues to Report:**
- Terminal crashes or stack traces
- Broken menu navigation  
- Unhandled exceptions
- UI formatting issues
- Functions that don't work as expected
- Missing back/exit options
- Confusing error messages

## 🔍 **After Testing**

Run the log analyzer to check for issues:
```bash
python analyze_logs.py
```

This will show:
- Any errors that occurred
- User interactions logged
- Overall system health
- Recommendations for fixes

## 💡 **Testing Tips**

1. **Take your time** - Try different paths through the interface
2. **Test invalid inputs** - See how the system handles bad data  
3. **Use realistic targets** - `example.com` is perfect for testing
4. **Try interrupting operations** - Press Ctrl+C to test graceful handling
5. **Navigate extensively** - Make sure all menus work properly

The logging system will capture everything automatically!

---
**Happy Testing! 🚀**