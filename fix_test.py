import re
path = 'tests/test_aegis.py'
src = open(path).read()

# Replace the demo-era assertions with production semantics
old_line = "        self.assertIn('演示模式',page); self.assertIn('接收器未连接',shell); self.assertIn('未对任何终端执行操作',page)\n"
new_line = ("        # Production: console must NOT contain demo mode or fake dispatch.\n"
            "        self.assertNotIn('演示模式',console); self.assertNotIn('界面样例',console)\n"
            "        # Auth gate present (middleware + login page)\n"
            "        self.assertTrue((ROOT/'middleware.ts').exists()); self.assertTrue((ROOT/'app/login/page.tsx').exists())\n")

if old_line in src:
    src = src.replace(old_line, new_line)
    open(path, 'w').write(src)
    print("console test updated to production semantics")
else:
    print("old line not found; searching...")
    for i, line in enumerate(src.splitlines()):
        if '演示模式' in line and 'assertIn' in line:
            print(f"  line {i+1}: {line[:80]}")
