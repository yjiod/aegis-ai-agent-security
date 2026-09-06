'use client';
import { useState, useEffect } from 'react';
import { Sun, Moon } from 'lucide-react';

export default function ThemeToggle() {
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
  }, [theme]);

  return (
    <button
      className="icon-btn"
      onClick={() => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))}
      aria-label={theme === 'dark' ? '切换到亮色主题' : '切换到暗色主题'}
    >
      {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
    </button>
  );
}
