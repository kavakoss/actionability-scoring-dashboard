/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        base: '#0B0F14',
        panel: '#11161D',
        raised: '#161C24',
        edge: '#1F2937',
        ink: {
          DEFAULT: '#E5E7EB',
          muted: '#9AA7B8',
          faint: '#7C8A9C',
        },
        accent: '#3B82F6',
        sev: {
          low: '#22C55E',
          medium: '#F59E0B',
          high: '#EF4444',
        },
        tech: {
          pwsh: '#8B5CF6',
          cmd: '#06B6D4',
          transfer: '#F43F5E',
        },
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', 'monospace'],
      },
      fontSize: {
        '2xs': ['11px', '14px'],
      },
    },
  },
  plugins: [],
}
