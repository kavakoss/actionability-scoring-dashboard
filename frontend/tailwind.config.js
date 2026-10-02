/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        base: '#0E1218',
        panel: '#161C24',
        raised: '#1D242E',
        edge: '#2A323E',
        ink: {
          DEFAULT: '#E9EDF3',
          muted: '#A9B4C2',
          faint: '#7E8A99',
        },
        accent: '#5B9DFF',
        // Severity semantics for detection rules (high = most severe).
        sev: {
          low: '#3ECF8E',
          medium: '#F0B429',
          high: '#F26D6D',
        },
        // Actionability semantics: high = most complete evidence.
        band: {
          high: '#3ECF8E',
          medium: '#F0B429',
          low: '#E07070',
        },
        tech: {
          pwsh: '#A78BFA',
          cmd: '#38BDF8',
          transfer: '#FB7185',
        },
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', 'monospace'],
      },
      fontSize: {
        '2xs': ['12px', '16px'],
      },
    },
  },
  plugins: [],
}
