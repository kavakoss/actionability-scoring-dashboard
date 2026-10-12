/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        base: '#0B0E13',
        panel: '#12161D',
        raised: '#1A2029',
        edge: { DEFAULT: '#29313D', strong: '#485362' },
        ink: { DEFAULT: '#E6EAF0', muted: '#ABB5C3', faint: '#8995A6' },
        accent: '#78AAFA',
        band: { high: '#34D399', medium: '#F5B54A', low: '#F87171' },
        tech: { pwsh: '#B5A0EF', cmd: '#74C7EA', transfer: '#EAA0AE' },
      },
      fontFamily: {
        sans: ['"Inter Variable"', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace'],
      },
      fontSize: {
        display: ['30px', { lineHeight: '36px', letterSpacing: '-0.025em' }],
        title: ['20px', { lineHeight: '28px', letterSpacing: '-0.015em' }],
        heading: ['16px', { lineHeight: '24px', letterSpacing: '-0.01em' }],
        body: ['14px', '21px'],
        small: ['13px', '19px'],
        caption: ['12px', '18px'],
        '2xs': ['12px', '18px'],
      },
      transitionDuration: { DEFAULT: '150' },
    },
  },
  plugins: [],
}
