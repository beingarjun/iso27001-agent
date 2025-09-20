/** @type {import('tailwindcss').Config} *//** @type {import('tailwindcss').Config} *//** @type {import('tailwindcss').Config} */module.exports = {/** @type {import('tailwindcss').Config} */

module.exports = {

  content: [module.exports = {

    './app/**/*.{js,ts,jsx,tsx,mdx}',

    './components/**/*.{js,ts,jsx,tsx,mdx}',  content: [module.exports = {

  ],

  theme: {    './app/**/*.{js,ts,jsx,tsx,mdx}',

    extend: {},

  },    './components/**/*.{js,ts,jsx,tsx,mdx}',  content: [  content: ['./src/**/*.{js,ts,jsx,tsx,mdx}'],module.exports = {

  plugins: [],

}    './src/**/*.{js,ts,jsx,tsx,mdx}',

  ],    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',

  theme: {

    extend: {    './src/components/**/*.{js,ts,jsx,tsx,mdx}',  theme: {  content: [

      colors: {

        primary: {    './src/app/**/*.{js,ts,jsx,tsx,mdx}',

          50: '#f0f9ff',

          500: '#3b82f6',    './app/**/*.{js,ts,jsx,tsx,mdx}',    extend: {    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',

          600: '#2563eb',

          700: '#1d4ed8',    './components/**/*.{js,ts,jsx,tsx,mdx}',

        },

        secondary: {  ],      colors: {    './src/components/**/*.{js,ts,jsx,tsx,mdx}',

          50: '#f8fafc',

          500: '#64748b',  theme: {

          600: '#475569',

        },    extend: {        primary: { 50: '#eff6ff', 500: '#3b82f6', 600: '#2563eb', 700: '#1d4ed8' },    './src/app/**/*.{js,ts,jsx,tsx,mdx}',

      },

    },      colors: {

  },

  plugins: [],        primary: {         success: { 50: '#f0fdf4', 500: '#22c55e' },  ],

}
          50: '#eff6ff', 

          500: '#3b82f6',         warning: { 50: '#fffbeb', 500: '#f59e0b' },  theme: {

          600: '#2563eb', 

          700: '#1d4ed8'         danger: { 50: '#fef2f2', 500: '#ef4444' }    extend: {

        },

        success: {       }      colors: {

          50: '#f0fdf4', 

          500: '#22c55e'     }        primary: {

        },

        warning: {   },          50: '#eff6ff',

          50: '#fffbeb', 

          500: '#f59e0b'   plugins: [require('@tailwindcss/forms'), require('@tailwindcss/typography')]          100: '#dbeafe',

        },

        danger: { };          200: '#bfdbfe',

          50: '#fef2f2',           300: '#93c5fd',

          500: '#ef4444'           400: '#60a5fa',

        },          500: '#3b82f6',

      },          600: '#2563eb',

    },          700: '#1d4ed8',

  },          800: '#1e40af',

  plugins: [],          900: '#1e3a8a',

}        },
        success: {
          50: '#f0fdf4',
          100: '#dcfce7',
          200: '#bbf7d0',
          300: '#86efac',
          400: '#4ade80',
          500: '#22c55e',
          600: '#16a34a',
          700: '#15803d',
          800: '#166534',
          900: '#14532d',
        },
        warning: {
          50: '#fffbeb',
          100: '#fef3c7',
          200: '#fde68a',
          300: '#fcd34d',
          400: '#fbbf24',
          500: '#f59e0b',
          600: '#d97706',
          700: '#b45309',
          800: '#92400e',
          900: '#78350f',
        },
        danger: {
          50: '#fef2f2',
          100: '#fee2e2',
          200: '#fecaca',
          300: '#fca5a5',
          400: '#f87171',
          500: '#ef4444',
          600: '#dc2626',
          700: '#b91c1c',
          800: '#991b1b',
          900: '#7f1d1d',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['Fira Code', 'Monaco', 'Consolas', 'monospace'],
      },
      animation: {
        'fade-in': 'fadeIn 0.5s ease-in-out',
        'slide-up': 'slideUp 0.3s ease-out',
        'pulse-slow': 'pulse 3s ease-in-out infinite',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%': { transform: 'translateY(10px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
      },
    },
  },
  plugins: [
    require('@tailwindcss/forms'),
  ],
}