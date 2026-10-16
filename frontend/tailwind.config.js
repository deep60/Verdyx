/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: ["class"],
  content: ["./client/index.html", "./client/src/**/*.{js,jsx,ts,tsx}"],
  theme: {
  	extend: {
  		borderRadius: {
  			lg: 'var(--radius)',
  			md: 'calc(var(--radius) - 2px)',
  			sm: 'calc(var(--radius) - 4px)'
  		},
  		colors: {
  			background: 'hsl(var(--background))',
  			foreground: 'hsl(var(--foreground))',
  			card: {
  				DEFAULT: 'hsl(var(--card))',
  				foreground: 'hsl(var(--card-foreground))'
  			},
  			popover: {
  				DEFAULT: 'hsl(var(--popover))',
  				foreground: 'hsl(var(--popover-foreground))'
  			},
  			primary: {
  				DEFAULT: 'hsl(var(--primary))',
  				foreground: 'hsl(var(--primary-foreground))'
  			},
  			secondary: {
  				DEFAULT: 'hsl(var(--secondary))',
  				foreground: 'hsl(var(--secondary-foreground))'
  			},
  			muted: {
  				DEFAULT: 'hsl(var(--muted))',
  				foreground: 'hsl(var(--muted-foreground))'
  			},
  			accent: {
  				DEFAULT: 'hsl(var(--accent))',
  				foreground: 'hsl(var(--accent-foreground))'
  			},
  			destructive: {
  				DEFAULT: 'hsl(var(--destructive))',
  				foreground: 'hsl(var(--destructive-foreground))'
  			},
  			success: {
  				DEFAULT: 'hsl(var(--success))',
  				foreground: 'hsl(var(--success-foreground))'
  			},
  			warning: {
  				DEFAULT: 'hsl(var(--warning))',
  				foreground: 'hsl(var(--warning-foreground))'
  			},
  			surface: {
  				DEFAULT: 'hsl(var(--surface))',
  				foreground: 'hsl(var(--surface-foreground))'
  			},
  			border: 'hsl(var(--border))',
  			input: 'hsl(var(--input))',
  			ring: 'hsl(var(--ring))',
  			chart: {
  				'1': 'var(--chart-1)',
  				'2': 'var(--chart-2)',
  				'3': 'var(--chart-3)',
  				'4': 'var(--chart-4)',
  				'5': 'var(--chart-5)'
  			},
  			sidebar: {
  				DEFAULT: 'hsl(var(--sidebar-background))',
  				foreground: 'hsl(var(--sidebar-foreground))',
  				primary: 'hsl(var(--sidebar-primary))',
  				'primary-foreground': 'hsl(var(--sidebar-primary-foreground))',
  				accent: 'hsl(var(--sidebar-accent))',
  				'accent-foreground': 'hsl(var(--sidebar-accent-foreground))',
  				border: 'hsl(var(--sidebar-border))',
  				ring: 'hsl(var(--sidebar-ring))'
  			}
  		},
  		fontFamily: {
  			sans: [
  				'Manrope',
  				'system-ui',
  				'-apple-system',
  				'Segoe UI',
  				'sans-serif'
  			],
  			display: [
  				'Syne',
  				'Manrope',
  				'system-ui',
  				'sans-serif'
  			],
  			serif: [
  				'Syne',
  				'serif'
  			],
  			mono: [
  				'IBM Plex Mono',
  				'ui-monospace',
  				'SFMono-Regular',
  				'monospace'
  			]
  		},
  		keyframes: {
  			'accordion-down': {
  				from: {
  					height: '0'
  				},
  				to: {
  					height: 'var(--radix-accordion-content-height)'
  				}
  			},
  			'accordion-up': {
  				from: {
  					height: 'var(--radix-accordion-content-height)'
  				},
  				to: {
  					height: '0'
  				}
  			},
  			float: {
  				'0%, 100%': {
  					transform: 'translateY(0px) rotate(0deg)'
  				},
  				'50%': {
  					transform: 'translateY(-20px) rotate(5deg)'
  				}
  			},
  			glow: {
  				from: {
  					boxShadow: '0 0 0 1px hsl(var(--primary) / 0.12), 0 8px 24px -8px hsl(var(--brand-from) / 0.35)'
  				},
  				to: {
  					boxShadow: '0 0 0 1px hsl(var(--primary) / 0.24), 0 14px 40px -8px hsl(var(--brand-from) / 0.6)'
  				}
  			},
  			'fade-up': {
  				from: { opacity: '0', transform: 'translateY(16px)' },
  				to: { opacity: '1', transform: 'translateY(0)' }
  			},
  			'fade-in': {
  				from: { opacity: '0' },
  				to: { opacity: '1' }
  			},
  			shimmer: {
  				'0%': { backgroundPosition: '-200% 0' },
  				'100%': { backgroundPosition: '200% 0' }
  			},
  			particle: {
  				'0%': {
  					transform: 'translateY(100vh) translateX(0px) rotate(0deg)',
  					opacity: '0'
  				},
  				'10%': {
  					opacity: '1'
  				},
  				'90%': {
  					opacity: '1'
  				},
  				'100%': {
  					transform: 'translateY(-100vh) translateX(100px) rotate(360deg)',
  					opacity: '0'
  				}
  			},
  			scan: {
  				'0%': {
  					backgroundPosition: '-200% 0'
  				},
  				'100%': {
  					backgroundPosition: '200% 0'
  				}
  			},
  			hologram: {
  				'0%, 100%': {
  					backgroundPosition: '0% 0%'
  				},
  				'50%': {
  					backgroundPosition: '100% 100%'
  				}
  			},
  			'pulse-slow': {
  				'0%, 100%': {
  					opacity: '1'
  				},
  				'50%': {
  					opacity: '0.5'
  				}
  			}
  		},
  		animation: {
  			'accordion-down': 'accordion-down 0.2s ease-out',
  			'accordion-up': 'accordion-up 0.2s ease-out',
  			float: 'float 6s ease-in-out infinite',
  			glow: 'glow 2.6s ease-in-out infinite alternate',
  			particle: 'particle 22s linear infinite',
  			scan: 'scan 2s linear infinite',
  			hologram: 'hologram 3s ease-in-out infinite',
  			'pulse-slow': 'pulse-slow 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
  			'fade-up': 'fade-up 0.7s cubic-bezier(0.22, 1, 0.36, 1) both',
  			'fade-in': 'fade-in 0.6s ease-out both',
  			shimmer: 'shimmer 2.5s linear infinite'
  		},
  		transitionDuration: {
  			'650': '650ms'
  		},
  		transitionTimingFunction: {
  			'expo-out': 'cubic-bezier(0.22, 1, 0.36, 1)'
  		}
  	}
  },
  plugins: [require("tailwindcss-animate"), require("@tailwindcss/typography")],
};
