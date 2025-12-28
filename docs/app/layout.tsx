import type { ReactNode } from 'react'
import { RootProvider } from 'fumadocs-ui/provider'
import { Geist, Geist_Mono } from 'next/font/google'
import 'fumadocs-ui/style.css'
import './globals.css'

const geist = Geist({
  subsets: ['latin'],
  variable: '--font-geist',
  display: 'swap',
})

const geistMono = Geist_Mono({
  subsets: ['latin'],
  variable: '--font-geist-mono',
  display: 'swap',
})

const SITE_CONFIG = {
  name: 'Lux TFHE',
  description: 'Pure Go implementation of Threshold Fully Homomorphic Encryption for the Lux Network. Compute on encrypted data without decryption.',
  url: 'https://tfhe.lux.network',
  keywords: ['TFHE', 'FHE', 'homomorphic encryption', 'privacy', 'cryptography', 'Go', 'blockchain', 'Lux Network'],
}

export const metadata = {
  title: {
    default: SITE_CONFIG.name,
    template: `%s | ${SITE_CONFIG.name}`,
  },
  description: SITE_CONFIG.description,
  keywords: SITE_CONFIG.keywords,
  authors: [{ name: 'Lux Network' }],
  metadataBase: new URL(SITE_CONFIG.url),
  icons: {
    icon: '/favicon.svg',
    apple: '/favicon.svg',
  },
  openGraph: {
    title: SITE_CONFIG.name,
    description: SITE_CONFIG.description,
    type: 'website',
    siteName: SITE_CONFIG.name,
    images: [
      {
        url: '/og.png',
        width: 1200,
        height: 630,
        alt: SITE_CONFIG.name,
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: SITE_CONFIG.name,
    description: SITE_CONFIG.description,
    images: ['/og.png'],
  },
}

export default function RootLayout({
  children
}: {
  children: ReactNode
}) {
  return (
    <html lang="en" className={`${geist.variable} ${geistMono.variable}`} suppressHydrationWarning>
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html: `
              (function() {
                const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
                if (prefersDark) {
                  document.documentElement.classList.add('dark');
                }
              })();
            `,
          }}
        />
      </head>
      <body className="min-h-screen bg-background font-sans antialiased">
        <RootProvider
          theme={{
            enabled: true,
            defaultTheme: 'system',
          }}
        >
          <div className="relative flex min-h-screen flex-col">
            {children}
          </div>
        </RootProvider>
      </body>
    </html>
  )
}
