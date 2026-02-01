import React from "react"
import type { Metadata } from 'next'
import { Geist, Geist_Mono } from 'next/font/google'
import './globals.css'

const _geist = Geist({ subsets: ["latin"] });
const _geistMono = Geist_Mono({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: {
    default: 'ScamShield AI - Scam & Phishing Detection',
    template: '%s • ScamShield AI'
  },
  description: 'AI-Assisted Scam & Phishing Detection System. Not just detecting scams — explaining them.',
  // generator metadata removed to avoid v0 branding
  icons: {
    icon: [
      {
        url: '/icon.svg',
        type: 'image/svg+xml',
        media: '(prefers-color-scheme: light)'
      },
      {
        url: '/icon-dark-32x32.png',
        media: '(prefers-color-scheme: dark)'
      }
    ],
    apple: '/icon.svg'
  },
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en">
      <body className={`font-sans antialiased`}>
        {children}
      </body>
    </html>
  )
}
