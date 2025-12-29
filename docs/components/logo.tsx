'use client'

import { getMenuBarSVG } from '@luxfi/logo'

interface LogoProps {
  size?: number
  className?: string
}

export function Logo({ size = 24, className = '' }: LogoProps) {
  const svg = getMenuBarSVG()

  return (
    <div
      className={`logo-container inline-block ${className}`}
      style={{ width: size, height: size }}
      dangerouslySetInnerHTML={{ __html: svg }}
    />
  )
}

interface LogoWithTextProps {
  size?: number
  name?: string
}

export function LogoWithText({ size = 24, name = 'Docs' }: LogoWithTextProps) {
  return (
    <div className="flex items-center gap-2 group">
      <Logo
        size={size}
        className="transition-transform duration-200 group-hover:scale-110"
      />
      <span className="font-bold text-lg">{name}</span>
    </div>
  )
}
