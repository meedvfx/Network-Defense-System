import React, { createContext, useContext, useState, useEffect } from 'react'

const ThemeContext = createContext(null)

const DEFAULTS = {
    theme: 'dark',
    density: 'normal',       // 'compact' | 'normal'
    detailLevel: 'full',     // 'minimal' | 'full'
    animations: true,
}

function load(key, fallback) {
    try {
        const v = localStorage.getItem(key)
        return v !== null ? JSON.parse(v) : fallback
    } catch {
        return fallback
    }
}

export function ThemeProvider({ children }) {
    const [theme, setThemeState] = useState(() => load('nds_theme', DEFAULTS.theme))
    const [density, setDensityState] = useState(() => load('nds_density', DEFAULTS.density))
    const [detailLevel, setDetailLevelState] = useState(() => load('nds_detail', DEFAULTS.detailLevel))
    const [animations, setAnimationsState] = useState(() => load('nds_anim', DEFAULTS.animations))

    // Apply data-theme attribute to <html> element
    useEffect(() => {
        document.documentElement.setAttribute('data-theme', theme)
        localStorage.setItem('nds_theme', JSON.stringify(theme))
    }, [theme])

    useEffect(() => {
        document.documentElement.setAttribute('data-density', density)
        localStorage.setItem('nds_density', JSON.stringify(density))
    }, [density])

    useEffect(() => {
        document.documentElement.setAttribute('data-detail', detailLevel)
        localStorage.setItem('nds_detail', JSON.stringify(detailLevel))
    }, [detailLevel])

    useEffect(() => {
        document.documentElement.setAttribute('data-animations', String(animations))
        localStorage.setItem('nds_anim', JSON.stringify(animations))
    }, [animations])

    // Initialise on mount
    useEffect(() => {
        document.documentElement.setAttribute('data-theme', theme)
        document.documentElement.setAttribute('data-density', density)
        document.documentElement.setAttribute('data-detail', detailLevel)
        document.documentElement.setAttribute('data-animations', String(animations))
    }, [])

    const toggleTheme = () => setThemeState(t => t === 'dark' ? 'light' : 'dark')
    const setTheme = (t) => setThemeState(t)
    const setDensity = (d) => setDensityState(d)
    const setDetailLevel = (l) => setDetailLevelState(l)
    const setAnimations = (a) => setAnimationsState(a)

    return (
        <ThemeContext.Provider value={{
            theme, toggleTheme, setTheme,
            density, setDensity,
            detailLevel, setDetailLevel,
            animations, setAnimations,
        }}>
            {children}
        </ThemeContext.Provider>
    )
}

export function useTheme() {
    const ctx = useContext(ThemeContext)
    if (!ctx) throw new Error('useTheme must be used inside ThemeProvider')
    return ctx
}
