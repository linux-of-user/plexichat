package main

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// PlexiChatTheme defines the custom theme for the application.
type PlexiChatTheme struct{}

var _ fyne.Theme = (*PlexiChatTheme)(nil)

// --- COLOR PALETTE ---
var (
	PlexiBlue      = &color.NRGBA{R: 0x1e, G: 0x90, B: 0xff, A: 0xff} // DodgerBlue
	PlexiLightGray = &color.NRGBA{R: 0x4a, G: 0x4f, B: 0x54, A: 0xff} // Slightly lighter than Fyne's dark gray
	PlexiMidGray   = &color.NRGBA{R: 0x3c, G: 0x3f, B: 0x44, A: 0xff}
	PlexiDarkGray  = &color.NRGBA{R: 0x28, G: 0x2a, B: 0x2d, A: 0xff}
	PlexiBlack     = &color.NRGBA{R: 0x1e, G: 0x1e, B: 0x1e, A: 0xff}
	PlexiWhite     = color.White
	PlexiGreen     = &color.NRGBA{R: 0x2e, G: 0xc7, B: 0x71, A: 0xff} // Success Green
	PlexiRed       = &color.NRGBA{R: 0xf0, G: 0x47, B: 0x47, A: 0xff} // Error Red
)

func (t *PlexiChatTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return PlexiDarkGray
	case theme.ColorNameButton:
		return PlexiLightGray
	case theme.ColorNameDisabledButton:
		return PlexiMidGray
	case theme.ColorNamePrimary:
		return PlexiBlue
	case theme.ColorNamePlaceHolder:
		return PlexiLightGray
	case theme.ColorNameHover:
		return PlexiMidGray
	case theme.ColorNameFocus:
		return PlexiBlue
	case theme.ColorNameInputBackground:
		return PlexiBlack
	case theme.ColorNameSeparator:
		return PlexiLightGray
	case theme.ColorNameShadow:
		return &color.NRGBA{A: 0x66}
	case theme.ColorNameSuccess:
		return PlexiGreen
	case theme.ColorNameError:
		return PlexiRed
	default:
		return theme.DefaultTheme().Color(name, variant)
	}
}

func (t *PlexiChatTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

func (t *PlexiChatTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (t *PlexiChatTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNamePadding:
		return 8
	case theme.SizeNameText:
		return 14
	case theme.SizeNameInputBorder:
		return 1
	default:
		return theme.DefaultTheme().Size(name)
	}
}
