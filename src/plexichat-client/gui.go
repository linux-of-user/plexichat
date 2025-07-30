package main

import (
	"log"
	"os"
	"context"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"fyne.io/fyne/v2/theme"
)

func main() {
	myApp := app.NewWithID("plexichat-gui")
	myApp.Settings().SetTheme(theme.DarkTheme())
	win := myApp.NewWindow("PlexiChat (Discord Style)")
	win.Resize(fyne.NewSize(1200, 800))

	// Sidebar (server/channel list placeholder)
	sidebar := widget.NewList(
		func() int { return 5 },
		func() fyne.CanvasObject { return widget.NewLabel("#channel") },
		func(i widget.ListItemID, o fyne.CanvasObject) { o.(*widget.Label).SetText("#channel" + string('A'+i)) },
	)
	sidebarBox := container.NewVBox(widget.NewLabel("Servers/Channels"), sidebar)

	// Chat area (placeholder)
	chat := widget.NewMultiLineEntry()
	chat.SetText("Welcome to PlexiChat!\n[Chat will appear here]")
	chat.SetReadOnly(true)
	chatBox := container.NewVBox(widget.NewLabel("Chat"), chat)

	// User list (placeholder)
	userList := widget.NewList(
		func() int { return 3 },
		func() fyne.CanvasObject { return widget.NewLabel("User") },
		func(i widget.ListItemID, o fyne.CanvasObject) { o.(*widget.Label).SetText("User" + string('1'+i)) },
	)
	userBox := container.NewVBox(widget.NewLabel("Online Users"), userList)

	// Status bar (health check placeholder)
	status := widget.NewLabel("Status: Connecting...")
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		// TODO: Integrate with Go client Health() method and update status
		status.SetText("Status: Online (placeholder)")
	}()
	statusBar := container.NewHBox(status)

	// Layout: sidebar | chat | user list
	mainContent := container.NewHSplit(
		container.NewVSplit(sidebarBox, widget.NewLabel("[Add server/channel controls here]")),
		container.NewVSplit(chatBox, userBox),
	)
	mainContent.Offset = 0.2

	// Top-level layout
	content := container.NewBorder(nil, statusBar, nil, nil, mainContent)
	win.SetContent(content)

	win.ShowAndRun()
}
