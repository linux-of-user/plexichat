package main

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"plexichat-client/cmd"
	"plexichat-client/pkg/client"

	// GUI imports
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// Version information (set by build flags)
var (
	Version   = "1.0.0"
	Commit    = "unknown"
	BuildTime = "unknown"
	GoVersion = runtime.Version()
)

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("\nWelcome to PlexiChat Client!")
	fmt.Println("Choose mode:")
	fmt.Println("1) Command Line (CLI)")
	fmt.Println("2) Graphical (GUI)")
	fmt.Print("Enter 1 or 2: ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	if choice == "2" {
		launchGUI()
		return
	}

	// Default to CLI
	apiClient := client.NewClient("http://localhost:8080")
	apiClient.SetTimeout(5 * time.Second)
	cmd.ConfigureCommands(apiClient)
	cmd.SetVersionInfo(Version, Commit, BuildTime, GoVersion)
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// launchGUI starts the Fyne GUI app (moved from main_gui.go)
func launchGUI() {
	myApp := app.NewWithID("plexichat-gui")
	myApp.Settings().SetTheme(&PlexiChatTheme{})
	win := myApp.NewWindow("PlexiChat")
	win.Resize(fyne.NewSize(500, 400))
	win.SetMaster()
	win.CenterOnScreen()

	logo := canvas.NewText("💬", theme.PrimaryColor())
	logo.TextSize = 64
	logo.Alignment = fyne.TextAlignCenter

	title := widget.NewLabelWithStyle("PlexiChat", fyne.TextAlignCenter, fyne.TextStyle{Bold: true, Italic: true})
	title.TextStyle.Monospace = true
	subtitle := widget.NewLabelWithStyle("Secure Messaging Platform", fyne.TextAlignCenter, fyne.TextStyle{})

	serverEntry := widget.NewEntry()
	serverEntry.SetPlaceHolder("https://plexichat.example.com")
	serverEntry.Validator = func(s string) error {
		if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
			return fmt.Errorf("Server address must start with http:// or https://")
		}
		return nil
	}
	if addr := loadLastServer(); addr != "" {
		serverEntry.SetText(addr)
	}

	connectBtn := widget.NewButtonWithIcon("Connect", theme.ConfirmIcon(), func() {
		addr := strings.TrimSpace(serverEntry.Text)
		if err := serverEntry.Validator(addr); err != nil {
			dialog := widget.NewLabel(err.Error())
			win.SetContent(container.NewVBox(dialog))
			return
		}
		saveLastServer(addr)
		loginScreen := NewLoginScreen(win, addr)
		win.SetContent(loginScreen.GetContent())
	})

	serverCard := widget.NewCard("Server Address", "Choose the PlexiChat server to connect to.", container.NewVBox(serverEntry, connectBtn))

	welcome := container.NewVBox(
		logo,
		title,
		subtitle,
		widget.NewSeparator(),
		serverCard,
	)

	centeredWelcome := container.New(layout.NewPaddedLayout(), welcome)
	win.SetContent(container.NewCenter(centeredWelcome))
	win.ShowAndRun()
}
