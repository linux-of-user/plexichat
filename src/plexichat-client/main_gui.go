package main

import (
	"context"
	"encoding/base64"
	"image"
	"os"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"plexichat-client/pkg/client"
)

// lastServerFile is a file to persist last-used server address
const lastServerFile = "last_server.txt"

func loadLastServer() string {
	b, err := os.ReadFile(lastServerFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func saveLastServer(addr string) {
	_ = os.WriteFile(lastServerFile, []byte(addr), 0600)
}

// LoginState tracks the current authentication state
type LoginState int

const (
	StateLogin LoginState = iota
	State2FA
	StateSignup
)

// LoginScreen handles the login/signup and 2FA flow
type LoginScreen struct {
	win            fyne.Window
	client         *client.Client
	currentState   LoginState
	usernameEntry  *widget.Entry
	passwordEntry  *widget.Entry
	twoFACodeEntry *widget.Entry
	signupLink     *widget.Hyperlink
	loginLink      *widget.Hyperlink
	statusLabel    *widget.Label
	content        *fyne.Container
}

// NewLoginScreen creates a new login screen instance
func NewLoginScreen(win fyne.Window, serverAddr string) *LoginScreen {
	c := client.NewClient(serverAddr)
	screen := &LoginScreen{
		win:          win,
		client:       c,
		currentState: StateLogin,
	}

	screen.createUI()
	return screen
}

func (s *LoginScreen) createUI() {
	// Create form fields
	s.usernameEntry = widget.NewEntry()
	s.usernameEntry.SetPlaceHolder("Username")

	s.passwordEntry = widget.NewPasswordEntry()
	s.passwordEntry.SetPlaceHolder("Password")

	s.twoFACodeEntry = widget.NewEntry()
	s.twoFACodeEntry.SetPlaceHolder("2FA Code")
	s.twoFACodeEntry.Hide()

	// Create links for toggling between login/signup
	s.signupLink = widget.NewHyperlink("Create an account", nil)
	s.signupLink.OnTapped = func() {
		s.currentState = StateSignup
		s.updateUI()
	}

	s.loginLink = widget.NewHyperlink("Already have an account? Login", nil)
	s.loginLink.OnTapped = func() {
		s.currentState = StateLogin
		s.updateUI()
	}

	// Status label for messages
	s.statusLabel = widget.NewLabel("")
	s.statusLabel.Wrapping = fyne.TextWrapWord

	// Create login/signup form
	form := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "Username", Widget: s.usernameEntry},
			{Text: "Password", Widget: s.passwordEntry},
		},
		OnSubmit: s.handleSubmit,
	}

	// Main content container
	s.content = container.NewVBox(
		widget.NewLabelWithStyle("PlexiChat", fyne.TextAlignCenter, fyne.TextStyle{Bold: true, Italic: true}),
		widget.NewLabel("Secure Messaging Platform"),
		form,
		s.twoFACodeEntry,
		s.statusLabel,
		s.signupLink,
	)

	s.updateUI()
}

func (s *LoginScreen) updateUI() {
	switch s.currentState {
	case StateLogin:
		s.win.SetTitle("Login - PlexiChat")
		s.signupLink.Show()
		s.loginLink.Hide()
		s.twoFACodeEntry.Hide()
		s.statusLabel.SetText("")

	case StateSignup:
		s.win.SetTitle("Create Account - PlexiChat")
		s.signupLink.Hide()
		s.loginLink.Show()
		s.twoFACodeEntry.Hide()
		s.statusLabel.SetText("")

	case State2FA:
		s.win.SetTitle("Two-Factor Authentication - PlexiChat")
		s.signupLink.Hide()
		s.loginLink.Hide()
		s.twoFACodeEntry.Show()
		s.twoFACodeEntry.Refresh()
	}

	s.content.Refresh()
}

func (s *LoginScreen) handleSubmit() {
	username := s.usernameEntry.Text
	password := s.passwordEntry.Text

	if username == "" || password == "" {
		s.statusLabel.SetText("Username and password are required")
		return
	}

	s.statusLabel.SetText("Authenticating...")

	if s.currentState == State2FA {
		s.handle2FASubmit(username, password, s.twoFACodeEntry.Text)
		return
	}

	// Handle regular login
	if s.currentState == StateLogin {
		go func() {
			resp, err := s.client.Login(context.Background(), username, password)
			if err != nil {
				s.statusLabel.SetText("Error: " + err.Error())
				return
			}

			if resp.TwoFARequired {
				s.statusLabel.SetText(resp.Message)
				s.currentState = State2FA
				s.updateUI()
			} else {
				s.showMainApplication()
			}
		}()
	} else if s.currentState == StateSignup {
		go func() {
			_, err := s.client.Register(context.Background(), username, username+"@example.com", password, "user")
			if err != nil {
				s.statusLabel.SetText("Error: " + err.Error())
				return
			}
			// After successful registration, prompt to set up 2FA
			dialog.ShowConfirm("Registration Successful", "Would you like to set up Two-Factor Authentication now for better security?",
				func(ok bool) {
					if ok {
						s.show2FASetupWizard()
					} else {
						s.showMainApplication()
					}
				}, s.win)
		}()
	}
}

func (s *LoginScreen) handle2FASubmit(username, password, code string) {
	go func() {
		resp, err := s.client.LoginWith2FA(
			context.Background(),
			username,
			password,
			"totp", // Default to TOTP, can be made configurable
			code,
			"", // Challenge response for hardware keys
		)

		if err != nil {
			fyne.CurrentApp().SendNotification(fyne.NewNotification("2FA Error", err.Error()))
			s.statusLabel.SetText("2FA Error: " + err.Error())
			return
		}

		if resp.TwoFARequired {
			s.statusLabel.SetText("2FA code is required")
			return
		}

		s.showMainApplication()
	}()
}

func (s *LoginScreen) showMainApplication() {
	mainChatUI := buildMainChatUI(s.win, s.client)
	s.win.SetContent(mainChatUI)
	s.win.Resize(fyne.NewSize(1200, 800))
	s.win.CenterOnScreen()
}

func (s *LoginScreen) show2FASetupWizard() {
	// Wizard UI
	wizardWin := fyne.CurrentApp().NewWindow("2FA Setup Wizard")
	wizardWin.Resize(fyne.NewSize(400, 500))
	wizardWin.CenterOnScreen()

	// --- Step 1: Method Selection ---
	methodLabel := widget.NewLabel("Choose a 2FA method:")
	methodSelect := widget.NewSelect([]string{"TOTP (Authenticator App)", "SMS", "Email"}, nil)

	// --- Step 2: Details & Verification ---
	qrCodeImage := canvas.NewImageFromImage(nil)
	qrCodeImage.FillMode = canvas.ImageFillContain
	qrCodeImage.SetMinSize(fyne.NewSize(256, 256))
	qrCodeImage.Hide()

	secretLabel := widget.NewLabel("")
	secretLabel.Wrapping = fyne.TextWrapWord
	secretLabel.Hide()

	verifyEntry := widget.NewEntry()
	verifyEntry.SetPlaceHolder("Enter 6-digit code")
	verifyEntry.Hide()

	// --- Step 3: Backup Codes ---
	backupCodesContainer := container.NewVBox()
	backupCodesCard := widget.NewCard("Backup Codes", "", container.NewScroll(backupCodesContainer))
	backupCodesCard.Hide()

	status := widget.NewLabel("")

	nextBtn := widget.NewButton("Next", func() {
		method := methodSelect.Selected
		if method == "" {
			status.SetText("Please select a method.")
			return
		}

		go func() {
			status.SetText("Generating setup information...")
			resp, err := s.client.Setup2FA(context.Background(), client.TwoFAMethodTOTP, "") // Default to TOTP
			if err != nil {
				status.SetText("Error: " + err.Error())
				return
			}

			// Decode QR code and display
			qrData, err := base64.StdEncoding.DecodeString(resp.QRCode)
			if err != nil {
				status.SetText("Error decoding QR code.")
				return
			}
			img, _, _ := image.Decode(strings.NewReader(string(qrData)))
			qrCodeImage.Image = img
			qrCodeImage.Show()
			qrCodeImage.Refresh()

			secretLabel.SetText("Secret: " + resp.Secret)
			secretLabel.Show()
			verifyEntry.Show()
			status.SetText("Scan the QR code with your authenticator app.")
		}()
	})

	verifyBtn := widget.NewButton("Verify & Enable", func() {
		code := verifyEntry.Text
		go func() {
			status.SetText("Verifying...")
			resp, err := s.client.Verify2FASetup(context.Background(), client.TwoFAMethodTOTP, code, "")
			if err != nil || !resp.Success {
				status.SetText("Verification failed: " + err.Error())
				return
			}

			// Show backup codes
			for _, backupCode := range resp.BackupCodes {
				backupCodesContainer.Add(widget.NewLabel(backupCode))
			}
			backupCodesCard.Show()
			status.SetText("2FA enabled successfully! Store your backup codes.")
		}()
	})

	finishBtn := widget.NewButton("Finish", func() {
		wizardWin.Close()
		s.showMainApplication()
	})

	wizardContent := container.NewVBox(
		methodLabel,
		methodSelect,
		nextBtn,
		widget.NewSeparator(),
		qrCodeImage,
		secretLabel,
		verifyEntry,
		verifyBtn,
		widget.NewSeparator(),
		backupCodesCard,
		status,
		layout.NewSpacer(),
		finishBtn,
	)

	wizardWin.SetContent(container.New(layout.NewPaddedLayout(), wizardContent))
	wizardWin.Show()
}

// buildMainChatUI creates the main chat interface.
func buildMainChatUI(win fyne.Window, c *client.Client) fyne.CanvasObject {
	// This is a placeholder for the main chat UI.
	// In a real app, this would be the full chat client interface.
	status := widget.NewLabel("Status: Connecting...")
	go func() {
		health, err := c.Health(context.Background())
		if err != nil {
			status.SetText("Status: Offline - " + err.Error())
			return
		}
		status.SetText("Status: " + health.Status)
	}()

	mainContent := container.NewCenter(
		container.NewVBox(
			widget.NewLabelWithStyle("Welcome to PlexiChat!", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
			widget.NewLabel("Chat interface will be built here."),
			status,
		),
	)

	return mainContent
}

// GetContent returns the login screen content
func (s *LoginScreen) GetContent() fyne.CanvasObject {
	return s.content
}

// buildLoginScreen creates the login/signup screen with 2FA support
func buildLoginScreen(win fyne.Window, serverAddr string) fyne.CanvasObject {
	loginScreen := NewLoginScreen(win, serverAddr)
	return loginScreen.GetContent()
}
