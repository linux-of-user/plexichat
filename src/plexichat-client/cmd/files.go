package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"plexichat-client/pkg/client"
)

var filesCmd = &cobra.Command{
	Use:   "files",
	Short: "File management commands",
	Long:  "Commands for uploading, downloading, and managing files",
}

var filesUploadCmd = &cobra.Command{
	Use:   "upload",
	Short: "Upload a file",
	Long:  "Upload a file to the PlexiChat server",
	RunE:  runFilesUpload,
}

var filesDownloadCmd = &cobra.Command{
	Use:   "download",
	Short: "Download a file",
	Long:  "Download a file from the PlexiChat server",
	RunE:  runFilesDownload,
}

var filesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List files",
	Long:  "List uploaded files",
	RunE:  runFilesList,
}

var filesDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a file",
	Long:  "Delete a file from the server",
	RunE:  runFilesDelete,
}

var filesInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Get file information",
	Long:  "Get detailed information about a file",
	RunE:  runFilesInfo,
}

func init() {
	rootCmd.AddCommand(filesCmd)
	filesCmd.AddCommand(filesUploadCmd)
	filesCmd.AddCommand(filesDownloadCmd)
	filesCmd.AddCommand(filesListCmd)
	filesCmd.AddCommand(filesDeleteCmd)
	filesCmd.AddCommand(filesInfoCmd)

	// Upload flags
	filesUploadCmd.Flags().StringP("file", "f", "", "File path to upload")
	filesUploadCmd.Flags().String("description", "", "File description")
	filesUploadCmd.Flags().Bool("public", false, "Make file public")
	filesUploadCmd.MarkFlagRequired("file")

	// Download flags
	filesDownloadCmd.Flags().IntP("id", "i", 0, "File ID to download")
	filesDownloadCmd.Flags().StringP("output", "o", "", "Output file path")
	filesDownloadCmd.MarkFlagRequired("id")

	// List flags
	filesListCmd.Flags().IntP("limit", "l", 50, "Number of files to retrieve")
	filesListCmd.Flags().IntP("page", "p", 1, "Page number")
	filesListCmd.Flags().String("type", "", "Filter by file type")

	// Delete flags
	filesDeleteCmd.Flags().IntP("id", "i", 0, "File ID to delete")
	filesDeleteCmd.MarkFlagRequired("id")

	// Info flags
	filesInfoCmd.Flags().IntP("id", "i", 0, "File ID")
	filesInfoCmd.MarkFlagRequired("id")
}

func runFilesUpload(cmd *cobra.Command, args []string) error {
	token := viper.GetString("token")
	if token == "" {
		return fmt.Errorf("not logged in. Use 'plexichat-client auth login' to authenticate")
	}

	filePath, _ := cmd.Flags().GetString("file")

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("file does not exist: %s", filePath)
	}

	// Get file info
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("failed to get file info: %w", err)
	}

	c := client.NewClient(viper.GetString("url"))
	c.SetToken(token)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second) // 5 minutes for large files
	defer cancel()

	// Create progress bar
	bar := progressbar.NewOptions64(
		fileInfo.Size(),
		progressbar.OptionSetDescription("Uploading"),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionShowBytes(true),
		progressbar.OptionSetWidth(50),
		progressbar.OptionThrottle(65*time.Millisecond),
		progressbar.OptionShowCount(),
		progressbar.OptionOnCompletion(func() {
			fmt.Fprint(os.Stderr, "\n")
		}),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionFullWidth(),
	)

	fmt.Printf("Uploading file: %s (%.2f MB)\n", filepath.Base(filePath), float64(fileInfo.Size())/1024/1024)

	// Upload file
	resp, err := c.UploadFile(ctx, "/api/v1/files", filePath)
	if err != nil {
		return fmt.Errorf("failed to upload file: %w", err)
	}

	bar.Finish()

	var file client.File
	err = c.ParseResponse(resp, &file)
	if err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	color.Green("✓ File uploaded successfully!")
	fmt.Printf("File ID: %d\n", file.ID)
	fmt.Printf("Filename: %s\n", file.Filename)
	fmt.Printf("Size: %d bytes (%.2f MB)\n", file.Size, float64(file.Size)/1024/1024)
	fmt.Printf("MIME Type: %s\n", file.MimeType)
	fmt.Printf("URL: %s\n", file.URL)
	fmt.Printf("Uploaded: %s\n", file.Uploaded)

	return nil
}

func runFilesDownload(cmd *cobra.Command, args []string) error {
	token := viper.GetString("token")
	if token == "" {
		return fmt.Errorf("not logged in. Use 'plexichat-client auth login' to authenticate")
	}

	fileID, _ := cmd.Flags().GetInt("id")
	outputPath, _ := cmd.Flags().GetString("output")

	c := client.NewClient(viper.GetString("url"))
	c.SetToken(token)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	// Get file info first
	resp, err := c.Get(ctx, fmt.Sprintf("/api/v1/files/%d", fileID))
	if err != nil {
		return fmt.Errorf("failed to get file info: %w", err)
	}

	var file client.File
	err = c.ParseResponse(resp, &file)
	if err != nil {
		return fmt.Errorf("failed to parse file info: %w", err)
	}

	// Determine output path
	if outputPath == "" {
		outputPath = file.Filename
	}

	// Download file
	downloadResp, err := c.Get(ctx, fmt.Sprintf("/api/v1/files/%d/download", fileID))
	if err != nil {
		return fmt.Errorf("failed to download file: %w", err)
	}
	defer downloadResp.Body.Close()

	if downloadResp.StatusCode >= 400 {
		return fmt.Errorf("download failed with status %d", downloadResp.StatusCode)
	}

	// Create output file
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	// Create progress bar
	bar := progressbar.NewOptions64(
		file.Size,
		progressbar.OptionSetDescription("Downloading"),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionShowBytes(true),
		progressbar.OptionSetWidth(50),
		progressbar.OptionThrottle(65*time.Millisecond),
		progressbar.OptionShowCount(),
		progressbar.OptionOnCompletion(func() {
			fmt.Fprint(os.Stderr, "\n")
		}),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionFullWidth(),
	)

	fmt.Printf("Downloading file: %s (%.2f MB)\n", file.Filename, float64(file.Size)/1024/1024)

	// Copy with progress
	_, err = io.Copy(io.MultiWriter(outFile, bar), downloadResp.Body)
	if err != nil {
		return fmt.Errorf("failed to download file: %w", err)
	}

	bar.Finish()

	color.Green("✓ File downloaded successfully!")
	fmt.Printf("Saved to: %s\n", outputPath)

	return nil
}

func runFilesList(cmd *cobra.Command, args []string) error {
	token := viper.GetString("token")
	if token == "" {
		return fmt.Errorf("not logged in. Use 'plexichat-client auth login' to authenticate")
	}

	limit, _ := cmd.Flags().GetInt("limit")
	page, _ := cmd.Flags().GetInt("page")
	fileType, _ := cmd.Flags().GetString("type")

	c := client.NewClient(viper.GetString("url"))
	c.SetToken(token)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	endpoint := fmt.Sprintf("/api/v1/files?limit=%d&page=%d", limit, page)
	if fileType != "" {
		endpoint += "&type=" + fileType
	}

	resp, err := c.Get(ctx, endpoint)
	if err != nil {
		return fmt.Errorf("failed to get files: %w", err)
	}

	var listResp client.ListResponse
	err = c.ParseResponse(resp, &listResp)
	if err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Parse files
	filesData, _ := json.Marshal(listResp.Items)
	var files []client.File
	json.Unmarshal(filesData, &files)

	if len(files) == 0 {
		fmt.Println("No files found.")
		return nil
	}

	// Display files in a table
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"ID", "Filename", "Size", "Type", "Uploaded"})
	table.SetBorder(false)
	table.SetRowSeparator("-")
	table.SetColumnSeparator("|")
	table.SetCenterSeparator("+")

	for _, file := range files {
		size := fmt.Sprintf("%.2f MB", float64(file.Size)/1024/1024)
		if file.Size < 1024*1024 {
			size = fmt.Sprintf("%.2f KB", float64(file.Size)/1024)
		}

		table.Append([]string{
			strconv.Itoa(file.ID),
			file.Filename,
			size,
			file.MimeType,
			file.Uploaded,
		})
	}

	fmt.Printf("Files (Page %d of %d)\n", page, listResp.TotalPages)
	table.Render()
	fmt.Printf("Total files: %d\n", listResp.Total)

	return nil
}

func runFilesDelete(cmd *cobra.Command, args []string) error {
	token := viper.GetString("token")
	if token == "" {
		return fmt.Errorf("not logged in. Use 'plexichat-client auth login' to authenticate")
	}

	fileID, _ := cmd.Flags().GetInt("id")

	c := client.NewClient(viper.GetString("url"))
	c.SetToken(token)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.Delete(ctx, fmt.Sprintf("/api/v1/files/%d", fileID))
	if err != nil {
		return fmt.Errorf("failed to delete file: %w", err)
	}

	err = c.ParseResponse(resp, nil)
	if err != nil {
		return fmt.Errorf("failed to delete file: %w", err)
	}

	color.Green("✓ File deleted successfully!")
	fmt.Printf("File ID %d has been deleted.\n", fileID)

	return nil
}

func runFilesInfo(cmd *cobra.Command, args []string) error {
	token := viper.GetString("token")
	if token == "" {
		return fmt.Errorf("not logged in. Use 'plexichat-client auth login' to authenticate")
	}

	fileID, _ := cmd.Flags().GetInt("id")

	c := client.NewClient(viper.GetString("url"))
	c.SetToken(token)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.Get(ctx, fmt.Sprintf("/api/v1/files/%d", fileID))
	if err != nil {
		return fmt.Errorf("failed to get file info: %w", err)
	}

	var file client.File
	err = c.ParseResponse(resp, &file)
	if err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	fmt.Printf("File ID: %d\n", file.ID)
	fmt.Printf("Filename: %s\n", file.Filename)
	fmt.Printf("Size: %d bytes (%.2f MB)\n", file.Size, float64(file.Size)/1024/1024)
	fmt.Printf("MIME Type: %s\n", file.MimeType)
	fmt.Printf("User ID: %d\n", file.UserID)
	fmt.Printf("URL: %s\n", file.URL)
	fmt.Printf("Uploaded: %s\n", file.Uploaded)

	return nil
}
