package main

import (
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed embedded/*
var toolbox embed.FS

const banner = `
   ╔══════════════════════════════════════════════════════╗
   ║                                                    ║
   ║   ██╗  ██╗███████╗███████╗                        ║
   ║   ╚██╗██╔╝██╔════╝██╔════╝                        ║
   ║    ╚███╔╝ ███████╗███████╗                        ║
   ║    ██╔██╗ ╚════██║╚════██║                        ║
   ║   ██╔╝ ██╗███████║███████║                        ║
   ║   ╚═╝  ╚═╝╚══════╝╚══════╝                        ║
   ║                                                    ║
   ║       XSS-Tesseract — The 4‑Dimensional XSS Engine ║
   ║                                                    ║
   ║   by Archsec-Emman (@Archsec-Emman)                ║
   ║   Arc‑Cyber‑Arsenal Edition                        ║
   ║   https://github.com/Arc-Cyber-Arsenal/XSS-Tesseract ║
   ║                                                    ║
   ╚══════════════════════════════════════════════════════╝
`

type PayloadDB struct {
	Name      string   `yaml:"name"`
	Context   string   `yaml:"context"`
	Payloads  []string `yaml:"payloads"`
	WAFBypass bool     `yaml:"waf_bypass"`
	CSPBypass bool     `yaml:"csp_bypass"`
}

var (
	targetURL   string
	payloadFile string
	onlyEngine  string
	skipEngine  string
)

func init() {
	flag.StringVar(&targetURL, "u", "", "Target URL (e.g., https://example.com?q=)")
	flag.StringVar(&payloadFile, "p", "", "Custom payload file (one per line)")
	flag.StringVar(&onlyEngine, "only", "", "Run only specified engines (xsstrike,dalfox,payloaddb)")
	flag.StringVar(&skipEngine, "skip", "", "Skip engines (comma‑separated)")
}

func main() {
	flag.Usage = func() {
		fmt.Print(banner)
		fmt.Println("\nUsage:  xss-tesseract -u <URL>  [-p <payloads.txt>]  [--only <engine>]  [--skip <engine>]")
		fmt.Println("Example: xss-tesseract -u https://example.com?q=test")
		fmt.Println("         xss-tesseract -u https://example.com?q=test -p my_payloads.txt --skip payloaddb")
		fmt.Println("\nFlags:")
		flag.PrintDefaults()
	}
	flag.Parse()

	if targetURL == "" {
		flag.Usage()
		os.Exit(1)
	}

	fmt.Println(banner)

	tmpDir, err := ioutil.TempDir("", "xss-tesseract")
	if err != nil {
		log.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Extract XSStrike
	xsstrikeDir := filepath.Join(tmpDir, "xsstrike")
	if err := extractDir("embedded/xsstrike", xsstrikeDir); err != nil {
		log.Printf("[!] Failed to extract XSStrike: %v", err)
	}

	// Extract dalfox binary
	dalfoxPath := filepath.Join(tmpDir, "dalfox")
	if data, err := toolbox.ReadFile("embedded/dalfox"); err == nil {
		ioutil.WriteFile(dalfoxPath, data, 0755)
	}

	// Extract payload database files
	payloadFiles := []string{}
	fs.WalkDir(toolbox, "embedded/payloads", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		dest := filepath.Join(tmpDir, filepath.Base(path))
		if data, err := toolbox.ReadFile(path); err == nil {
			ioutil.WriteFile(dest, data, 0644)
			payloadFiles = append(payloadFiles, dest)
		}
		return nil
	})

	// Merge payloads (now supports YAML)
	allPayloads := []string{}
	for _, pf := range payloadFiles {
		data, err := ioutil.ReadFile(pf)
		if err != nil {
			continue
		}
		var db []PayloadDB
		if err := yaml.Unmarshal(data, &db); err != nil {
			continue
		}
		for _, cat := range db {
			allPayloads = append(allPayloads, cat.Payloads...)
		}
	}
	if payloadFile != "" {
		if data, err := ioutil.ReadFile(payloadFile); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					allPayloads = append(allPayloads, line)
				}
			}
		}
	}
	mergedPayloadsPath := filepath.Join(tmpDir, "tesseract_payloads.txt")
	ioutil.WriteFile(mergedPayloadsPath, []byte(strings.Join(allPayloads, "\n")), 0644)

	// Engine selection
	runSet := map[string]bool{
		"xsstrike":  true,
		"dalfox":    true,
		"payloaddb": true,
	}
	if onlyEngine != "" {
		runSet = make(map[string]bool)
		for _, e := range strings.Split(onlyEngine, ",") {
			runSet[strings.TrimSpace(e)] = true
		}
	}
	if skipEngine != "" {
		for _, e := range strings.Split(skipEngine, ",") {
			runSet[strings.TrimSpace(e)] = false
		}
	}

	var wg sync.WaitGroup
	outputs := make(map[string]string)
	var mu sync.Mutex

	// Engine 1: XSStrike
	if runSet["xsstrike"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cmd := exec.Command("python3", filepath.Join(xsstrikeDir, "xsstrike.py"),
				"-u", targetURL, "--crawl", "--blind")
			cmd.Dir = tmpDir
			out, err := cmd.Output()
			mu.Lock()
			if err != nil {
				outputs["XSStrike"] = fmt.Sprintf("Error: %v", err)
			} else {
				outputs["XSStrike"] = string(out)
			}
			mu.Unlock()
		}()
	}

	// Engine 2: dalfox
	if runSet["dalfox"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := os.Stat(dalfoxPath); os.IsNotExist(err) {
				mu.Lock()
				outputs["dalfox"] = "dalfox binary not available (Rust build required)"
				mu.Unlock()
				return
			}
			cmd := exec.Command(dalfoxPath, "scan", targetURL,
				"--custom-payload", mergedPayloadsPath)
			cmd.Dir = tmpDir
			out, err := cmd.Output()
			mu.Lock()
			if err != nil {
				outputs["dalfox"] = fmt.Sprintf("Error: %v", err)
			} else {
				outputs["dalfox"] = string(out)
			}
			mu.Unlock()
		}()
	}

	// Engine 3: PayloadDB
	if runSet["payloaddb"] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			output := "Payload Database Summary:\n"
			output += "========================\n"
			output += fmt.Sprintf("Total payloads loaded: %d\n\n", len(allPayloads))
			output += "Context Distribution:\n"
			categories := map[string]int{}
			for _, pf := range payloadFiles {
				var db []PayloadDB
				data, _ := ioutil.ReadFile(pf)
				if yaml.Unmarshal(data, &db) == nil {
					for _, cat := range db {
						categories[cat.Context] += len(cat.Payloads)
					}
				}
			}
			for ctx, count := range categories {
				output += fmt.Sprintf("  - %s: %d payloads\n", ctx, count)
			}
			output += fmt.Sprintf("\nMerged payload file saved to: %s\n", mergedPayloadsPath)
			mu.Lock()
			outputs["PayloadDB"] = output
			mu.Unlock()
		}()
	}

	wg.Wait()

	fmt.Println("======================================")
	fmt.Println("   XSS-Tesseract Combined Report")
	fmt.Println("======================================")
	fmt.Println()

	engineOrder := []string{"XSStrike", "dalfox", "PayloadDB"}
	for _, name := range engineOrder {
		out, ok := outputs[name]
		if !ok {
			continue
		}
		fmt.Printf("--- %s ---\n", name)
		fmt.Println(out)
		fmt.Println()
	}

	fmt.Println("=== DONE ===")
	fmt.Printf("\n⚡ XSS-Tesseract completed multi‑engine scan.\n")
	fmt.Printf("   Report saved to: %s\n", tmpDir)
}

func extractDir(embedPath, destDir string) error {
	return fs.WalkDir(toolbox, embedPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relPath, err := filepath.Rel(embedPath, path)
		if err != nil {
			return err
		}
		destPath := filepath.Join(destDir, relPath)
		if d.IsDir() {
			return os.MkdirAll(destPath, 0755)
		}
		data, err := toolbox.ReadFile(path)
		if err != nil {
			return err
		}
		return ioutil.WriteFile(destPath, data, 0755)
	})
}
