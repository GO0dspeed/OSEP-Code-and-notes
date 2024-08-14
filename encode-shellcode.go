package main

import(
	"fmt"
	"flag"
	"io/ioutil"
	"path/filepath"
	"os"
	"strings"

	"github.com/fatih/color"
)

func main() {

	input := flag.String("i", "", "Input file path of shellcode file")
	output := flag.String("o", "", "Output file path")
	key := flag.String("k", "", "Encryption key")
	flag.Usage = func() {
		flag.PrintDefaults()
		os.Exit(0)
	}
	flag.Parse()

	// Check to make sure the input file exists << stolen from https://github.com/Ne0nd0g/go-shellcode/blob/master/cmd/ShellcodeUtils/main.go
	_, errInputFile := os.Stat(*input)

	if os.IsNotExist(errInputFile) {
		color.Red(fmt.Sprintf("[!]The file does not exist: %s", *input))
		flag.Usage()
		os.Exit(1)
	}

	shellcode, errShellcode := ioutil.ReadFile(*input)

	if errShellcode != nil {
		color.Red(fmt.Sprintf("[!]%s", errShellcode.Error()))
		flag.Usage()
		os.Exit(1)
	}

	// Check to make sure an output file was provided
	if *output == "" {
		color.Red("[!]The -o output argument is required")
		flag.Usage()
		os.Exit(1)
	}

	// Check to make sure the output directory exists
	dir, _ := filepath.Split(*output)

	outDir, errOutDir := os.Stat(dir)
	if errOutDir != nil {
		color.Red(fmt.Sprintf("[!]%s", errOutDir.Error()))
		os.Exit(1)
	}

	if !outDir.IsDir() {
		color.Red(fmt.Sprintf("[!]The output directory does not exist: %s", dir))
	}

	if *key == "" {
		color.Red("[!] A key must be provided with the -key parameter to encrypt the input file")
			os.Exit(1)
		}

	var outputBytes []byte

	var encryptedBytes []byte

	encryptedBytes = make([]byte, len(shellcode))
	tempKey := *key
	for k, v := range shellcode {
		encryptedBytes[k] = v ^ tempKey[k%len(tempKey)]
	}

	if len(encryptedBytes) <= 0 {
		color.Red("[!]Encrypted byte slice length is equal to or less than 0")
		os.Exit(1)
	} else {
		outputBytes = append(outputBytes, encryptedBytes...)
	}

	var buff strings.Builder
	if len(outputBytes) > 0 {
		buff.Grow(len(outputBytes)*6 - 2)
		for i, b := range outputBytes {
			if i > 0 {
				buff.WriteString(",")
			}
			fmt.Fprintf(&buff, "0x%02x", b)
		}
	}
	result := buff.String()
	f, err := os.OpenFile(*output, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		color.Red(fmt.Sprintf("[!]%s", err.Error()))
		os.Exit(1)
	}
	numBytes, writeError := f.WriteString(result)
	if writeError != nil {
		color.Red(fmt.Sprintf("[!]%s", err.Error()))
		os.Exit(1)
	}

	color.Green(fmt.Sprintf("[+]wrote %d bytes to: %s", numBytes, *output))
}
