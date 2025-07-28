package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/AppliedCrypto-ETHZ/restic-chunker"
)

const (
	N_RUNS = 10
)

func main() {
	datasetFolder := flag.String("dataset", "dataset", "Path to the dataset folder")
	flag.Parse()

	// Read all files in the dataset folder

	files, err := os.ReadDir(*datasetFolder)
	if err != nil {
		fmt.Println("Error reading dataset folder:", err)
		return
	}

	testFiles := make([]string, 0, len(files))
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".bin") {
			// Skip directories and non-binary files
			continue 
		}
		testFiles = append(testFiles, *datasetFolder + "/" + file.Name())
	}

	if len(testFiles) == 0 {
		fmt.Println("No valid files found in the dataset folder.")
		return
	}

	// Sort files by size

	slices.SortFunc(testFiles, func(a, b string) int {
		infoA, errA := os.Stat(a)
		infoB, errB := os.Stat(b)
		if errA != nil || errB != nil {
			return 0 // If there's an error, we can't compare sizes
		}
		if infoA.Size() < infoB.Size() {
			return -1
		} else if infoA.Size() > infoB.Size() {
			return 1
		}
		return 0
	})


	timings := make(map[string]time.Duration)

	fmt.Println("\n[Running Restic chunker with AES]\n")

	for _, file := range testFiles {
		filename := filepath.Base(file)
		fmt.Println("File:", filename)

		for i := 0; i < N_RUNS; i++ {
			fd, err := os.Open(file)
			if err != nil {
				fmt.Println("Error opening file")
				return
			}

			reader := bufio.NewReader(fd)
			chnkr := chunker.New(reader, chunker.Pol(0x3DA3358B4DC173))

			buf := make([]byte, 8*1024*1024)

			start := time.Now()

			for {
				_, err := chnkr.Next(buf)
				if err == io.EOF {
					break
				}

				if err != nil {
					fmt.Println("Error chunking data")
					return
				}
			}

			elapsed := time.Since(start)
			timings[file] += elapsed
			fmt.Printf("[%s] Time elapsed: %s\n", filename, elapsed)
		}

		timings[file] /= N_RUNS

		fmt.Printf("[%s] Average time elapsed: %s\n", filename, timings[file])
	}

	// Reset the timings
	timings = make(map[string]time.Duration)

	fmt.Println("\n[Running Restic chunker without AES]\n")

	for _, file := range testFiles {
		filename := filepath.Base(file)
		fmt.Println("File:", filename)

		for i := 0; i < N_RUNS; i++ {
			fd, err := os.Open(file)
			if err != nil {
				fmt.Println("Error opening file")
				return
			}

			reader := bufio.NewReader(fd)
			chnkr := chunker.NewNoAes(reader, chunker.Pol(0x3DA3358B4DC173))

			buf := make([]byte, 8*1024*1024)

			start := time.Now()

			for {
				_, err := chnkr.Next(buf)
				if err == io.EOF {
					break
				}

				if err != nil {
					fmt.Println("Error chunking data")
					return
				}
			}

			elapsed := time.Since(start)
			timings[file] += elapsed
			fmt.Printf("[%s] Time elapsed: %s\n", filename, elapsed)
		}

		timings[file] /= N_RUNS

		fmt.Printf("[%s] Average time elapsed: %s\n", filename, timings[file])
	}
}
