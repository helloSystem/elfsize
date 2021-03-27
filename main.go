// Print the size of an ELF file in bytes based on the information in the ELF header
// Based on https://forum.golangbridge.org/t/calculate-the-size-of-an-elf/16064/5
// Author: Holloway, Chew Kean Ho <kean.ho.chew@zoralab.com>

package main

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "USAGE: %s <path to ELF file>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "    Print the size of an ELF file in bytes\n")
		fmt.Fprintf(os.Stderr, "    based on the information in the ELF header\n")
		os.Exit(1)
	}

	if fileExists(os.Args[1]) != true {
		fmt.Fprintf(os.Stderr, "%s does not exist, exiting\n", os.Args[1])
		os.Exit(1)
	}

	fmt.Printf("%v\n", CalculateElfSize(os.Args[1]))

}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// PrintError prints error, prefixed by a string that explains the context
func PrintError(context string, e error) {
	if e != nil {
		os.Stderr.WriteString("ERROR " + context + ": " + e.Error() + "\n")
	}
}

// GetSectionData returns the contents of an ELF section and error
func GetSectionData(filepath string, name string) ([]byte, error) {
	// fmt.Println("GetSectionData for '" + name + "'")
	r, err := os.Open(filepath)
	if err == nil {
		defer r.Close()
	}
	f, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}
	section := f.Section(name)
	if section == nil {
		return nil, nil
	}
	data, err := section.Data()
	if err != nil {
		return nil, err
	}
	return data, nil
}

// GetSectionOffsetAndLength returns the Offset and Length of an ELF section and error
func GetSectionOffsetAndLength(filepath string, name string) (uint64, uint64, error) {
	r, err := os.Open(filepath)
	if err == nil {
		defer r.Close()
	}
	f, err := elf.NewFile(r)
	if err != nil {
		return 0, 0, err
	}
	section := f.Section(name)
	if section == nil {
		return 0, 0, nil
	}
	return section.Offset, section.Size, nil
}

// GetElfArchitecture returns the architecture of a file, and err
func GetElfArchitecture(filepath string) (string, error) {
	r, err := os.Open(filepath)
	if err == nil {
		defer r.Close()
	}
	f, err := elf.NewFile(r)
	if err != nil {
		return "", err
	}
	arch := f.Machine.String()
	// Why does everyone name architectures differently?
	switch arch {
	case "EM_X86_64":
		arch = "x86_64"
	case "EM_386":
		arch = "i686"
	case "EM_ARM":
		arch = "armhf"
	case "EM_AARCH64":
		arch = "aarch64"
	}
	return arch, nil
}

// CalculateElfSize returns the size of an ELF binary as an int64 based on the information in the ELF header
func CalculateElfSize(file string) int64 {

	// Open given elf file

	f, err := os.Open(file)
	PrintError("ioReader", err)
	// defer f.Close()
	if err != nil {
		return 0
	}

	_, err = f.Stat()
	PrintError("ioReader", err)
	if err != nil {
		return 0
	}

	e, err := elf.NewFile(f)
	if err != nil {
		PrintError("elfsize elf.NewFile", err)
		return 0
	}

	// Read identifier
	var ident [16]uint8
	_, err = f.ReadAt(ident[0:], 0)
	if err != nil {
		PrintError("elfsize read identifier", err)
		return 0
	}

	// Decode identifier
	if ident[0] != '\x7f' ||
		ident[1] != 'E' ||
		ident[2] != 'L' ||
		ident[3] != 'F' {
		fmt.Fprintf(os.Stderr, "Bad magic number at %d\n", ident[0:4])
		return 0
	}

	// Process by architecture
	sr := io.NewSectionReader(f, 0, 1<<63-1)
	var shoff, shentsize, shnum int64
	switch e.Class.String() {
	case "ELFCLASS64":
		hdr := new(elf.Header64)
		_, err = sr.Seek(0, 0)
		if err != nil {
			PrintError("elfsize", err)
			return 0
		}
		err = binary.Read(sr, e.ByteOrder, hdr)
		if err != nil {
			PrintError("elfsize", err)
			return 0
		}

		shoff = int64(hdr.Shoff)
		shnum = int64(hdr.Shnum)
		shentsize = int64(hdr.Shentsize)
	case "ELFCLASS32":
		hdr := new(elf.Header32)
		_, err = sr.Seek(0, 0)
		if err != nil {
			PrintError("elfsize", err)
			return 0
		}
		err = binary.Read(sr, e.ByteOrder, hdr)
		if err != nil {
			PrintError("elfsize", err)
			return 0
		}

		shoff = int64(hdr.Shoff)
		shnum = int64(hdr.Shnum)
		shentsize = int64(hdr.Shentsize)
	default:
		fmt.Fprintf(os.Stderr, "unsupported elf architecture")
		return 0
	}

	// Calculate ELF size
	elfsize := shoff + (shentsize * shnum)
	// log.Println("elfsize:", elfsize, file)
	return elfsize
}
