// This program was made to parse PE file
// Author: z0rga (zorganico@gmail.com)
package main

import (
    "fmt"
    "flag"
    "os"
    "encoding/hex"
    "encoding/binary"
    "time"
    "io"
)

//From: https://stackoverflow.com/questions/23725924/can-gos-flag-package-print-usage
var myUsage = func() {
    fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
    flag.PrintDefaults()
}

func check(err error) {
    if err != nil {
        panic(err)
    }
}

func main() {
    flag.Usage = myUsage
    fPtr := flag.String("f", "", "PE file")
    boolStubPtr := flag.Bool("s", false, "Print DOS Stub [Optional]") 
    flag.Parse()
    if *fPtr == "" {
        flag.Usage()
        os.Exit(1)
    }
    f, err := os.Open(*fPtr)
    check(err)
    if !is_PE_file(f) {
        fmt.Println("This is not a PE file!!!")
        flag.Usage()
        f.Close()
        return
    }
    pe_h_offset := read_dos_stub_from_file(f, *boolStubPtr)
    opt_hdr_offset := read_pe_header_from_file(f, pe_h_offset)
    parse_optional_header(f, opt_hdr_offset)
    f.Close()
}

//Check the magic code to check if the file is a PE file
func is_PE_file (fp *os.File) bool {
    magic := read_next_2byte_field(fp)
    result := false
    if magic == 0x5A4D {
        result = true
    }
    return result
}

// Print DOS stub and returns address of PE Header (called "e_lfanew" field)
func read_dos_stub_from_file (fp *os.File, sPrint bool) int64 {
    //Get e_lfanew (this value is always located at 0x3C):
    fp.Seek(0x3C, 0)
    pe_header_addr := make([]byte, 1)
    _, err2 := fp.Read(pe_header_addr) //_ to ignore the number of bytes read
    check(err2)
    fmt.Printf("PE header starts at : 0x%X\n", pe_header_addr[0])
    var pe_h_offset int64 = int64(pe_header_addr[0]) //Convert from uint8 to int64
    fp.Seek(0, 0)
    stub := make([]byte, pe_h_offset) //Read until the PE header which is located directly after the DOS stub
    n, err := fp.Read(stub)
    check(err)
    if sPrint {
        fmt.Printf("[DOS Stub]\n")
        fmt.Printf("%s\n", hex.Dump(stub[:n])) //Print hex dump of the entire content of stub bytes array:
    }
    fp.Seek(0, 0)
    return pe_h_offset
}

// Returns the CPU type the PE file has to be ran on
// Args: code retrieved from PE header
// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types
func get_machine_type (code uint16) string {
    result := "Undefined"
    switch code {
        case 0x0:
            result = "Any"
        case 0x1D3:
            result = "Matsushita AM33"
        case 0x1C0:
            result = "ARM little endian"
        case 0xAA64:
            result = "ARM64 little endian"
        case 0x1C4:
            result = "ARM Thumb-2 little endian"
        case 0xEBC:
            result = "EFI byte code"
        case 0x14C:
            result = "Intel 386 or later processors and compatible processors"
        case 0x8664:
            result = "x64"
        case 0x200:
            result = "Intel Itanium processor family"
        case 0x9041:
            result = "Mitsubishi M32R little endian"
        case 0x266:
            result = "MIPS16"
        case 0x366:
            result = "MIPS with FPU"
        case 0x466:
            result = "MIPS16 with FPU"
        case 0x1F0:
            result = "Power PC little endian"
        case 0x1F1:
            result = "Power PC with floating point support"
        case 0x166:
            result = "MIPS little endian"
        case 0x5032:
            result = "RISC-V 32-bit address space"
        case 0x5064:
            result = "RISC-V 64-bit address space"
        case 0x5128:
            result = "RISC-V 128-bit address space"
        case 0x1A2:
            result = "Hitachi SH3"
        case 0x1A3:
            result = "Hitachi SH3 DSP"
        case 0x1A6:
            result = "Hitachi SH4"
        case 0x1A8:
            result = "Hitachi SH5"
        case 0x1C2:
            result = "Thumb"
        case 0x169:
            result = "MIPS little-endian WCE v2"
    }
    return result
}

func get_characteristics (flags uint16) string {
    // Get the binary representation of flags:
    // The bits that are set will tell us which characteristics is present.
    // Ex: 0x10E in binary is 100001110
    //     The Bits 1, 2, 3, and 8 are set 
    //     Check the table at http://www.pelib.com/resources/luevel.txt to see what characteristics is activated
    //fmt.Printf("%08b\n", flags)
    result := ""
    //flag_bin := strconv.FormatInt(int64(flags), 2)
    //fmt.Printf("Binary repr of 0x%X : %s\n", flags, flag_bin)
    //fmt.Printf("Size of flag_bin: %d\n", len(flag_bin))
    //How to retrieve the bits we want: https://stackoverflow.com/questions/30158105/split-uint16-t-in-bits-in-c
    bit0 := flags & 0x1
    bit1 := (flags & 0x2) >> 1
    bit2 := (flags & 0x4) >> 2
    bit3 := (flags & 0x8) >> 3
    bit4 := (flags & 0x10) >> 4
    bit5 := (flags & 0x20) >> 5
    bit6 := (flags & 0x40) >> 6
    bit7 := (flags & 0x80) >> 7
    bit8 := (flags & 0x100) >> 8
    bit9 := (flags & 0x200) >> 9
    bit10 := (flags & 0x400) >> 10
    bit11 := (flags & 0x800) >> 11
    bit12 := (flags & 0x1000) >> 12
    bit13 := (flags & 0x2000) >> 13
    bit14 := (flags & 0x4000) >> 14
    bit15 := (flags & 0x8000) >> 15

    if bit0 == 1 {
        result += "        0x1: No relocation information\n"
    }
    if bit1 == 1 {
        result += "        0x2: File is executable\n"
    }
    if bit2 == 1 {
        result += "        0x4: Line numbers stripped\n"
    }
    if bit3 == 1 {
        result += "        0x8: Local symbols stripped\n"
    }
    if bit4 == 1 {
        result += "        0x10: Operating system is supposed to trim the working set of the running process by paging out\n"
    }
    if bit5 == 1 {
        result += "        0x20: Application can handle > 2GB Addresses\n"
    }
    if bit6 == 1 {
        result += "        0x40\n"
    }
    if bit7 == 1 {
        result += "        0x80: Little Endian. Bytes must be swapped before reading\n"
    }
    if bit8 == 1 {
        result += "        0x100: 32-bit word machine\n"
    }
    if bit9 == 1 {
        result += "        0x200: Debugging information stripped\n"
    }
    if bit10 == 1 {
        result += "        0x400: Application may not run from a removable medium\n"
    }
    if bit11 == 1 {
        result += "        0x800: Application may not run from the network\n"
    }
    if bit12 == 1 {
        result += "        0x1000: Application is a system file (eg. driver)\n"
    }
    if bit13 == 1 {
        result += "        0x2000: The file is a DLL\n"
    }
    if bit14 == 1 {
        result += "        0x4000: File should be run only on a uniprocessor machine\n"
    }
    if bit15 == 1 {
        result += "        0x8000: Big Endiand\n"
    }
    //fmt.Printf("Value of Bit 0 : %d\n", bit0)
    //fmt.Printf("Value of Bit 1 : %d\n", bit1)
    //fmt.Printf("Value of Bit 2 : %d\n", bit2)
    //fmt.Printf("Value of Bit 3 : %d\n", bit3)
    //fmt.Printf("Value of Bit 4 : %d\n", bit4)
    //fmt.Printf("Value of Bit 5 : %d\n", bit5)
    //fmt.Printf("Value of Bit 6 : %d\n", bit6)
    //fmt.Printf("Value of Bit 7 : %d\n", bit7)
    //fmt.Printf("Value of Bit 8 : %d\n", bit8)
    return result
}

// Helper functions to parse PE files 
func read_next_4byte_field (fp *os.File) uint32 {
    field := make([]byte, 4)
    _, err := fp.Read(field)
    check(err)
    iField := binary.LittleEndian.Uint32(field)
    return iField
}

func read_next_2byte_field (fp *os.File) uint16 {
    field := make([]byte, 2)
    _, err := fp.Read(field)
    check(err)
    iField := binary.LittleEndian.Uint16(field)
    return iField
}

func read_next_byte (fp *os.File) byte {
    myByte := make([]byte, 1)
    _, err := fp.Read(myByte)
    check(err)
    return myByte[0]
}

//Parse PE header and return offset to Optional Header
func read_pe_header_from_file (fp *os.File, offset int64) int64 {
    //Signature Field:
    fp.Seek(offset, 0)
    pe_signature := make([]byte, 4) //PE signature is a 4-byte signature (0x00004550)
    _, err := fp.Read(pe_signature)
    check(err)
    fmt.Printf("[PE signature]\n")
    fmt.Printf("%s\n", hex.Dump(pe_signature))
    fmt.Printf("[PE Header Information]\n")

    code := read_next_2byte_field(fp)
    fmt.Printf("    Machine type: %s\n", get_machine_type(code))

    number := read_next_2byte_field(fp)
    fmt.Printf("    Number of sections: %d\n", number)

    bTime := read_next_4byte_field(fp)
    t := time.Unix(int64(bTime), 0).UTC()
    strDate := t.Format(time.UnixDate)
    fmt.Printf("    Time Date Stamp: %s\n", strDate)

    iPtr := read_next_4byte_field(fp)
    fmt.Printf("    Pointer To Symbol Table: %d\n", iPtr)

    iSymbs := read_next_4byte_field(fp)
    fmt.Printf("    Number Of Symbols: %d\n", iSymbs)

    iOptHeaderSize := read_next_2byte_field(fp)
    fmt.Printf("    Size Of Optional Header: %d\n", iOptHeaderSize)

    flags := read_next_2byte_field(fp)
    fmt.Printf("    Characteristics code: 0x%X\n", flags)
    fmt.Printf(get_characteristics(flags))
    fmt.Printf("\n")

    opt_hdr_offset, err := fp.Seek(0, io.SeekCurrent)
    return opt_hdr_offset
}

func get_windows_subsystem(code uint16) string {
    result := "Unknown"
    switch code {
        case 0:
            result = "Unknown"
        case 1:
            result = "Device drivers and native Windows processes"
        case 2:
            result = "The Windows graphical user interface (GUI) subsystem"
        case 3:
            result = "The Windows character subsystem"
        case 4:
            result = "Unknown"
        case 5:
            result = "The OS/2 character subsystem"
        case 6:
            result = "Unknown"
        case 7:
            result = "The Posix character subsystem"
        case 8:
            result = "Native Win9x driver"
        case 9:
            result = "Windows CE"
        case 10:
            result = "An Extensible Firmware Interface (EFI) application"
        case 11:
            result = "An EFI driver with boot services"
        case 12:
            result = "An EFI driver with run-time services"
        case 13:
            result = "An EFI ROM image"
        case 14:
            result = "XBOX"
        case 15:
            result = "Unknown"
        case 16:
            result = "Windows boot application"
    }
    return result
}

func parse_optional_header (fp *os.File, offset int64) {
    fmt.Printf("[PE OPTIONAL HEADER]\n")
    fp.Seek(offset, 0)
    iMagic := read_next_2byte_field(fp)
    arch := ""
    switch iMagic {
        case 0x10B:
            arch = "PE32 (32 bit executable)"
        case 0x20B:
            arch = "PE32+ (64 bit executable)"
    }
    fmt.Printf("    Magic: 0x%X, meaning: %s\n", iMagic, arch)
    majLinkerVer := read_next_byte(fp) // (1-byte long)
    fmt.Printf("    Major Linker Version: %d\n", majLinkerVer)
    minLinkerVer := read_next_byte(fp)
    fmt.Printf("    Minor Linker Version: %d\n", minLinkerVer)
    iSizeOfCode := read_next_4byte_field(fp)
    fmt.Printf("    Size of Code: 0x%X\n", iSizeOfCode)
    iSizeOfInitializedData := read_next_4byte_field(fp)
    fmt.Printf("    Size of Initialized Data: 0x%X\n", iSizeOfInitializedData)
    iSizeOfUninitializedData := read_next_4byte_field(fp)
    fmt.Printf("    Size of Uninitialized Data: 0x%X\n", iSizeOfUninitializedData)
    AddressOfEntryPoint := read_next_4byte_field(fp)
    fmt.Printf("    Address of Entry Point (RVA): 0x%X\n", AddressOfEntryPoint)
    BaseOfCode := read_next_4byte_field(fp)
    fmt.Printf("    Base of Code: 0x%X\n", BaseOfCode)
    BaseOfData := read_next_4byte_field(fp)
    fmt.Printf("    Base of Data: 0x%X\n", BaseOfData)
    ImageBase := read_next_4byte_field(fp)
    fmt.Printf("    Image Base: 0x%X\n", ImageBase)
    sectAlign := read_next_4byte_field(fp)
    fmt.Printf("    Section Alignment: 0x%X\n", sectAlign)
    FileAlign := read_next_4byte_field(fp)
    fmt.Printf("    File Alignment: 0x%X\n", FileAlign)
    MajOpSysVer := read_next_2byte_field(fp)
    fmt.Printf("    Major Operating System Version: 0x%X\n", MajOpSysVer)
    MinOpSysVer := read_next_2byte_field(fp)
    fmt.Printf("    Minor Operating System Version: 0x%X\n", MinOpSysVer)
    MajImgVer := read_next_2byte_field(fp)
    fmt.Printf("    Major Image Version: 0x%X\n", MajImgVer)
    MinImgVer := read_next_2byte_field(fp)
    fmt.Printf("    Minor Image Version: 0x%X\n", MinImgVer)
    MajSubSysVer := read_next_2byte_field(fp)
    fmt.Printf("    Major Subsystem Version: 0x%X\n", MajSubSysVer)
    MinSubSysVer := read_next_2byte_field(fp)
    fmt.Printf("    Minor Subsystem Version: 0x%X\n", MinSubSysVer)
    Win32VerValue := read_next_4byte_field(fp)
    fmt.Printf("    Win32 Version Value: 0x%X\n", Win32VerValue)
    SizeOfImage := read_next_4byte_field(fp)
    fmt.Printf("    Size of Image: 0x%X\n", SizeOfImage)
    SizeOfHeaders := read_next_4byte_field(fp)
    fmt.Printf("    Size of Headers: 0x%X\n", SizeOfHeaders)
    checksum := read_next_4byte_field(fp)
    fmt.Printf("    Checksum: 0x%X\n", checksum)
    subsystem := read_next_2byte_field(fp)
    fmt.Printf("    Subsystem: %s\n", get_windows_subsystem(subsystem))
    return
}
