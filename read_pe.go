// This program was made to parse PE file
// Author: z0rga (zorganico@gmail.com)
package main

import (
    "fmt"
    "flag"
    "os"
    "bufio"
    "encoding/hex"
    "encoding/binary"
    "io"
    "time"
    //"reflect"
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
    fptr := flag.String("fpath", "", "PE file")
    flag.Parse()
    //Print usage if not enough arguments
    if len(os.Args) < 2 {
        flag.Usage()
        os.Exit(1)
    }

    f, err := os.Open(*fptr)
    check(err)
    //dump_file(f)
    if !is_PE_file(f) {
        fmt.Println("This is not a PE file")
        f.Close()
        return
    }
    pe_h_offset := read_dos_stub_from_file(f)
    read_pe_header_from_file(f, pe_h_offset)
    f.Close()
}

//Check the magic code to check if the file is a PE file
//MS-DOS header begins with the magic code 0x5A4D
func is_PE_file (fp *os.File) bool {
    magic := make([]byte, 2)
    _, err := fp.Read(magic)
    check(err)
    result := false
    if magic[0] == 0x4D && magic[1] == 0x5A {
        result = true
    }
    return result
}

// Print DOS stub and returns address of PE Header (called "e_lfanew" field)
func read_dos_stub_from_file (fp *os.File) int64  {
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
    fmt.Printf("DOS Stub:\n")
    fmt.Printf("%s\n", hex.Dump(stub[:n])) //Print hex dump of the entire content of stub bytes array:
    //read_pe_header_from_file(fp, pe_h_offset)
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

func read_pe_header_from_file (fp *os.File, offset int64) {
    //Signature Field:
    fp.Seek(offset, 0)
    pe_signature := make([]byte, 4) //PE signature is a 4-byte signature (0x00004550)
    _, err := fp.Read(pe_signature)
    check(err)
    fmt.Printf("PE signature: \n")
    fmt.Printf("%s\n", hex.Dump(pe_signature))

    //Machine Field:
    machine_field := make([]byte, 2) //Machine field is 2-byte long
    _, err2 := fp.Read(machine_field)
    check(err2)
    //fmt.Printf("Machine type: %X\n", machine_field)
    //fmt.Printf("Type: %s\n", reflect.TypeOf(machine_field))
    code := binary.LittleEndian.Uint16(machine_field)
    //fmt.Println(code)
    //fmt.Printf("%X\n", code)
    fmt.Printf("Machine type: %s\n", get_machine_type(code))

    //Number of Sections:
    nSections := make([]byte, 2) // This field is 2-byte long
    _, err3 := fp.Read(nSections)
    check(err3)
    number := binary.LittleEndian.Uint16(nSections)
    fmt.Printf("Number of sections: %d\n", number)

    //TimeDateStamp:
    timestamp := make([]byte, 4) // This field is 4-byte long
    _, err4 := fp.Read(timestamp)
    bTime := binary.LittleEndian.Uint32(timestamp)
    t := time.Unix(int64(bTime), 0).UTC()
    strDate := t.Format(time.UnixDate)
    fmt.Printf("Time Date Stamp: %s\n", strDate)
    check(err4)
    return
}

//From: http://zetcode.com/golang/readfile/
func dump_file(fp *os.File) {
    reader := bufio.NewReader(fp)
    buf := make([]byte, 256)

    for {
        _, err := reader.Read(buf)
        if err != nil {
            if err != io.EOF {
                fmt.Println(err)
            }
            break
        }
        fmt.Printf("%s", hex.Dump(buf))
    }
}

