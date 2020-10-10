// This program was made to parse PE file
// Author: z0rga (zorganico@gmail.com)
package main

import (
    "fmt"
    "flag"
    "os"
    "bufio"
    "encoding/hex"
    //"encoding/binary"
    "io"
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
    read_dos_stub_from_file(f)
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

func read_dos_stub_from_file (fp *os.File) {
    //Get the address of the PE header (this value is always located at 0x3C):
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
    fmt.Printf("%s", hex.Dump(stub[:n])) //Print hex dump of the entire content of stub bytes array:
    read_pe_header_from_file(fp, pe_h_offset)
    return
}

func read_pe_header_from_file (fp *os.File, offset int64) {
    fp.Seek(offset, 0)
    pe_signature := make([]byte, 4) //PE signature is a 4-byte signature (0x00004550)
    _, err := fp.Read(pe_signature)
    check(err)
    fmt.Printf("PE signature: \n")
    fmt.Printf("%s\n", hex.Dump(pe_signature))
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

