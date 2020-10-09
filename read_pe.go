// This program was made to parse PE file
// Author: z0rga (zorganico@gmail.com)
package main

import (
    "fmt"
    "flag"
    "os"
    "bufio"
    "encoding/hex"
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
    fptr := flag.String("fpath", "", "PE file")
    flag.Parse()
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
    fp.Seek(0, 0)
    stub := make([]byte, 128)
    //n: the number of bytes read
    n, err := fp.Read(stub)
    check(err)
    //Print the entire content of stub bytes array:
    fmt.Printf("DOS Stub:\n")
    fmt.Printf("%s", hex.Dump(stub[:n]))
    //Get the address of the PE header:
    fp.Seek(0x3C, 0)
    pe_header_addr := make([]byte, 1)
    _, err2 := fp.Read(pe_header_addr)
    check(err2)
    fmt.Printf("PE header is located at : %x", pe_header_addr)
    //Print the PE header
    //TODO
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

