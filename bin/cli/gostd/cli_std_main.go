package main

import (
	"flag"
	"fmt"
)

func main() {
	nFlag := flag.Int("n", 1234, "n is Int")
	bFlag := flag.Bool("b", false, "b is Bool")
	sFlag := flag.String("s", "abc", "s is String")
	ssFlag := flag.String("ss", "ss", "ss is String")

	fmt.Printf("nFlag: %d\n", *nFlag)
	fmt.Printf("bFlag: %t\n", *bFlag)
	fmt.Printf("sFlag: %s\n", *sFlag)
	fmt.Printf("sFlag2: %s\n", *ssFlag)

	flag.Usage()
}
