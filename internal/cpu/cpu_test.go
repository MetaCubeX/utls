package cpu

import (
	"encoding/json"
	"fmt"
	"testing"
)

func marshal(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestCpu(t *testing.T) {
	fmt.Printf("X86: %s\n", marshal(X86))
	fmt.Printf("ARM: %s\n", marshal(ARM))
	fmt.Printf("ARM64: %s\n", marshal(ARM64))
	fmt.Printf("Loong64: %s\n", marshal(Loong64))
	fmt.Printf("MIPS64X: %s\n", marshal(MIPS64X))
	fmt.Printf("PPC64: %s\n", marshal(PPC64))
	fmt.Printf("S390X: %s\n", marshal(S390X))
	fmt.Printf("RISCV64: %s\n", marshal(RISCV64))
}
