package main

import (
	"fmt"
	"log"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

const (
	stringLength = 10
	regexLength  = 5
)

type charEqualityCircuit struct {
	A [stringLength]frontend.Variable `gnark:",secret"`
	B [regexLength]frontend.Variable  `gnark:",public"`
}

func (circuit *charEqualityCircuit) Define(api frontend.API) error {
	matchedFront := frontend.Variable(1)
	result := frontend.Variable(0)
	regexSize := frontend.Variable(regexLength)
	pivotA := 0
	// Initialize a variable to store if any comparison was successful
	for i := 0; i < len(circuit.A); i++ {
		pivotA = i
		for j := 0; j < len(circuit.B); j++ {
			diff := api.Sub(circuit.A[pivotA], circuit.B[j])
			isEqual := api.IsZero(diff)
			flag := api.IsZero(api.Sub(regexSize, result))
			matchedFront = api.Select(flag, 0, matchedFront)
			result = api.Select(api.Or(isEqual, flag), api.Add(result, matchedFront), 0)
			api.Println("Frontinteger resultt:: ", result)
			if pivotA < len(circuit.A)-1 {
				pivotA++
			} else {
				break
			}
		}

		api.Println("reultequal", result)
	}

	api.AssertIsEqual(result, regexSize)

	return nil
}

func main() {
	var circuit charEqualityCircuit

	// Secret values
	a := make([]*big.Int, stringLength)
	inputString := "HELLOWORLD"
	for i, char := range inputString {
		if i < stringLength {
			a[i] = big.NewInt(int64(char))
		}
	}

	b := make([]*big.Int, regexLength)
	regexPattern := "WORLD"
	for i, char := range regexPattern {
		if i < regexLength {
			b[i] = big.NewInt(int64(char))
		}
	}

	// Compile the circuit into a set of constraints
	ccs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	if err != nil {
		log.Fatalf("Failed to compile the circuit: %v", err)
	}

	// Setup the Proving and Verifying keys
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatalf("Failed to setup the proving and verifying keys: %v", err)
	}

	assignment := charEqualityCircuit{
		A: [stringLength]frontend.Variable{},
		B: [regexLength]frontend.Variable{},
	}

	for i := 0; i < stringLength; i++ {
		assignment.A[i] = frontend.Variable(a[i])
	}

	for i := 0; i < regexLength; i++ {
		assignment.B[i] = frontend.Variable(b[i])
	}

	// Create a witness from the assignment
	witness, err := frontend.NewWitness(&assignment, ecc.BN254)
	if err != nil {
		log.Fatalf("Failed to create a witness: %v", err)
	}

	// Extract the public part of the witness
	publicWitness, err := witness.Public()
	if err != nil {
		log.Fatalf("Failed to extract the public witness: %v", err)
	}

	// Prove the witness
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		log.Fatalf("Failed to prove the witness: %v", err)
	}

	// Verify the proof
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Println("Verification Result: Failed")
		log.Fatalf("Failed to verify the proof: %v", err)
	} else {
		fmt.Println("Verification Result: Success")
	}
}
