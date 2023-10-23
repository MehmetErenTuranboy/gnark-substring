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

type charEqualityCircuit struct {
	A, B     frontend.Variable `gnark:",secret"`
	AreEqual frontend.Variable `gnark:",public"` // AreEqual is public, 1 if A and B are equal, 0 otherwise
}

func (circuit *charEqualityCircuit) Define(api frontend.API) error {
	// Calculate (A - B)
	diff := api.Sub(circuit.A, circuit.B)

	// Create a binary variable that is 1 if diff is 0, and 0 otherwise
	isEqual := api.IsZero(diff)

	// Assert that the binary variable matches the public AreEqual variable
	api.AssertIsEqual(circuit.AreEqual, isEqual)

	return nil
}

func main() {
	var circuit charEqualityCircuit

	// Secret values (characters 'A' and 'B' for example)
	a := big.NewInt(int64('A'))
	b := big.NewInt(int64('A'))

	// Expected result: 0 (since 'A' is not equal to 'B')
	expectedResult := big.NewInt(1)

	// Compile the circuit into a set of constraints
	ccs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &circuit)
	if err != nil {
		log.Fatalf("Failed to compile the circuit: %v", err)
	}

	// Setup the Proving and Verifying keys
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatalf("Failed to setup the proving and verifying keys: %v", err)
	}

	assignment := charEqualityCircuit{
		A:        *a,
		B:        *b,
		AreEqual: *expectedResult,
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
