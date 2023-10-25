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
	A        [3]frontend.Variable `gnark:",secret"`
	B        [2]frontend.Variable   `gnark:",secret"`
	AreEqual frontend.Variable   `gnark:",public"` // AreEqual is public, 1 if any element in A is equal to B, 0 otherwise
}

// ... (previous code)

func (circuit *charEqualityCircuit) Define(api frontend.API) error {
	// Initialize a variable to store if any comparison was successful
	anyEqual := frontend.Variable(0)

	for _, a := range circuit.A {
		for _, b := range circuit.B {
			// Calculate (a - B)
			diff := api.Sub(a, b)

			// Create a binary variable that is 1 if diff is 0, and 0 otherwise
			isEqual := api.IsZero(diff)

			// If any of the comparisons is true, set anyEqual to 1
			anyEqual = api.Add(anyEqual, isEqual)
		}
	}

	// Convert anyEqual to a binary variable (0 or 1)
	// Here you might need to implement the logic for IsNonZero if it's not available
	areEqual := anyEqual // Replace this with the correct logic

	// Assert that the binary variable matches the public AreEqual variable
	api.AssertIsEqual(circuit.AreEqual, areEqual)

	return nil
}

func main() {
	var circuit charEqualityCircuit

	// Secret values
	a := [3]*big.Int{
		big.NewInt(int64('A')),
		big.NewInt(int64('B')),
		big.NewInt(int64('C')),
	}
	b := [2]*big.Int{
		big.NewInt(int64('B')),
		big.NewInt(int64('D')),
	}

	// Expected result: 1 (since 'A' is in the array)
	expectedResult := big.NewInt(2)

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
		A: [3]frontend.Variable{
			frontend.Variable(a[0]),
			frontend.Variable(a[1]),
			frontend.Variable(a[2]),
		},
		B:  [2]frontend.Variable{
			frontend.Variable(b[0]),
			frontend.Variable(b[1]),
		},
		AreEqual: frontend.Variable(expectedResult),
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
