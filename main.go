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
	A               [3]frontend.Variable `gnark:",secret"`
	B               [2]frontend.Variable `gnark:",public"`
	AreEqual        frontend.Variable    `gnark:",public"` // AreEqual is public, 1 if any element in A is equal to B, 0 otherwise
	matchedFront    frontend.Variable    `gnark:",public"`
	numberOfMathces int
	pivotA          int
	pivotB          int
	matched         bool
}

func (circuit *charEqualityCircuit) Define(api frontend.API) error {
	circuit.matchedFront = 0
	matchedFront := frontend.Variable(1)
	result := frontend.Variable(0)
	regexSize := frontend.Variable(2)
	// Initialize a variable to store if any comparison was successful
	circuit.pivotA = 0
	circuit.pivotB = 0
	circuit.numberOfMathces = 0
	circuit.matched = false

	for i := 0; i <= len(circuit.A); i++ {
		circuit.pivotA = i
		tmp := circuit.numberOfMathces
		if circuit.pivotA == len(circuit.A) || circuit.pivotB == len(circuit.B) {
			fmt.Printf("\n Termination case for helper function")

			api.Println("Final result:", result)
			api.AssertIsEqual(result, regexSize)
			return nil
		}
		circuit.numberOfMathces = 0
		diff := api.Sub(circuit.A[circuit.pivotA], circuit.B[circuit.pivotB])
		isEqual := api.IsZero(diff)
		flag := api.IsZero(api.Sub(regexSize, result))
		matchedFront = api.Select(flag, 0, matchedFront)
		result = api.Select(api.Or(isEqual, flag), api.Add(result, matchedFront), 0)
		fmt.Printf("Main integer resultt : %d\n", circuit.numberOfMathces)

		api.Println("Frontinteger resultt:: ", result)

		circuit.pivotB = 0

		// api.AssertIsDifferent(diff, 0)
		api.Println("helllp", diff)

		circuit.pivotB++
		circuit.numberOfMathces = tmp

		circuit.numberOfMathces++
		fmt.Printf("integer resultt1 : %d", circuit.numberOfMathces)

		api.Println(isEqual)

		if circuit.pivotA == 5 {
			break
		}
	}

	api.AssertIsEqual(result, regexSize)

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
		big.NewInt(int64('A')),
		big.NewInt(int64('B')),
	}

	// Expected result: 1 (since 'A' is in the array)
	expectedResult := big.NewInt(0)

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
		A: [3]frontend.Variable{
			frontend.Variable(a[0]),
			frontend.Variable(a[1]),
			frontend.Variable(a[2]),
		},
		B: [2]frontend.Variable{
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
