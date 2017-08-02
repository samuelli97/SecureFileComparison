/*
 * File: Conversions.java
 * Converts integer form of dot product to decimal in [0,1]. Also parses
 * normalized vectors and converts values to integers, because the GMP functions
 * only work for integers.
 * Part of 2017 REU in secure cloud computing at MST.
 * Written by Samuel Li
 */

public class Conversions {

	private int significantDigits; // significant digits we desire

        // initializes Conversions object for sigDigits significant digits
	public Conversions(int sigDigits) {
		if (sigDigits < 1) 
			throw new IllegalArgumentException("Must have > 0 significant digits");
		this.significantDigits = sigDigits;
	}

        // returns number of significant digits
	public int getSigDigits() {
		return this.significantDigits;
	}

        // gets a whole nubmer vector as integer array for Vector myVector,
        // where each entry is multiplied by 10^sigDigits
	public int[] wholeNumberVector(Vector myVector) {

		int[] iVectorArray = new int[myVector.getDimension()];

		for (int index = 0; index < myVector.getDimension(); index++) {

			double currentValue = myVector.getValue(index);
			currentValue *= Math.pow(10, significantDigits);

			double dFloor = Math.floor(currentValue);
			int iFloor = (int) dFloor;

			iVectorArray[index] = iFloor;		
		}

		return iVectorArray;
	}

        // converts dot product on two "whole nubmer vectors" back to [0,1]
        // each entry is multiplied by 10^(2*sigDigits)
	public double scaledDotProduct(long dotProduct) {

		int shiftPoint = 2 * significantDigits;

		double scaled = dotProduct / Math.pow(10, shiftPoint);

		return scaled;
	}
}