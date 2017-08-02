/*
File: Vector.java
Implements a mathematical vector to support vector space model.
Part of 2017 REU in secure cloud computing at MST.
Written by Samuel Li
*/


import java.io.Serializable;

public class Vector implements Serializable{

	private int dimension; // size of vector array
	private double[] array; // array of vector values

        // Initializes a Vector of dimension dim
	public Vector(int dim) {
		if (dim < 0) throw new IllegalArgumentException("Dimension less than zero");
		this.dimension = dim;
		this.array = new double[dim];
	}

        // sets array[index] = value
	public void setValue(int index, double value) {
		if (index < 0 || index >= array.length)
			throw new IllegalArgumentException("Invalid dimension index");

		array[index] = value;
	}

        // returns vector size
	public int getDimension() {
		return this.dimension;
	}

        // returns value at array[index]
	public double getValue(int index) {
		if (index < 0 || index >= array.length)
			throw new IllegalArgumentException("Invalid dimension index");

		return array[index];
	}
        
        // prints vector, for debugging purposes
	public void print() {

		System.out.print("( ");
		for (int i = 0; i < dimension; i++) {
			if (i != dimension - 1)
				System.out.printf("%.2f, ", array[i]);
			else
				System.out.printf("%.2f )\n", array[i]);
		}
	}

        // mathematically normalizes vector
	public void normalize() {
		double vectorLengthSquared = 0.0;
		for (int i = 0; i < array.length; i++) {
			vectorLengthSquared += array[i] * array[i];
		}
		double vectorLength = Math.sqrt(vectorLengthSquared);
		for (int i = 0; i < array.length; i++) {
			array[i] = array[i] / vectorLength;
		}
	}

        // computes dot product of this vector with vector that
	public double dotProduct(Vector that) {
		if (that.dimension != this.dimension)
			throw new IllegalArgumentException("Vectors have different sizes");

		double product = 0.0;
		for (int i = 0; i < dimension; i++)
			product += (that.getValue(i) * array[i]);

		return product;
	}
}