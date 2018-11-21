package random;

import java.security.SecureRandom;
import java.util.Random;

public class Random1 {

	/**
	 * @param args
	 */
	public static void main(String[] args) {

		// teste1();
		teste2();
		

	}

	public static void teste1() {
		SecureRandom secureRandom;

		byte[] seed = { 0, 0 };

		for (int j = 0; j < 5; j++) {
			secureRandom = new SecureRandom(seed);
			for (int i = 0; i < 10; i++) {
				System.out.print(secureRandom.nextInt() + " ");
			}
			System.out.println("");
		}
	}

	public static void teste2() {

		SecureRandom secureRandom;
		secureRandom = new SecureRandom();
		int range = 100;
		int numTest = 500;
		int[] distribuicao = new int[range + 1];
		long acc = 0;
		for (int i = 0; i < numTest; i++) {
			int rand = secureRandom.nextInt(range + 1);
			acc = acc + rand;
			distribuicao[rand]++;
		}

		System.out.println("acc: " + acc / numTest);
		printDistribuicao(distribuicao);
	}
	

	public static void printDistribuicao(int[] dis) {
		for(int i=0; i<dis.length;i++){
			 System.out.print(String.format("%03d", dis[i] ) + " ");
		}
		System.out.println();
		for(int i=0; i<dis.length;i++){
			 System.out.print(String.format("%03d", i) + " ");
		}
		System.out.println();
		
	}

}
