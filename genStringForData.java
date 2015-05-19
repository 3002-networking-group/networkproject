private String genStringForData(int length) {

		String ALPHABET = "gdbac";

		Random r = new Random();
		String randomPattern = new String();
		String randomString = new String();
		int min = 10;
		int max = 100;

		int randomLength = 0;
		randomLength = min + rand.nextInt((max - min) +1);
		// will gen a random string using alphabet
		for(int i = 0; i < (randomLength/3); i++)
			randomPattern += Character.toString(ALPHABET.charAt(r.nextInt(ALPHABET.length())));

		for(int i = 0; i < randomLength; i++)
			randomString += Character.toString(ALPHABET.charAt(r.nextInt(ALPHABET.length())));

			// return a string in the format string-striiiing
		return randomPattern + "-" + randomString;
}
