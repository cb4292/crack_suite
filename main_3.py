#!/user/bin/python3
# main module
import sys
import hashlib
import itertools
# Hashing helper Function


def brute_force(target_file):

    # random strings length 4 - 6
    stringlength = 6
    while stringlength < 7:
        # Generate number strings
        number_hash_dict = {}
        numlist = iter(['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'])
        combos = itertools.chain(itertools.combinations_with_replacement(
                                 numlist, stringlength))
        for number_string in combos:

            hashed_number = hash(b, hash_type)
            number_hash_dict.update({hashed_number: number_string})
            
        stringlength + 1
    print("All numbers tested\n")
#  Generate alphabet strings, lower case
    stringlength = 6
    while stringlength < 7:
        alphalist = iter(['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
                         'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
                          'u', 'v', 'w', 'x',
                          'y', 'z'])
        alphacombos = itertools.chain(itertools.combinations_with_replacement(
                                      alphalist, stringlength))
        for x in alphacombos:
            b = ''.join(x)
            a = hash(b, hash_type)
            crack(password_hashes, a, b)
        stringlength + 1
    print("All lower-case alphabet tested\n")
# Generate alphabet strings, upper case
    stringlength = 6
    while stringlength < 7:
        Alphalist = iter(['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
                         'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
                          'U', 'V', 'W', 'X', 'Y', 'Z'])
        Alphacombos = itertools.chain(itertools.combinations_with_replacement(
                                      Alphalist, stringlength))
        for x in Alphacombos:
            b = ''.join(x)
            a = hash(b, hash_type)
            crack(password_hashes, a, b)
        stringlength + 1
    print("All Upper-case alphabet tested\n")
# Generate alphabet strings, upper and lower case
    stringlength = 6
    while stringlength < 7:
        aLphalist = iter(['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
                         'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
                          'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D',
                          'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
                          'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
                          'X', 'Y', 'Z'])
        aLphacombos = itertools.chain(itertools.combinations_with_replacement(
                                      aLphalist, stringlength))
        for x in aLphacombos:
            b = ''.join(x)
            a = hash(b, hash_type)
            crack(password_hashes, a, b)
        stringlength + 1
    print("All upper and lower case alphabet tested.\n")

def hash(string, hashtype):
    string = bytes(string, encoding='utf8')
    if hashtype == "MD5":
        hashed = hashlib.md5(string).hexdigest()
    elif hashtype == "SHA1":
        hashed = hashlib.sha1(string).hexdigest()
    elif hashtype == "SHA256":
        hashed = hashlib.sha256(string).hexdigest()
    else:
        return -1
    return hashed


def crack(hashed, unhashed):
    cracked_passwords = open("cracked_passwords.txt", "a")
    with open(sys.argv[1]) as password_file:
        passwords = password_file.readlines()
        for line in passwords:
            if hashed == line.rstrip():
                cracked_passwords.write(hashed.hexdigest())
                cracked_passwords.write('    ')
                cracked_passwords.write(unhashed)
                cracked_passwords.write('\n')
                #   Display correctly guessed hashes
                print("Password cracked")
                continue
    password_file.close()
    cracked_passwords.close()

#   Crack function for non-generated words, args: dictionary, passwords, hash


def crack2(wordlist, hash_type):
    cracked_passwords = open("cracked_passwords.txt", "a")
    number_cracked = 0
    print("Number of hashes cracked:", number_cracked)
    with open(sys.argv[1], "r") as stolen_passwords_file:
        passwords = stolen_passwords_file.readlines()
        for line in passwords:
            print("Current stolen hash to be tested: ", line.rstrip())
            with open(wordlist, encoding = "ISO-8859-1") as attempts:
                for attempt in attempts:
                    attempt_string = attempt.rstrip()
                    try:
                        hash_crack = hash(attempt_string, hash_type)
                    except(UnicodeDecodeError):
                        print("Failed to hash password {}".format(attempt_string))
                    #print("Trying attempt password {}, hashed as {}, against hash value {}.".format(attempt_string, hash_crack, line.rstrip()))
                    if hash_crack == line.rstrip():
                        print("Trying attempt password {}, hashed as {}, against hash value {}.".format(attempt_string, hash_crack, line.rstrip()))
                        cracked_passwords.write(attempt)
                        cracked_passwords.write("   ")
                        cracked_passwords.write(hash_crack)
                        cracked_passwords.write("n")
                        print("Password cracked")
                        continue
    passwords.close()
    attempts.close()
    cracked_passwords.close()
# main Function

"""
def crack2(wordlist, hash_type):
    cracked_passwords = open("cracked_passwords.txt", "a")
    number_cracked = 0
    print("Number of hashes cracked:", number_cracked)
    with open(sys.argv[1], "r") as stolen_passwords_file:
        passwords = stolen_passwords_file.readlines()
        for line in passwords:
            print("Current stolen hash to be tested: ", line.rstrip())
            with open(wordlist, encoding = "ISO-8859-1") as attempts:
                for attempt in attempts:
                    attempt_string = attempt.rstrip()
                    try:
                        hash_crack = hash(attempt_string, hash_type)
                    except(UnicodeDecodeError):
                        print("Failed to hash password {}".format(attempt_string))
                    #print("Trying attempt password {}, hashed as {}, against hash value {}.".format(attempt_string, hash_crack, line.rstrip()))
                    if hash_crack == line.rstrip():
                        print("Trying attempt password {}, hashed as {}, against hash value {}.".format(attempt_string, hash_crack, line.rstrip()))
                        cracked_passwords.write(attempt)
                        cracked_passwords.write("   ")
                        cracked_passwords.write(hash_crack)
                        cracked_passwords.write("n")
                        print("Password cracked")
                        continue
    passwords.close()
    attempts.close()
    cracked_passwords.close()
"""

def better_dictionary_crack(wordlist, hash_type):
    cracked_passwords = open("cracked_passwords.txt", "a")
    number_cracked = 0
    print("Number of hashes cracked:", number_cracked)
    dictionary_hash_dict = {}
    with open(wordlist, encoding = "ISO-8859-1") as attempts_file:
        attempts = attempts_file.readlines()
        for attempt in attempts:
            attempt_string = attempt.rstrip()
            try:
                hash_crack = hash(attempt_string, hash_type)
                dictionary_hash_dict.update({hash_crack: attempt_string})
            except(UnicodeDecodeError):
                print("Failed to hash password {}".format(attempt_string))
            #print("Trying attempt password {}, hashed as {}, against hash value {}.".format(attempt_string, hash_crack, line.rstrip()))
    with open(sys.argv[1], "r") as stolen_passwords_file:
        passwords = stolen_passwords_file.readlines()
        for line in passwords:
            line_string = line.rstrip()
            #print("Current stolen hash to be tested: ", line_string)
            #print("Trying attempt password hashed as {}, against hash value {}.".format(line_string, dictionary_hash_dict[line_string]))
            if line_string in dictionary_hash_dict:
                #print("Trying attempt password {}, hashed as {}, against hash value {}.".format(attempt_string, hash_crack, line.rstrip()))
                cracked_passwords.write(dictionary_hash_dict[line_string])
                cracked_passwords.write("\t")
                cracked_passwords.write(line.rstrip())
                cracked_passwords.write("\n")
                print("Password cracked: {} = {}".format(line_string, dictionary_hash_dict[line_string]))
                continue
    stolen_passwords_file.close()
    #attempts.close()
    cracked_passwords.close()

def main(argv):
    password_hashes = open(sys.argv[1])
    print("Running cracker on {} hash\n".format(str(sys.argv[1])))
#   Determine hash type
    hashlines = password_hashes.readlines()
    hashSize = 0
    num_hashes = 0
    hash_type = ""
    for x in hashlines:
        # count max length of hashes
        num_hashes += 1
        hashSize = len(x)
    password_hashes.close()
    print("Hash length is ", hashSize)
#   Determine hashtype
    if (hashSize > 31) & (hashSize < 39):
        hash_type = "MD5"

    elif (hashSize > 39) & (hashSize < 45):
        hash_type = "SHA1"

    elif (hashSize > 60) & (hashSize < 69):
        hash_type = "SHA256"

    else:
        print("Error, unrecognized hash.")
#   Generate brute force combinations
    print("Hashes to be cracked: ", num_hashes)
    print("Trying dictionary attack using rockyou.txt.\n")
    better_dictionary_crack("rockyou.txt", hash_type)
# Try other dictionaries

#   Try other dictionaries
    #print("Running crack on rockyou list:\n")
    #crack2("rockyou.txt", hash_type)
    print("Rockyou list test complete.\n")


if __name__ == "__main__":
    main(sys.argv)
