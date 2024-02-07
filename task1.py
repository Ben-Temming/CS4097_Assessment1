
#task 1 code
import itertools
import hashlib


def hash_tuple(password_tuple): 
    #create string from tuple
    password_str = "".join(password_tuple)

    ##hash the password string 
    #create sha512 object
    sha512 = hashlib.sha512() 
    #update object with encoded password_str
    sha512.update(password_str.encode())
    #generate and return hashed string
    return password_str, sha512.hexdigest()


def get_all_permuations(elem_list, length): 
    #we want to get all possible permuations with repetition and a set length 
    return list(itertools.product(elem_list, repeat=length))


def bruteforce_hashes(hash_list): 
    password_chars = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", 
                      "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", 
                      "1", "2", "3", "4", "5", "6", "7", "8", "9"]
    #store result in list to keep the order of the passwords
    result_list = ["Not found"]*len(hash_list)
    #create a set of the indexes of all the uncracked hashes
    uncracked_hashes_indexes = set(range(len(hash_list)))

    #set the initial passowrd length, shortest length is 1
    password_len = 1

    #while there are still uncracked passwords
    while uncracked_hashes_indexes: 
        #get all possilbe permuations for password chars with lenght password_len
        # in lexicographical order
        permutations_list = get_all_permuations(password_chars, password_len)
        
        #for every permutation 
        for perm in permutations_list: 
            #create password string and generate hash 
            perm_str, hashed_perm = hash_tuple(perm)
            #for every uncracked hash check if the there is a match 
            for index in list(uncracked_hashes_indexes): 
                #check if the hash from hash list is the same as the generated hash
                if hash_list[index] == hashed_perm: 
                    #if a matching hash is found, update the result list with the password
                    result_list[index] = perm_str 
                    #remove the hash index from the set of uncracked hashes
                    uncracked_hashes_indexes.remove(index) 

            # if there are no more uncracked hashes stop checking permuations 
            if not uncracked_hashes_indexes: 
                break
        #increment password length by 1
        password_len +=1
    #return list of password
    return result_list



if __name__ == "__main__": 
    hash_list = [
        'f14aae6a0e050b74e4b7b9a5b2ef1a60ceccbbca39b132ae3e8bf88d3a946c6d8687f3266fd2b626419d8b67dcf1d8d7c0fe72d4919d9bd05efbd37070cfb41a', 
        'e85e639da67767984cebd6347092df661ed79e1ad21e402f8e7de01fdedb5b0f165cbb30a20948f1ba3f94fe33de5d5377e7f6c7bb47d017e6dab6a217d6cc24', 
        '4e2589ee5a155a86ac912a5d34755f0e3a7d1f595914373da638c20fecd7256ea1647069a2bb48ac421111a875d7f4294c7236292590302497f84f19e7227d80', 
        'afd66cdf7114eae7bd91da3ae49b73b866299ae545a44677d72e09692cdee3b79a022d8dcec99948359e5f8b01b161cd6cfc7bd966c5becf1dff6abd21634f4b'
        ]
    #get list of passwords
    password_list = bruteforce_hashes(hash_list)
    
    #print each password in the terminal
    for password in password_list: 
        print(password)